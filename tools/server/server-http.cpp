#include "common.h"
#include "http.h"
#include "server-http.h"
#include "server-common.h"
#include "server-auth.h"
#include "server-mtls.h"
#include "ui.h"

#include <cpp-httplib/httplib.h>

#include <algorithm>
#include <functional>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <unordered_set>

//
// HTTP implementation using cpp-httplib
//

class server_http_context::Impl {
public:
    std::unique_ptr<httplib::Server> srv;
};

server_http_context::server_http_context()
    : pimpl(std::make_unique<Impl>())
{}

server_http_context::~server_http_context() = default;

static void log_server_request(const httplib::Request & req, const httplib::Response & res) {
    // skip logging requests that are regularly sent, to avoid log spam
    if (req.path == "/health"
        || req.path == "/v1/health"
        || req.path == "/models"
        || req.path == "/v1/models"
        || req.path == "/props"
        || req.path == "/metrics"
    ) {
        return;
    }

    // reminder: this function is not covered by httplib's exception handler; if someone does more complicated stuff, think about wrapping it in try-catch

    SRV_TRC("done request: %s %s %s %d\n", req.method.c_str(), req.path.c_str(), req.remote_addr.c_str(), res.status);

    SRV_DBG("request:  %s\n", req.body.c_str());
    SRV_DBG("response: %s\n", res.body.c_str());
}

// returns true if the Origin header value's host is localhost / 127.0.0.1 / ::1 (any port)
static bool origin_is_localhost(const std::string & origin) {
    try {
        const std::string host = common_http_parse_url(origin).host;
        return host == "localhost" || host == "127.0.0.1" || host == "::1";
    } catch (const std::exception &) {
        return false;
    }
}

// For Google Cloud Platform deployment compatibility
struct gcp_params {
    bool enabled;
    std::string path_health;
    std::string path_predict;
    int port;

    // Ref: https://docs.cloud.google.com/vertex-ai/docs/predictions/custom-container-requirements#aip-variables
    gcp_params() {
        enabled = getenv("AIP_MODE", "") == "PREDICTION";
        path_health = getenv("AIP_HEALTH_ROUTE", "", true); // default: using the route defined in server.cpp
        path_predict = getenv("AIP_PREDICT_ROUTE", "/predict", true);
        port = std::stoi(getenv("AIP_HTTP_PORT", "8080"));
    }

    static std::string getenv(const char * name, const std::string & default_value, bool ensure_leading_slash = false) {
        const auto * value = std::getenv(name);
        if (value == nullptr || value[0] == '\0') {
            return default_value;
        }
        std::string val = value;
        if (ensure_leading_slash && !val.empty() && val[0] != '/') {
            val.insert(val.begin(), '/');
        }
        return val;
    }
};

bool server_http_context::init(const common_params & params) {
    const gcp_params gcp;

    path_prefix = params.api_prefix;
    port = params.port;
    hostname = params.hostname;

    if (gcp.enabled) {
        SRV_TRC("Google Cloud Platform compat: health route = %s, predict route = %s, port = %d\n", gcp.path_health.c_str(), gcp.path_predict.c_str(), gcp.port);

        if (port != gcp.port) {
            SRV_WRN("Google Cloud Platform compat: overriding server port %d with AIP_HTTP_PORT %d\n", port, gcp.port);
        }

        port = gcp.port;
    }

    auto & srv = pimpl->srv;

    // F008b: Build and validate mTLS configuration.
    server_mtls_config mtls_cfg;
    if (!server_mtls::configure(params, mtls_cfg)) {
        return false;
    }

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    bool has_server_tls = !params.ssl_file_key.empty() && !params.ssl_file_cert.empty();

    // F008b: mTLS requires server cert/key for the TLS listener.
    if (mtls_cfg.enabled && !has_server_tls) {
        SRV_ERR("%s", "mTLS requires --ssl-cert-file and --ssl-key-file\n");
        return false;
    }

    if (has_server_tls) {
        SRV_TRC("running with SSL: key = %s, cert = %s\n",
                params.ssl_file_key.c_str(), params.ssl_file_cert.c_str());

        // F008b: Use 4-arg SSLServer ctor if mTLS is enabled, else plain 2-arg.
        if (mtls_cfg.enabled) {
            srv = std::make_unique<httplib::SSLServer>(
                params.ssl_file_cert.c_str(),
                params.ssl_file_key.c_str(),
                mtls_cfg.client_ca_file.empty() ? nullptr : mtls_cfg.client_ca_file.c_str(),
                mtls_cfg.client_ca_dir.empty() ? nullptr : mtls_cfg.client_ca_dir.c_str()
            );
        } else {
            srv = std::make_unique<httplib::SSLServer>(
                params.ssl_file_cert.c_str(),
                params.ssl_file_key.c_str()
            );
        }

        // F008b: Check SSLServer construction (fail-closed on bad cert/key/CA).
        if (!srv->is_valid()) {
            SRV_ERR("%s", "failed to init SSL server (cert/key/CA)\n");
            return false;
        }

        // F008b: Harden TLS context on any SSL server (mTLS or plain HTTPS).
        // This applies min-version to both paths (S2) and verify-depth/optional-mode only when mTLS is enabled.
        auto ssl_srv = static_cast<httplib::SSLServer *>(srv.get());
        if (!server_mtls::harden_context(ssl_srv->tls_context(), mtls_cfg)) {
            SRV_ERR("%s", "failed to harden TLS context\n");
            return false;
        }

        is_ssl = true;
    } else {
        SRV_TRC("%s", "running without SSL\n");
        srv = std::make_unique<httplib::Server>();
    }
#else
    // F008b: Fail-closed if SSL is required but not built.
    if (mtls_cfg.enabled || !params.ssl_file_key.empty() || !params.ssl_file_cert.empty()) {
        SRV_ERR("%s", "the server is built without SSL support\n");
        return false;
    }
    srv.reset(new httplib::Server());
#endif

    srv->set_default_headers({{"Server", "llama.cpp"}});
    // srv->set_logger(log_server_request); // TODO @ngxson : this is too spamy, no very useful; improve it in the future
    srv->set_exception_handler([](const httplib::Request &, httplib::Response & res, const std::exception_ptr & ep) {
        // this is fail-safe; exceptions should already handled by `ex_wrapper`

        std::string message;
        try {
            std::rethrow_exception(ep);
        } catch (const std::exception & e) {
            message = e.what();
        } catch (...) {
            message = "Unknown Exception";
        }

        res.status = 500;
        res.set_content(message, "text/plain");
        SRV_ERR("got exception: %s\n", message.c_str());
    });

    srv->set_error_handler([](const httplib::Request &, httplib::Response & res) {
        if (res.status == 404) {
            res.set_content(
                safe_json_to_str(json {
                    {"error", {
                        {"message", "File Not Found"},
                        {"type", "not_found_error"},
                        {"code", 404}
                    }}
                }),
                "application/json; charset=utf-8"
            );
        }
        // for other error codes, we skip processing here because it's already done by res->error()
    });

    // set timeouts and change hostname and port
    srv->set_read_timeout (params.timeout_read);
    srv->set_write_timeout(params.timeout_write);
    srv->set_socket_options([reuse_port = params.reuse_port](const socket_t sock) {
        httplib::set_socket_opt(sock, SOL_SOCKET, SO_REUSEADDR, 1);
        if (reuse_port) {
#ifdef SO_REUSEPORT
            httplib::set_socket_opt(sock, SOL_SOCKET, SO_REUSEPORT, 1);
#else
            SRV_WRN("%s", "SO_REUSEPORT is not supported\n");
#endif
        }
    });

    if (params.api_keys.size() == 1) {
        const auto key = params.api_keys[0];
        const std::string substr = key.substr(std::max(static_cast<int>(key.length() - 4), 0));
        SRV_TRC("api_keys: ****%s\n", substr.c_str());
    } else if (params.api_keys.size() > 1) {
        SRV_TRC("api_keys: %zu keys loaded\n", params.api_keys.size());
    }

    //
    // Middlewares
    //

    // Frontend paths - all embedded UI assets
    static const std::unordered_set<std::string> frontend_paths = []() {
        std::unordered_set<std::string> paths { "/" };
        for (const llama_ui_asset & a : llama_ui_get_assets()) {
            paths.insert("/" + a.name);
        }
        return paths;
    }();

    // req.path is prefixed (params.api_prefix + asset path) while frontend_paths
    // entries are not; strip the prefix before checking membership.
    auto is_frontend_asset = [&params](const std::string & path) {
        std::string p = path;
        if (!params.api_prefix.empty()) {
            if (p.rfind(params.api_prefix, 0) != 0) {
                return false;
            }
            p = p.substr(params.api_prefix.size());
            if (p.empty()) {
                p = "/";
            }
        }
        return frontend_paths.count(p) > 0;
    };

    auto middleware_authz = [](const httplib::Request & req, httplib::Response & res) {
        // F005: build auth request DTO
        server_auth_request ar;
        ar.method = req.method;
        ar.raw_path = req.path;
        ar.authorization = req.get_header_value("Authorization");
        ar.x_api_key = req.get_header_value("X-Api-Key");
        ar.peer_addr = req.remote_addr;
        ar.x_auth_subject = req.get_header_value(server_auth_headers::X_AUTH_SUBJECT);
        ar.x_auth_roles = req.get_header_value(server_auth_headers::X_AUTH_ROLES);

        // F008c: Extract mTLS identity from the client certificate, if any. req.peer_cert()
        // is the only public accessor httplib exposes for the peer cert; all SAN parsing and
        // the C1 ambiguous-SAN handling live in server_mtls::extract_identity (server-mtls.cpp),
        // this is the single call site.
#ifdef CPPHTTPLIB_SSL_ENABLED
        mtls_identity id;
        auto peer_cert = req.peer_cert();
        if (server_mtls::extract_identity(&peer_cert, id)) {
            ar.mtls_present = id.present;
            ar.mtls_san_uri = id.san_uri;
            ar.mtls_san_dns = id.san_dns;
        }
#endif

        const server_auth_decision d = server_auth::authorize_request(ar);
        if (d.allowed) {
            return true;
        }
        res.status = d.status;
        res.set_content(
            safe_json_to_str(json {{"error", format_error_response(d.message, d.type)}}),
            "application/json; charset=utf-8");
        return false;
    };

    auto middleware_server_state = [this](const httplib::Request & req, httplib::Response & res) {
        if (!is_ready.load()) {
            if (frontend_paths.count(req.path)) {
                return true; // frontend asset, allow it to load and show "loading"
            }
            // no endpoints are allowed to be accessed when the server is not ready
            // this is to prevent any data races or inconsistent states
            res.status = 503;
            res.set_content(
                safe_json_to_str(json {
                    {"error", {
                        {"message", "Loading model"},
                        {"type", "unavailable_error"},
                        {"code", 503}
                    }}
                }),
                "application/json; charset=utf-8"
            );
            return false;
        }
        return true;
    };

    // register server middlewares
    srv->set_pre_routing_handler([&params, middleware_authz, middleware_server_state, is_frontend_asset](const httplib::Request & req, httplib::Response & res) {
        // F005: clear thread_local principal at middleware entry (reset-on-entry)
        server_auth::reset_principal();

        if (params.cors_credentials && params.cors_origins == "*") {
            // special case: echo back the Origin header to allow any origin to access the server with credentials
            res.set_header("Access-Control-Allow-Origin", req.get_header_value("Origin"));
        } else if (params.cors_origins == "localhost") {
            // special case: only reflect the Origin header if it is a localhost origin
            std::string origin = req.get_header_value("Origin");
            if (!origin.empty() && origin_is_localhost(origin)) {
                res.set_header("Access-Control-Allow-Origin", origin);
            } else if (!origin.empty()) {
                SRV_WRN("(CORS) skip non-localhost origin: %s\n", origin.c_str());
            }
        } else {
            res.set_header("Access-Control-Allow-Origin", params.cors_origins);
        }
        // If this is OPTIONS request, skip validation because browsers don't include Authorization header
        if (req.method == "OPTIONS") {
            res.set_header("Access-Control-Allow-Credentials", params.cors_credentials ? "true" : "false");
            res.set_header("Access-Control-Allow-Methods",     params.cors_methods);
            res.set_header("Access-Control-Allow-Headers",     params.cors_headers);
            res.set_content("", "text/html"); // blank response, no data
            return httplib::Server::HandlerResponse::Handled; // skip further processing
        }
        if (!middleware_server_state(req, res)) {
            return httplib::Server::HandlerResponse::Handled;
        }
        // UI-asset public carve-out: frontend assets bypass authz
        if (is_frontend_asset(req.path)) {
            return httplib::Server::HandlerResponse::Unhandled;
        }
        if (!middleware_authz(req, res)) {
            return httplib::Server::HandlerResponse::Handled;
        }
        return httplib::Server::HandlerResponse::Unhandled;
    });

    auto n_threads_http = params.n_threads_http;
    if (n_threads_http < 1) {
        // +4 threads for monitoring, health and some threads reserved for MCP and other tasks in the future
        n_threads_http = std::max(params.n_parallel + 4, static_cast<int32_t>(std::thread::hardware_concurrency() - 1));
    }
    SRV_TRC("using %d threads for HTTP server\n", n_threads_http);
    srv->new_task_queue = [n_threads_http] {
        // spawn n_threads_http fixed thread (always alive), while allow up to 1024 max possible additional threads
        // when n_threads_http is used, server will create new "dynamic" threads that will be destroyed after processing each request
        // ref: https://github.com/yhirose/cpp-httplib/pull/2368
        const auto max_threads = static_cast<size_t>(n_threads_http + 1024);
        return new httplib::ThreadPool(n_threads_http, max_threads);
    };

    //
    // Web UI setup
    //

    // Use new `params.ui` field (backed by old `params.webui` for compat)
    if (!params.ui) {
        SRV_INF("%s", "The UI is disabled\n");
        SRV_INF("%s", "Use --ui/--no-ui (or deprecated --webui/--no-webui) to enable/disable\n");
    } else {
        // register static assets routes
        if (!params.public_path.empty()) {
            // Set the base directory for serving static files
            if (const auto is_found = srv->set_mount_point(params.api_prefix + "/", params.public_path); !is_found) {
                SRV_ERR("static assets path not found: %s\n", params.public_path.c_str());
                return false;
            }
        } else {
#if defined(LLAMA_UI_HAS_ASSETS)
            static auto handle_gzip_header = [](const httplib::Request & req, httplib::Response & res) {
                if (!llama_ui_use_gzip()) {
                    // no gzip build, skip
                    return true;
                }
                if (req.get_header_value("Accept-Encoding").find("gzip") == std::string::npos) {
                    res.status = 415; // unsupported media type
                    res.set_content("Error: gzip is not supported by this browser", "text/plain");
                    return false;
                } else {
                    res.set_header("Content-Encoding", "gzip");
                }
                return true;
            };

            auto serve_asset_cached = [](const std::string & name, bool isolation) {
                return [name, isolation](const httplib::Request & req, httplib::Response & res) {
                    if (!handle_gzip_header(req, res)) {
                        return true; // returns error message
                    }
                    const llama_ui_asset * a = llama_ui_find_asset(name);
                    if (!a) { res.status = 404; return false; }
                    res.set_header("ETag", a->etag);
                    if (const std::string & inm = req.get_header_value("If-None-Match");
                        !inm.empty() && (inm == a->etag || inm == std::string("W/") + a->etag)) {
                        res.status = 304;
                        return false;
                    }
                    if (isolation) {
                        res.set_header("Cross-Origin-Embedder-Policy", "require-corp");
                        res.set_header("Cross-Origin-Opener-Policy",   "same-origin");
                    }
                    res.set_header("Cache-Control", "public, max-age=31536000, immutable");
                    res.set_content(reinterpret_cast<const char*>(a->data), a->size, a->type.c_str());
                    return false;
                };
            };

            auto serve_asset_nocache = [](const std::string & name) {
                return [name](const httplib::Request & req, httplib::Response & res) {
                    if (!handle_gzip_header(req, res)) {
                        return true; // returns error message
                    }
                    const llama_ui_asset * a = llama_ui_find_asset(name);
                    if (!a) {
                        res.status = 404;
                        return false;
                    }
                    res.set_header("Cache-Control", "no-cache");
                    res.set_content(reinterpret_cast<const char*>(a->data), a->size, a->type.c_str());
                    return false;
                };
            };

            // main index file
            srv->Get(params.api_prefix + "/",           serve_asset_cached("index.html", true));
            srv->Get(params.api_prefix + "/index.html", serve_asset_cached("index.html", true));

            // All remaining assets registered directly from the embedded asset table.
            // PWA revalidation files (sw.js, manifest, version.json) use no-cache;
            // everything else is immutable.
            static const std::unordered_set<std::string> no_cache_names = {
                "sw.js",
                "manifest.webmanifest",
                "_app/version.json",
                "build.json"
            };

            for (const auto & a : llama_ui_get_assets()) {
                if (a.name == "index.html") continue;  // served at "/" and "/index.html" above
                if (no_cache_names.count(a.name)) {
                    SRV_DBG("serve nocache for %s\n", a.name.c_str());
                    srv->Get(params.api_prefix + "/" + a.name, serve_asset_nocache(a.name));
                } else {
                    srv->Get(params.api_prefix + "/" + a.name, serve_asset_cached(a.name, false));
                }
            }

#endif
        }
    }
    return true;
}

bool server_http_context::start() {
    // Bind and listen

    const auto & srv = pimpl->srv;
    auto was_bound = false;
    auto is_sock = false;
    if (string_ends_with(std::string(hostname), ".sock")) {
        is_sock = true;
        SRV_TRC("%s", "setting address family to AF_UNIX\n");
        srv->set_address_family(AF_UNIX);
        // bind_to_port requires a second arg, any value other than 0 should
        // simply get ignored
        was_bound = srv->bind_to_port(hostname, 8080);
    } else {
        SRV_TRC("%s", "binding port with default address family\n");
        // bind HTTP listen port
        if (port == 0) {
            const auto bound_port = srv->bind_to_any_port(hostname);
            was_bound = (bound_port >= 0);
            if (was_bound) {
                port = bound_port;
            }
        } else {
            was_bound = srv->bind_to_port(hostname, port);
        }
    }

    if (!was_bound) {
        SRV_ERR("couldn't bind HTTP server socket, hostname: %s, port: %d\n", hostname.c_str(), port);
        return false;
    }

    // run the HTTP server in a thread
    thread = std::thread([this] { pimpl->srv->listen_after_bind(); });
    srv->wait_until_ready();

    listening_address = is_sock ? string_format("unix://%s", hostname.c_str())
                                : string_format("%s://%s:%d", is_ssl ? "https" : "http", common_http_format_host(hostname).c_str(), port);
    return true;
}

void server_http_context::stop() const {
    if (pimpl->srv) {
        pimpl->srv->stop();
    }
}

static void set_headers(httplib::Response & res, const std::map<std::string, std::string> & headers) {
    for (const auto & [key, value] : headers) {
        res.set_header(key, value);
    }
}

// percent-decode a path component (%XX). path params arrive raw from httplib, unlike query
// params, so a conv id like "conv::model" sent as "conv%3A%3Amodel" must be decoded here to
// match the value the client put in the X-Conversation-Id header
static std::string decode_path_component(const std::string & in) {
    std::string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); i++) {
        if (in[i] == '%' && i + 2 < in.size()) {
            auto hex = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            int hi = hex(in[i + 1]);
            int lo = hex(in[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(char((hi << 4) | lo));
                i += 2;
                continue;
            }
        }
        out.push_back(in[i]);
    }
    return out;
}

static std::map<std::string, std::string> get_params(const httplib::Request & req) {
    std::map<std::string, std::string> params;
    for (const auto & [key, value] : req.params) {
        params[key] = value;
    }
    for (const auto & [key, value] : req.path_params) {
        params[key] = decode_path_component(value);
    }
    return params;
}

static std::map<std::string, std::string> get_headers(const httplib::Request & req) {
    // F007: Strip identity headers (always, from trusted or untrusted peers).
    // Single source of truth: server_auth::identity_headers() (see server-auth.h).
    static const std::unordered_set<std::string> stripped(
        server_auth::identity_headers().begin(), server_auth::identity_headers().end());
    std::map<std::string, std::string> headers;
    for (const auto & [key, value] : req.headers) {
        // Case-insensitive header comparison
        std::string lk = key;
        std::transform(lk.begin(), lk.end(), lk.begin(),
                       [](unsigned char c){ return std::tolower(c); });
        if (stripped.count(lk)) {
            continue;  // skip identity headers
        }
        headers[key] = value;
    }
    return headers;
}

static std::string build_query_string(const httplib::Request & req) {
    std::string qs;
    for (const auto & [key, value] : req.params) {
        if (!qs.empty()) {
            qs += '&';
        }
        qs += httplib::encode_query_component(key) + "=" + httplib::encode_query_component(value);
    }
    return qs;
}

// using unique_ptr for request to allow safe capturing in lambdas
using server_http_req_ptr = std::unique_ptr<server_http_req>;

static void process_handler_response(server_http_req_ptr && request, server_http_res_ptr & response, httplib::Response & res) {
    if (response->is_stream()) {
        res.status = response->status;
        // Tell Nginx to not buffer any streamed response
        response->headers["X-Accel-Buffering"] = "no";
        set_headers(res, response->headers);
        const std::string content_type = response->content_type;
        // F013: deadline after which no further SSE chunk may be written (0 = never expires)
        const int64_t auth_deadline = server_auth::stream_deadline(request->principal);
        // convert to shared_ptr as both chunked_content_provider() and on_complete() need to use it
        std::shared_ptr<server_http_req> q_ptr = std::move(request);
        std::shared_ptr<server_http_res> r_ptr = std::move(response);

        const auto chunked_content_provider = [response = r_ptr, auth_deadline](size_t, httplib::DataSink & sink) -> bool {
            // F013: only SSE responses are gated. In router mode server_http_proxy sets next()
            // unconditionally, so non-streaming JSON bodies are also "streams" here; writing SSE
            // framing into those would corrupt them. Producers that are really SSE all set this
            // content type: server-context.cpp (completions/chat/infill/responses/messages),
            // server-models.cpp (/models/sse), server-stream.cpp (GET /v1/stream),
            // server-tools.cpp (tool stream), and the proxy when the child streams.
            const bool auth_gated = auth_deadline > 0 &&
                response->content_type.rfind("text/event-stream", 0) == 0;
            const auto cut = [&]() -> bool {
                const std::string & chunk = response->sse_expired_chunk.empty()
                    ? server_auth::sse_expired_chunk_oai()
                    : response->sse_expired_chunk;
                sink.write(chunk.data(), chunk.size());
                sink.done();
                response->auth_expired = true;
                SRV_WRN("auth: access token expired mid-stream, terminating stream for %s\n",
                        response->content_type.c_str());
                return false;
            };
            if (auth_gated && server_auth::stream_expired(auth_deadline)) {
                return cut();
            }
            std::string chunk;
            const bool has_next = response->next(chunk);
            // F013: next() can block for an unbounded time (slot queue, proxy pipe read, tool wait),
            // so re-check before writing: no byte may cross the deadline (B1).
            if (auth_gated && server_auth::stream_expired(auth_deadline)) {
                return cut();
            }
            if (!chunk.empty()) {
                if (!sink.write(chunk.data(), chunk.size())) {
                    return false;
                }
                SRV_DBG("http: streamed chunk: %s\n", chunk.c_str());
            }
            if (!has_next) {
                sink.done();
                SRV_DBG("%s", "http: stream ended\n");
            }
            return has_next;
        };
        const auto on_complete = [request = q_ptr, response = r_ptr](bool) mutable {
            response->on_complete();
            response.reset();
            request.reset();
        };
        res.set_chunked_content_provider(content_type, chunked_content_provider, on_complete);
    } else {
        res.status = response->status;
        set_headers(res, response->headers);
        res.set_content(response->data, response->content_type);
        response->on_complete();
    }
}

void server_http_context::get(const std::string & path, const server_http_context::handler_t & handler) const {
    handlers.emplace(path, handler);
    registered_routes.emplace_back("GET", path);
    pimpl->srv->Get(path_prefix + path, [handler](const httplib::Request & req, httplib::Response & res) {
        server_http_req_ptr request = std::make_unique<server_http_req>(server_http_req{
            get_params(req),
            get_headers(req),
            req.path,
            build_query_string(req),
            req.body,
            {},
            req.is_connection_closed,
            {}
        });
        // F005: copy principal from thread_local to request
        request->principal = server_auth::principal_at_construction();
        server_http_res_ptr response = handler(*request);
        process_handler_response(std::move(request), response, res);
    });
}

void server_http_context::post(const std::string & path, const server_http_context::handler_t & handler) const {
    handlers.emplace(path, handler);
    registered_routes.emplace_back("POST", path);
    pimpl->srv->Post(path_prefix + path, [handler](const httplib::Request & req, httplib::Response & res) {
        std::string body = req.body;
        std::map<std::string, uploaded_file> files;

        if (req.is_multipart_form_data()) {
            // translate text fields to a JSON object and use it as the body
            json form_json = json::object();
            for (const auto & [key, field] : req.form.fields) {
                if (form_json.contains(key)) {
                    // if the key already exists, convert it to an array
                    if (!form_json[key].is_array()) {
                        json existing_value = form_json[key];
                        form_json[key] = json::array({existing_value});
                    }
                    form_json[key].push_back(field.content);
                } else {
                    form_json[key] = field.content;
                }
            }
            body = form_json.dump();

            // populate files from multipart form
            for (const auto & [key, file] : req.form.files) {
                files[key] = uploaded_file{
                    raw_buffer(file.content.begin(), file.content.end()),
                    file.filename,
                    file.content_type,
                };
            }
        }

        server_http_req_ptr request = std::make_unique<server_http_req>(server_http_req{
            get_params(req),
            get_headers(req),
            req.path,
            build_query_string(req),
            body,
            std::move(files),
            req.is_connection_closed,
            {}
        });
        // F005: copy principal from thread_local to request
        request->principal = server_auth::principal_at_construction();
        server_http_res_ptr response = handler(*request);
        process_handler_response(std::move(request), response, res);
    });
}

void server_http_context::del(const std::string & path, const server_http_context::handler_t & handler) const {
    handlers.emplace(path, handler);
    registered_routes.emplace_back("DELETE", path);
    pimpl->srv->Delete(path_prefix + path, [handler](const httplib::Request & req, httplib::Response & res) {
        server_http_req_ptr request = std::make_unique<server_http_req>(server_http_req{
            get_params(req),
            get_headers(req),
            req.path,
            build_query_string(req),
            req.body,
            {},
            req.is_connection_closed,
            {}
        });
        // F005: copy principal from thread_local to request
        request->principal = server_auth::principal_at_construction();
        server_http_res_ptr response = handler(*request);
        process_handler_response(std::move(request), response, res);
    });
}

//
// Vertex AI Prediction protocol (AIP_PREDICT_ROUTE)
// https://cloud.google.com/vertex-ai/docs/predictions/custom-container-requirements
//

// Derives the camelCase @requestFormat alias for a registered path.
// e.g. "/v1/chat/completions" -> "chatCompletions", "/apply-template" -> "applyTemplate"
static std::string path_to_gcp_format(const std::string & path) {
    std::string s = path;
    if (s.size() > 3 && s[0] == '/' && s[1] == 'v' && s[2] == '1') {
        s = s.substr(3);
    }
    if (!s.empty() && s[0] == '/') {
        s = s.substr(1);
    }
    std::string result;
    bool cap = false;
    for (unsigned char c : s) {
        if (c == ':') break; // stop before path parameters
        if (c == '/' || c == '-' || c == '_') {
            cap = true;
        } else {
            result += static_cast<char>(cap ? std::toupper(c) : c);
            cap = false;
        }
    }
    return result;
}

static json parse_gcp_predict_response(const server_http_res_ptr & res) {
    if (res == nullptr) {
        throw std::runtime_error("empty response from internal handler");
    }
    if (res->is_stream()) {
        throw std::invalid_argument("predict route does not support streaming responses");
    }
    if (res->data.empty()) {
        return nullptr;
    }
    try {
        return json::parse(res->data);
    } catch (...) {
        return res->data;
    }
}

void server_http_context::register_gcp_compat() const {
    const gcp_params gcp;

    if (!gcp.enabled) {
        // do nothing
        return;
    }

    if (handlers.count(gcp.path_predict)) {
        SRV_ERR("AIP_PREDICT_ROUTE=%s conflicts with an existing llama-server route\n", gcp.path_predict.c_str());
        exit(1);
    }

    // Register dynamic gcp routes for auth
    server_auth::register_route("POST", gcp.path_predict, PERM_INFER);
    if (!gcp.path_health.empty()) {
        server_auth::register_route("GET", gcp.path_health, PERM_PUBLIC);
    }

    // camelCase alias -> canonical path (first registration wins on collision)
    // e.g. "chatCompletions" -> "/v1/chat/completions"
    std::unordered_map<std::string, std::string> alias_to_path;
    for (const auto & [path, _] : handlers) {
        alias_to_path.emplace(path_to_gcp_format(path), path);
    }

    if (!gcp.path_health.empty()) {
        const auto health_handler = handlers.find("/health");
        GGML_ASSERT(health_handler != handlers.end());
        get(gcp.path_health, health_handler->second);
    }

    post(gcp.path_predict, [this, alias_to_path = std::move(alias_to_path)](const server_http_req & req) -> server_http_res_ptr {
        static const auto build_error = [](const std::string & message, error_type type) -> json {
            return json {{"error", format_error_response(message, type)}};
        };

        json data;
        try {
            data = json::parse(req.body);
        } catch (const std::exception & e) {
            auto res = std::make_unique<server_http_res>();
            res->status = 400;
            res->data = safe_json_to_str({{"error", format_error_response(e.what(), ERROR_TYPE_INVALID_REQUEST)}});
            return res;
        }
        if (!data.is_object()) {
            auto res = std::make_unique<server_http_res>();
            res->status = 400;
            res->data = safe_json_to_str({{"error", format_error_response("request body must be a JSON object", ERROR_TYPE_INVALID_REQUEST)}});
            return res;
        }
        if (!data.contains("instances") || !data.at("instances").is_array()) {
            auto res = std::make_unique<server_http_res>();
            res->status = 400;
            res->data = safe_json_to_str({{"error", format_error_response("request body must include an array field named instances", ERROR_TYPE_INVALID_REQUEST)}});
            return res;
        }

        const json & instances = data.at("instances");
        static const size_t MAX_INSTANCES = 128;
        if (instances.size() > MAX_INSTANCES) {
            auto res = std::make_unique<server_http_res>();
            res->status = 400;
            res->data = safe_json_to_str({{"error", format_error_response("instances array exceeds maximum size of " + std::to_string(MAX_INSTANCES), ERROR_TYPE_INVALID_REQUEST)}});
            return res;
        }

        std::vector<std::future<json>> futures;
        futures.reserve(instances.size());

        for (const auto & instance : instances) {
            futures.push_back(std::async(std::launch::async, [this, &req, &alias_to_path, instance]() -> json {
                if (!instance.is_object()) {
                    return build_error("each instance must be a JSON object", ERROR_TYPE_INVALID_REQUEST);
                }
                if (!instance.contains("@requestFormat") || !instance.at("@requestFormat").is_string()) {
                    return build_error("each instance must include a string @requestFormat", ERROR_TYPE_INVALID_REQUEST);
                }

                try {
                    json payload = instance;
                    const std::string format = payload.at("@requestFormat").get<std::string>();
                    payload.erase("@requestFormat");

                    if (payload.contains("stream")) {
                        SRV_WRN("%s", "ignoring client-provided stream field in instance, streaming is not supported in predict route\n");
                        payload["stream"] = false;
                    }

                    // accept both camelCase aliases (e.g. "chatCompletions") and direct paths
                    std::string dispatch_path;
                    auto it_alias = alias_to_path.find(format);
                    if (it_alias != alias_to_path.end()) {
                        dispatch_path = it_alias->second;
                    } else if (handlers.count(format)) {
                        dispatch_path = format;
                    } else {
                        return build_error("no handler registered for @requestFormat: " + format, ERROR_TYPE_INVALID_REQUEST);
                    }

                    // Check that dispatch_path is INFER-only (S1: prevent escalation)
                    if (!server_auth::is_infer_only(dispatch_path)) {
                        return build_error("requestFormat not permitted via predict route: " + format,
                                         ERROR_TYPE_PERMISSION);
                    }

                    const server_http_req internal_req {
                        req.params,
                        req.headers,
                        path_prefix + dispatch_path,
                        req.query_string,
                        payload.dump(),
                        {},
                        req.should_stop,
                        req.principal,  // F005: carry outer principal onto async path
                    };

                    server_http_res_ptr internal_res = handlers.at(dispatch_path)(internal_req);
                    return parse_gcp_predict_response(internal_res);
                } catch (const std::invalid_argument & e) {
                    return build_error(e.what(), ERROR_TYPE_INVALID_REQUEST);
                } catch (const std::exception & e) {
                    return build_error(e.what(), ERROR_TYPE_SERVER);
                } catch (...) {
                    return build_error("unknown error", ERROR_TYPE_SERVER);
                }
            }));
        }

        json predictions = json::array();
        for (auto & future : futures) {
            predictions.push_back(future.get());
        }

        auto res = std::make_unique<server_http_res>();
        res->data = safe_json_to_str({{"predictions", predictions}});
        return res;
    });
}
