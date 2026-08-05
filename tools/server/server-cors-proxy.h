#pragma once

#include "common.h"
#include "http.h"
#include "server-ssrf.h"

#include <string>
#include <unordered_set>
#include <list>
#include <map>
#include <algorithm>
#include <cctype>

#include "server-http.h"

static std::string proxy_header_to_lower(std::string header) {
    std::transform(header.begin(), header.end(), header.begin(), [](unsigned char c) {
        return std::tolower(c);
    });
    return header;
}

static server_http_res_ptr proxy_request(const server_http_req & req, std::string method) {
    std::string target_url = req.get_param("url");

    common_http_url parsed_url;
    try {
        parsed_url = common_http_parse_url(target_url);
    } catch (const std::out_of_range &) {
        // R-A3: wrap parse_url to catch std::out_of_range from stoi and return 403
        auto res = std::make_unique<server_http_res>();
        res->status = 403;
        res->data = safe_json_to_str({
            {"error", {
                {"message", "proxy target not allowed"},
                {"type", "proxy_target_denied"},
            }}
        });
        return res;
    } catch (...) {
        throw;
    }

    if (parsed_url.host.empty()) {
        throw std::runtime_error("invalid target URL: missing host");
    }

    if (parsed_url.path.empty()) {
        parsed_url.path = "/";
    }

    if (!parsed_url.password.empty()) {
        throw std::runtime_error("authentication in target URL is not supported");
    }

    if (parsed_url.scheme != "http" && parsed_url.scheme != "https") {
        throw std::runtime_error("unsupported URL scheme in target URL: " + parsed_url.scheme);
    }

    // F014: SSRF check before making the request
    server_ssrf_target tgt;
    std::string ssrf_reason;
    if (!server_ssrf::check_target(parsed_url.host, parsed_url.port, tgt, ssrf_reason)) {
        SRV_WRN("cors-proxy: target denied (%s)\n", ssrf_reason.c_str());
        auto res = std::make_unique<server_http_res>();
        res->status = 403;
        res->data = safe_json_to_str({
            {"error", {
                {"message", "proxy target not allowed"},
                {"type", "proxy_target_denied"},
            }}
        });
        return res;
    }

    SRV_INF("proxying %s request to %s://%s:%i%s\n", method.c_str(), parsed_url.scheme.c_str(), common_http_format_host(parsed_url.host).c_str(), parsed_url.port, parsed_url.path.c_str());

    std::map<std::string, std::string> headers;
    const std::string proxy_header_prefix = "x-llama-server-proxy-header-";
    // B1-c: denylist of headers that must never be forwarded
    static const std::unordered_set<std::string> denied_headers = {
        "x-auth-subject", "x-auth-roles", "x-api-key",
        "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
        "x-real-ip", "forwarded"
    };

    for (auto [key, value] : req.headers) {
        const std::string lowered_key = proxy_header_to_lower(key);
        if (!string_starts_with(lowered_key, proxy_header_prefix)) {
            continue;
        }

        auto new_key = key.substr(proxy_header_prefix.size());
        if (new_key.empty()) {
            continue;
        }

        const std::string new_key_lower = proxy_header_to_lower(new_key);
        if (denied_headers.count(new_key_lower) > 0) {
            continue;  // Skip denied headers
        }

        headers[new_key] = value;
    }

    auto proxy = std::make_unique<server_http_proxy>(
            method,
            parsed_url.scheme,
            tgt.host,  // Use original host for SNI/cert verification
            tgt.port,
            parsed_url.path,
            headers,
            req.body,
            req.files,
            req.should_stop,
            600, // timeout_read (default to 10 minutes)
            600,  // timeout_write (default to 10 minutes)
            server_http_proxy_opts{tgt.pinned_ip, false}  // F014: pin IP and refuse redirects
            );

    return proxy;
}

static server_http_context::handler_t proxy_handler_post = [](const server_http_req & req) -> server_http_res_ptr {
    return proxy_request(req, "POST");
};

static server_http_context::handler_t proxy_handler_get = [](const server_http_req & req) -> server_http_res_ptr {
    return proxy_request(req, "GET");
};
