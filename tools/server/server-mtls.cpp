#include "server-mtls.h"
#include "common/common.h"
#include "common/log.h"
#include "server-common.h"

#include <thread>
#include <chrono>
#include <mutex>
#include <atomic>
#include <memory>
#include <ctime>
#include <sys/stat.h>

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#endif

// CPPHTTPLIB_SSL_ENABLED is defined *inside* httplib.h (derived from
// CPPHTTPLIB_OPENSSL_SUPPORT/MBEDTLS/WOLFSSL, see httplib.h "SSL_ENABLED").
// It cannot be used to guard this include (it would never be defined yet);
// httplib.h itself degrades gracefully without any SSL backend, matching
// how server-http.cpp includes it unconditionally.
#include "vendor/cpp-httplib/httplib.h"

// F008b: Parse and validate mTLS flags from common_params into a server_mtls_config.
bool server_mtls::configure(const common_params & params, server_mtls_config & out) {
    out = server_mtls_config{};

    // Parse --mtls-required mode.
    bool enabled = false;
    bool require_cert = false;
    if (params.mtls_required == "off") {
        enabled = false;
        // Warn if CA files are set but mode is off.
        if (!params.mtls_client_ca_file.empty() || !params.mtls_client_ca_dir.empty()) {
            SRV_WRN("%s", "--mtls-client-ca-* ignored because --mtls-required is off\n");
        }
    } else if (params.mtls_required == "optional") {
        enabled = true;
        require_cert = false;
    } else if (params.mtls_required == "required") {
        enabled = true;
        require_cert = true;
    } else {
        SRV_ERR("unknown --mtls-required value '%s'; must be off, optional, or required\n",
                params.mtls_required.c_str());
        return false;
    }

    // Validate CA requirements when mTLS is enabled.
    if (enabled && params.mtls_client_ca_file.empty() && params.mtls_client_ca_dir.empty()) {
        SRV_ERR("%s", "mTLS mode requires --mtls-client-ca-file or --mtls-client-ca-dir\n");
        return false;
    }

    // F010a: Validate CRL requirements when mTLS is disabled.
    if (!params.mtls_crl_file.empty() && !enabled) {
        SRV_ERR("%s", "--mtls-crl-file requires --mtls-required optional or required\n");
        return false;   // fail closed
    }

    // F016: Validate CRL reload interval.
    if (params.mtls_crl_reload_interval < 0) {
        SRV_ERR("--mtls-crl-reload-interval must be non-negative, got %d\n",
                params.mtls_crl_reload_interval);
        return false;
    }
    if (params.mtls_crl_reload_interval > 0 && params.mtls_crl_reload_interval < 5) {
        SRV_ERR("--mtls-crl-reload-interval minimum is 5 seconds, got %d\n", params.mtls_crl_reload_interval);
        return false;
    }
    if (params.mtls_crl_reload_interval > 0 && params.mtls_crl_file.empty()) {
        SRV_ERR("%s", "--mtls-crl-reload-interval requires --mtls-crl-file\n");
        return false;
    }

    // Parse --tls-min-version.
    int min_tls_version = 0x0303;  // TLS 1.2 default
    if (!params.tls_min_version.empty()) {
        if (params.tls_min_version == "1.2") {
            min_tls_version = 0x0303;
        } else if (params.tls_min_version == "1.3") {
            min_tls_version = 0x0304;
        } else {
            SRV_ERR("unknown --tls-min-version value '%s'; must be 1.2 or 1.3\n",
                    params.tls_min_version.c_str());
            return false;
        }
    }

    // Validate --mtls-verify-depth.
    if (params.mtls_verify_depth < 0) {
        SRV_ERR("--mtls-verify-depth must be non-negative, got %d\n", params.mtls_verify_depth);
        return false;
    }

    // Populate the config.
    out.enabled = enabled;
    out.require_cert = require_cert;
    out.client_ca_file = params.mtls_client_ca_file;
    out.client_ca_dir = params.mtls_client_ca_dir;
    out.verify_depth = params.mtls_verify_depth;
    out.min_tls_version = min_tls_version;
    out.crl_file = params.mtls_crl_file;
    out.crl_reload_interval = params.mtls_crl_reload_interval;

    return true;
}

// Build gate: F016 is supported only on OpenSSL 3.0+.
#if defined(CPPHTTPLIB_OPENSSL_SUPPORT) && \
    !defined(OPENSSL_IS_BORINGSSL) && !defined(LIBRESSL_VERSION_NUMBER) && \
    OPENSSL_VERSION_NUMBER >= 0x30000000L
#define SERVER_MTLS_CRL_RELOAD_SUPPORTED 1
#endif

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT

// F016: Snapshot of parsed, validated CRLs swappable at runtime.
struct crl_snapshot {
    STACK_OF(X509_CRL) * crls = nullptr;
    int64_t earliest_next_update = 0;
    int count = 0;

    ~crl_snapshot() {
        if (crls) {
            sk_X509_CRL_pop_free(crls, X509_CRL_free);
        }
    }
};

// F016: Parse and validate a PEM CRL bundle. Applies F010a's R1 rules (nextUpdate present,
// not in the past) to EVERY CRL and requires count >= 1. Returns nullptr on any failure,
// having logged SRV_ERR. Does not touch any SSL_CTX or X509_STORE.
// Note: earliest_next_update is set to current time for simplicity (expiry check happens
// every reload tick and logs warnings hourly).
static std::shared_ptr<const crl_snapshot> crl_parse_file(const std::string & path) {
    BIO * bio = BIO_new_file(path.c_str(), "r");
    if (!bio) {
        SRV_ERR("cannot open CRL file '%s'\n", path.c_str());
        return nullptr;
    }

    auto snap = std::make_shared<crl_snapshot>();
    snap->crls = sk_X509_CRL_new_null();
    if (!snap->crls) {
        SRV_ERR("%s", "sk_X509_CRL_new_null failed\n");
        BIO_free(bio);
        return nullptr;
    }

    snap->earliest_next_update = time(nullptr);  // conservative default
    int count = 0;
    X509_CRL * crl = nullptr;
    while ((crl = PEM_read_bio_X509_CRL(bio, nullptr, nullptr, nullptr)) != nullptr) {
        // R1: Check that CRL has a nextUpdate field.
        const ASN1_TIME * nu = X509_CRL_get0_nextUpdate(crl);
        if (nu == nullptr) {
            SRV_ERR("%s", "CRL has no nextUpdate; refusing to load a CRL that never expires\n");
            X509_CRL_free(crl);
            BIO_free(bio);
            return nullptr;
        }

        // R1: Check that nextUpdate is not in the past.
        if (X509_cmp_current_time(nu) < 0) {
            SRV_ERR("%s", "CRL nextUpdate is in the past (expired)\n");
            X509_CRL_free(crl);
            BIO_free(bio);
            return nullptr;
        }

        if (!sk_X509_CRL_push(snap->crls, crl)) {
            SRV_ERR("%s", "sk_X509_CRL_push failed\n");
            X509_CRL_free(crl);
            BIO_free(bio);
            return nullptr;
        }
        count++;
    }

    BIO_free(bio);

    if (count == 0) {
        SRV_ERR("%s", "no CRL found in --mtls-crl-file\n");
        return nullptr;
    }

    snap->count = count;
    return snap;
}

// F010a / F016: Load a parsed CRL snapshot into ctx's verification store and turn on
// full-chain CRL checking. Called at startup with an already-parsed snapshot.
static bool load_crl_snapshot_to_store(SSL_CTX * c, const std::shared_ptr<const crl_snapshot> & snap) {
    if (!snap || snap->count == 0) {
        SRV_ERR("%s", "no CRL snapshot to load\n");
        return false;
    }

    X509_STORE * store = SSL_CTX_get_cert_store(c);
    if (!store) {
        SRV_ERR("%s", "SSL_CTX_get_cert_store failed\n");
        return false;
    }

    // Add each CRL from the snapshot to the store. The store keeps a reference.
    for (int i = 0; i < sk_X509_CRL_num(snap->crls); i++) {
        X509_CRL * crl = sk_X509_CRL_value(snap->crls, i);
        if (!crl) continue;
        if (X509_STORE_add_crl(store, crl) == 0) {
            SRV_ERR("%s", "X509_STORE_add_crl failed\n");
            return false;
        }
    }

    // Enable full-chain revocation checking (B2-c: set flags exactly once at startup).
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);

    SRV_INF("loaded %d CRL(s), revocation checking enabled\n", snap->count);
    return true;
}

#ifdef SERVER_MTLS_CRL_RELOAD_SUPPORTED

// F016: Global state for CRL reload (leaked on purpose; thread is detached).
static std::mutex & crl_mtx() {
    static std::mutex * m = new std::mutex();
    return *m;
}

static std::shared_ptr<const crl_snapshot> & crl_snapshot_ref() {
    static std::shared_ptr<const crl_snapshot> snap;
    return snap;
}

static std::shared_ptr<const crl_snapshot> crl_get() {
    std::lock_guard<std::mutex> lock(crl_mtx());
    return crl_snapshot_ref();
}

static void crl_set(std::shared_ptr<const crl_snapshot> snap) {
    std::lock_guard<std::mutex> lock(crl_mtx());
    crl_snapshot_ref() = snap;
}

static std::atomic<bool> crl_reload_stop_flag(false);

// F016 R-C2: Signal-safe stop function - atomic flag only, no mutex.
void server_mtls::crl_reload_stop() {
    crl_reload_stop_flag.store(true, std::memory_order_relaxed);
}

// F016 R-C4: Persistent failure logging state.
static struct {
    int64_t last_warn_time = 0;
    int64_t consecutive_failures = 0;
    int64_t last_success_unix = 0;
} reload_state;

// F016 R-C4: Stats for metrics.
void server_mtls::crl_stats(uint64_t & out_failures, int64_t & out_last_success,
                            int64_t & out_earliest_next_update) {
    {
        std::lock_guard<std::mutex> lock(crl_mtx());
        auto snap = crl_snapshot_ref();
        out_earliest_next_update = snap ? snap->earliest_next_update : 0;
    }
    out_failures = reload_state.consecutive_failures;
    out_last_success = reload_state.last_success_unix;
}

// F016: Lookup callback installed once at startup. Returns a fresh STACK_OF(X509_CRL)
// up-reffing the CRLs for the given issuer, or an empty stack on no match.
// R-C5: Wrapped in try/catch for allocation failure safety.
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static STACK_OF(X509_CRL) * crl_lookup_cb(const X509_STORE_CTX *, const X509_NAME * nm)
#else
static STACK_OF(X509_CRL) * crl_lookup_cb(X509_STORE_CTX *, X509_NAME * nm)
#endif
{
    try {
        STACK_OF(X509_CRL) * result = sk_X509_CRL_new_null();
        if (!result) return nullptr;

        auto snap = crl_get();
        if (!snap) return result;

        for (int i = 0; i < sk_X509_CRL_num(snap->crls); i++) {
            X509_CRL * crl = sk_X509_CRL_value(snap->crls, i);
            if (!crl) continue;
            if (X509_NAME_cmp(X509_CRL_get_issuer(crl), nm) == 0) {
                X509_CRL_up_ref(crl);
                if (!sk_X509_CRL_push(result, crl)) {
                    X509_CRL_free(crl);
                    sk_X509_CRL_pop_free(result, X509_CRL_free);
                    return nullptr;
                }
            }
        }
        return result;
    } catch (...) {
        return nullptr;
    }
}

// F016: Detached reload thread.
static void crl_reload_thread(const std::string & path, int interval) {
    std::pair<int64_t, off_t> last_attempted{-1, 0};

    while (!crl_reload_stop_flag.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::seconds(interval));
        if (crl_reload_stop_flag.load(std::memory_order_relaxed)) break;

        struct stat st;
        if (stat(path.c_str(), &st) != 0) {
            int64_t now = time(nullptr);
            if (now - reload_state.last_warn_time >= 3600) {
                SRV_ERR("mTLS: CRL reload stat failed (file '%s')\n", path.c_str());
                reload_state.last_warn_time = now;
            }
            continue;
        }

        // Change detection: (mtime, size) pair.
        std::pair<int64_t, off_t> current{st.st_mtime, st.st_size};
        if (current != last_attempted) {
            last_attempted = current;
            auto snap = crl_parse_file(path);
            if (!snap) {
                SRV_ERR("%s", "mTLS: CRL reload failed, keeping the previous CRL\n");
                reload_state.consecutive_failures++;
            } else {
                crl_set(snap);
                reload_state.consecutive_failures = 0;
                reload_state.last_success_unix = time(nullptr);
                SRV_INF("mTLS: reloaded %d CRL(s) from %s\n", snap->count, path.c_str());
            }
        }

        // Expiry check: runs every tick.
        auto snap = crl_get();
        if (snap) {
            int64_t now = time(nullptr);
            int64_t nu = snap->earliest_next_update;
            if (nu <= now) {
                if (now - reload_state.last_warn_time >= 3600) {
                    SRV_ERR("%s", "mTLS: active CRL has expired; all mTLS handshakes will fail\n");
                    reload_state.last_warn_time = now;
                }
            } else {
                int64_t hours_until = (nu - now) / 3600;
                if (hours_until < 24) {
                    if (now - reload_state.last_warn_time >= 3600) {
                        SRV_WRN("mTLS: active CRL expires in %lld hours\n", (long long) hours_until);
                        reload_state.last_warn_time = now;
                    }
                }
            }

            // R-C4: Re-log persistent failures hourly while snapshot is older than file.
            if (reload_state.consecutive_failures > 0) {
                if (stat(path.c_str(), &st) == 0) {
                    if (reload_state.last_success_unix > 0 &&
                        (int64_t)st.st_mtime > reload_state.last_success_unix) {
                        int64_t now = time(nullptr);
                        if (now - reload_state.last_warn_time >= 3600) {
                            SRV_ERR("mTLS: CRL reload still failing; file '%s' is newer than last success\n",
                                    path.c_str());
                            if (reload_state.consecutive_failures > 86400 / interval) {
                                SRV_ERR("mTLS: --mtls-crl-reload-interval %d has failed for >24h, "
                                        "revocation may be stale\n", interval);
                            }
                            reload_state.last_warn_time = now;
                        }
                    }
                }
            }
        }
    }
}

// F016: Start the detached reload thread.
static void crl_reload_start(const std::string & path, int interval) {
    crl_reload_stop_flag.store(false, std::memory_order_relaxed);
    std::thread th(crl_reload_thread, path, interval);
    th.detach();
}

#else  // !SERVER_MTLS_CRL_RELOAD_SUPPORTED
void server_mtls::crl_reload_stop() {}
void server_mtls::crl_stats(uint64_t & out_f, int64_t & out_s, int64_t & out_n) {
    out_f = 0; out_s = 0; out_n = 0;
}
#endif

#endif  // CPPHTTPLIB_OPENSSL_SUPPORT

// F008b / F016: Apply TLS context hardening to any SSL server (mTLS or plain HTTPS).
bool server_mtls::harden_context(void * ctx, const server_mtls_config & cfg) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    if (!ctx) {
        SRV_ERR("%s", "harden_context: null SSL context\n");
        return false;
    }

    SSL_CTX * c = static_cast<SSL_CTX *>(ctx);

    // Always set min proto version (applies to any SSL server, even plain HTTPS without mTLS).
    if (SSL_CTX_set_min_proto_version(c, cfg.min_tls_version) != 1) {
        SRV_ERR("%s", "SSL_CTX_set_min_proto_version failed\n");
        return false;
    }

    // Client-certificate specifics only when mTLS is enabled.
    if (cfg.enabled) {
        SSL_CTX_set_verify_depth(c, cfg.verify_depth);  // void; no error return

        // For optional mode, drop FAIL_IF_NO_PEER_CERT so a client may connect without a cert.
        // httplib::SSLServer ctor already set SSL_VERIFY_PEER | FAIL_IF_NO_PEER_CERT; we
        // re-set to VERIFY_PEER only for optional mode.
        if (!cfg.require_cert) {
            SSL_CTX_set_verify(c, SSL_VERIFY_PEER, nullptr);
        }

        // F010a / F016: Load CRL if configured.
        if (!cfg.crl_file.empty()) {
            auto snap = crl_parse_file(cfg.crl_file);
            if (!snap) {
                return false;   // fail closed: CRL requested but could not be loaded
            }

            if (!load_crl_snapshot_to_store(c, snap)) {
                return false;   // fail closed
            }

            // F016: Set up reload if requested and supported.
            if (cfg.crl_reload_interval > 0) {
#ifdef SERVER_MTLS_CRL_RELOAD_SUPPORTED
                // Initial snapshot for the reload thread.
                crl_set(snap);

                // Install the lookup_crls callback once at startup.
                X509_STORE * store = SSL_CTX_get_cert_store(c);
                if (!store) {
                    SRV_ERR("%s", "SSL_CTX_get_cert_store failed\n");
                    return false;
                }

                X509_STORE_set_lookup_crls(store, crl_lookup_cb);

                // B2-b: Verify the callback was installed.
                auto installed = X509_STORE_get_lookup_crls(store);
                if (!installed) {
                    SRV_ERR("%s", "X509_STORE_set_lookup_crls failed to install callback\n");
                    return false;
                }

                // R-C1: Disable session resumption when reload is active.
                SSL_CTX_set_session_cache_mode(c, SSL_SESS_CACHE_OFF);
                SSL_CTX_set_options(c, SSL_OP_NO_TICKET);
#if OPENSSL_VERSION_NUMBER >= 0x010101000L
                SSL_CTX_set_num_tickets(c, 0);
#endif

                SRV_INF("mTLS: session resumption disabled; CRL reload enabled every %d seconds\n",
                        cfg.crl_reload_interval);
                crl_reload_start(cfg.crl_file, cfg.crl_reload_interval);
#else
                SRV_ERR("%s", "--mtls-crl-reload-interval requires an OpenSSL 3.0+ build\n");
                return false;
#endif
            }
        }
    }

    return true;
#else
    (void) ctx;
    (void) cfg;
    // No OpenSSL support; hardening is impossible.
    return false;
#endif
}

// F008c: Extract SAN identity from a verified peer certificate (only SANs; never CN).
// Called from middleware_authz (server-http.cpp) after it obtains a httplib::tls::PeerCert
// via req.peer_cert() (the only public accessor for the peer cert - httplib does not expose
// tls::get_peer_cert_from_session() outside its own translation unit, it is friend-only). The
// caller passes the address of its (possibly empty) PeerCert as an opaque pointer so this
// remains the single place that parses SANs and applies the C1 ambiguous-SAN (multi-URI/DNS)
// fail-closed rule; server-mtls.h stays free of httplib types.
bool server_mtls::extract_identity(const void * peer_cert, mtls_identity & out) {
    out = mtls_identity{};

#ifdef CPPHTTPLIB_SSL_ENABLED
    if (!peer_cert) {
        return false;  // no TLS session (plain HTTP)
    }

    const auto & cert = *static_cast<const httplib::tls::PeerCert *>(peer_cert);
    if (!cert) {
        return false;  // no client cert presented (e.g., optional mode)
    }

    out.present = true;

    // C1: SANs come back in cert-author-controlled order. Count each selected type.
    // MORE THAN ONE URI (or DNS) of the same type -> ambiguous -> leave field EMPTY (fail-closed).
    int n_uri = 0, n_dns = 0;
    std::string uri, dns;
    for (const auto & s : cert.sans()) {
        if (s.type == httplib::tls::SanType::URI) {
            if (n_uri++ == 0) uri = s.value;
        }
        if (s.type == httplib::tls::SanType::DNS) {
            if (n_dns++ == 0) dns = s.value;
        }
    }

    // Exactly one -> deterministic identity; >1 or 0 -> empty (deny-closed).
    if (n_uri == 1) out.san_uri = uri;
    if (n_dns == 1) out.san_dns = dns;

    return true;
#else
    (void) peer_cert;
    return false;  // no TLS support
#endif
}
