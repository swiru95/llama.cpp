#pragma once

#include <string>

struct common_params;

// Resolved, validated mTLS configuration built from common_params flags.
struct server_mtls_config {
    bool        enabled        = false;   // required or optional mode requested
    bool        require_cert   = false;   // true = required mode (fail handshake if no cert)
    std::string client_ca_file;           // may be empty if dir is set
    std::string client_ca_dir;            // may be empty if file is set
    int         verify_depth   = 1;       // SSL_CTX_set_verify_depth argument (SPIFFE: leaf-under-issuer)
    int         min_tls_version = 0x0303; // TLS1_2 (0x0303) or TLS1_3 (0x0304)
    std::string crl_file;                 // F010a: PEM CRL bundle (empty = no revocation checking)
    int crl_reload_interval = 0;          // F016: seconds between CRL re-stat checks; 0 = no reload
    // identity_source and role mapping are POLICY concerns (server-auth.cpp), not here.
};

// Client certificate identity extracted from a verified peer cert (SAN only, no CN/DN).
struct mtls_identity {
    bool        present = false;   // a verified peer cert was presented
    std::string san_uri;          // first SAN of type URI ("" if none or ambiguous)
    std::string san_dns;          // first SAN of type DNS ("" if none or ambiguous)
    // deliberately NO cn/subject_dn field (CN not used, DN is PII we must not log).
};

struct server_mtls {
    // Check whether mTLS is enabled (set by configure()). Used to runtime-gate expensive
    // operations like peer certificate extraction. Never throws.
    static bool enabled();

    // Parse and validate common_params into a server_mtls_config. Returns false (and logs
    // SRV_ERR) on invalid combinations: unknown --mtls-required/--tls-min-version values,
    // negative --mtls-verify-depth, or (mode != off) without a CA file or dir. Never throws.
    // ALWAYS populates cfg.min_tls_version even when mode is off (applies to any SSL server).
    static bool configure(const common_params & params, server_mtls_config & out);

    // Apply TLS context hardening to ANY SSL server (the value from SSLServer::tls_context()).
    // ctx is a tls::ctx_t (void*); cast to SSL_CTX* internally under CPPHTTPLIB_OPENSSL_SUPPORT.
    // ALWAYS sets the min proto version from cfg.min_tls_version (so --tls-min-version is honored
    // with or without mTLS). WHEN cfg.enabled additionally sets the verify depth and - when
    // cfg.require_cert is false (optional mode) - re-sets the verify mode to SSL_VERIFY_PEER
    // WITHOUT SSL_VERIFY_FAIL_IF_NO_PEER_CERT so a client may connect without a cert.
    // Returns false on any setter failure or if built without OpenSSL support. Never throws.
    static bool harden_context(void * ctx, const server_mtls_config & cfg);

    // Extract SAN identity from a verified peer certificate. Called by middleware_authz
    // inside #ifdef CPPHTTPLIB_SSL_ENABLED, passing the address of the httplib::tls::PeerCert
    // obtained via req.peer_cert() (opaque const void*; httplib does not expose a public way
    // to build a PeerCert from req.ssl directly - tls::get_peer_cert_from_session is friend-only
    // inside PeerCert and not reachable via qualified lookup from outside httplib.cpp).
    // Returns false and leaves out.present=false if peer_cert is null or carries no cert
    // (optional mode, no client cert presented). Returns true with out.present=true and
    // out.san_uri/san_dns populated (one per SAN type, or "" if ambiguous/absent). Never throws.
    static bool extract_identity(const void * peer_cert, mtls_identity & out);

    // F016: Stop the CRL reload thread (idempotent; sets the stop flag). Never throws; safe
    // to call from a signal handler. Does not join or block. Called from server_http_context::stop().
    static void crl_reload_stop();

    // F016: CRL reload statistics for metric exposure. Only used if crl_reload is active.
    // (uint64_t reload_failures, int64_t last_success_unix, int64_t earliest_next_update)
    static void crl_stats(uint64_t & out_failures, int64_t & out_last_success,
                          int64_t & out_earliest_next_update);
};
