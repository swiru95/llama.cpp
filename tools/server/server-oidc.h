#pragma once

#include <cstdint>
#include <string>

struct common_params;

// Result of validating one JWT access token. On ok==false all other fields are unset and
// `error` holds a SHORT, non-sensitive reason (for audit/metrics); the token is NEVER copied
// into `error`.
struct oidc_validation {
    bool        ok         = false;
    std::string subject;        // "sub" claim
    std::string issuer;         // "iss" claim (already verified == configured issuer)
    int64_t     expires_at = 0; // "exp" (unix seconds; 0 if absent, but absence fails validation)
    std::string claims_json;    // the verified payload serialized as JSON, for role extraction
    std::string error;          // short failure reason; never the token
};

struct server_oidc {
    // True iff OIDC is configured: --oidc-issuer OR --oidc-jwks-url is set. Pure param check,
    // safe to call before init and on any build.
    static bool configured(const common_params & params);

    // Parse/validate config, resolve the JWKS URL (explicit --oidc-jwks-url wins over discovery
    // from --oidc-issuer), and perform the initial MANDATORY JWKS fetch. Returns false (fail
    // closed, logs SRV_ERR) on any misconfiguration OR if the initial fetch fails (PLAN 4.2c:
    // the server does not start). Returns true and is a no-op when not configured. Requires an
    // OpenSSL build when configured; without it, returns false. Never throws.
    static bool init(const common_params & params);

    // Validate one bearer token (already stripped of a leading "Bearer "). Never throws.
    // Enforces the fixed order in section 4.3. Safe only after a successful init.
    static oidc_validation validate(const std::string & token);

    // True iff `token` has JWT shape: exactly three non-empty, base64url-charset segments
    // separated by '.'. Pure string check (no crypto), used by resolve_principal to tell a
    // Bearer JWT apart from a Bearer API key (section 5.3). Safe on any build.
    static bool looks_like_jwt(const std::string & token);

    // Set whether to require typ=="at+jwt" in the token header. Called from server-auth::init
    // before validate() is called, on every OIDC-enabled path (C3). Never throws.
    static void set_require_typ(bool require_typ);

    // F010b: True iff introspection is configured: --oidc-introspection-url is set. Pure param check.
    static bool introspection_configured(const common_params & params);

    // F010b: Introspect one opaque bearer token via RFC 7662 (POST + client-credential auth). Never throws.
    // Caches by token hash (positive TTL <= min(exp-now, 60s); negative TTL a few seconds). Returns
    // an oidc_validation exactly like validate(): ok=true with subject/issuer/expires_at/claims_json
    // on active==true, ok=false otherwise. Safe only after a successful init.
    static oidc_validation introspect(const std::string & token);

    // F015: JWKS refresh counters (success, failure). Zero-filled when OIDC is not configured.
    static void jwks_refresh_counts(uint64_t & out_success, uint64_t & out_failure);
};
