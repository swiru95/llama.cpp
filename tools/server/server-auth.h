#pragma once

#include "server-common.h"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

struct common_params;

// Permission bits. Roles are named sets of these; see the policy JSON.
// PR1 uses PERM_PUBLIC as the sentinel for "no authentication required".
enum server_perm : uint32_t {
    PERM_PUBLIC       = 0u,        // no auth required (health, etc.)
    PERM_INFER        = 1u << 0,
    PERM_READ_STATE   = 1u << 1,
    PERM_METRICS      = 1u << 2,
    PERM_ADMIN_STATE  = 1u << 3,
    PERM_ADMIN_MODELS = 1u << 4,
    PERM_PROXY        = 1u << 5,
};

// All non-public permission bits OR-ed together. Used by legacy super-user keys.
static constexpr uint32_t PERM_ALL =
    PERM_INFER | PERM_READ_STATE | PERM_METRICS |
    PERM_ADMIN_STATE | PERM_ADMIN_MODELS | PERM_PROXY;

// Authentication method. Extended in PR3/PR4/F007.
enum server_auth_method { AUTH_NONE, AUTH_API_KEY, AUTH_TRUSTED_PROXY, AUTH_MTLS, AUTH_OIDC };
static constexpr int AUTH_METHOD_COUNT = 5;  // for metrics array sizing (F015)

// Canonical names of the identity headers a trusted proxy injects. This is the
// single source of truth for two sites that must never drift apart:
//   - server-http.cpp middleware_authz reads these to build server_auth_request
//     (honored only if the peer is trusted, see server_auth::authorize_request)
//   - server-http.cpp get_headers strips these from every proxied request via
//     server_auth::identity_headers(), so a client can never spoof them
// Adding a header here and to identity_headers() below strips it everywhere;
// wire up a matching read in middleware_authz if it must also be honored.
namespace server_auth_headers {
    constexpr const char * X_AUTH_SUBJECT          = "X-Auth-Subject";
    constexpr const char * X_AUTH_ROLES             = "X-Auth-Roles";
    constexpr const char * X_FORWARDED_CLIENT_CERT  = "X-Forwarded-Client-Cert";
}

// The identity resolved for a request. Propagated to handlers via req.principal (F005).
struct server_auth_principal {
    bool                     authenticated = false;
    std::string              subject;        // stable non-reversible id (never raw key)
    std::string              issuer;         // "" (api_key) or "trusted-proxy"
    std::vector<std::string> roles;          // resolved role names
    uint32_t                 perms         = 0;
    server_auth_method       method        = AUTH_NONE;
    int64_t                  expires_at    = 0;  // 0 = no expiry; populated by OIDC in PR4
};

// Per-request auth inputs (F005 DTO)
struct server_auth_request {
    std::string method;          // req.method
    std::string raw_path;        // req.path (httplib single-decoded)
    std::string authorization;   // Authorization header (raw, may be empty)
    std::string x_api_key;       // X-Api-Key header (raw, may be empty)
    std::string peer_addr;       // req.remote_addr (TCP peer)
    std::string x_auth_subject;  // X-Auth-Subject (honored only if peer trusted - F007)
    std::string x_auth_roles;    // X-Auth-Roles, comma-separated (honored only if trusted - F007)
    bool        mtls_present = false;   // a verified client cert was presented (F008c)
    std::string mtls_san_uri;           // SAN URI from the client cert ("" if none)
    std::string mtls_san_dns;           // SAN DNS from the client cert ("" if none)
};

// Result of a normalization attempt.
enum server_norm_status {
    NORM_OK,        // out holds the normalized, prefix-stripped path
    NORM_UNMATCHED, // path is outside api_prefix; cannot be a protected API route
    NORM_REJECT,    // malformed/hostile path (NUL, '%', backslash, '.'/'..' segment)
};

// Outcome the middleware turns into an HTTP response.
struct server_auth_decision {
    bool        allowed = false;
    int         status  = 403;                       // used only when !allowed
    error_type  type    = ERROR_TYPE_PERMISSION;     // 401 vs 403 mapping, section 9
    std::string message;
};

struct server_auth {
    // True iff auth enforcement is enabled (policy or api_keys or trusted-proxies configured).
    // Safe to call after init.
    static bool enabled();

    // Load policy (compiled-in default if no --auth-policy-file), build role and
    // key tables, and record api_prefix. Returns false on ANY error (fail closed:
    // the caller MUST abort startup). Idempotent enough to call once in main().
    static bool init(const common_params & params);

    // Normalize a raw httplib req.path (already single-decoded by httplib) against
    // the configured api_prefix. See section 5. Never throws.
    static server_norm_status normalize_path(const std::string & raw_path,
                                              std::string & out_normalized);

    // Required permission for a normalized path + HTTP method. Returns PERM_PUBLIC
    // for public routes. If the (path, method) pair is not in the table, sets
    // matched=false (caller treats as "not a protected API route"). Never throws.
    static uint32_t required_perm(const std::string & normalized_path,
                                  const std::string & method,
                                  bool & matched);

    // Full per-request check: normalize, classify, authenticate, and authorize.
    // Builds server_auth_principal, stores in request-scoped thread_local,
    // and returns the authz decision. Never throws.
    static server_auth_decision authorize_request(const server_auth_request & req);

    // F005: clear the request-scoped principal thread_local. Call at pre_routing
    // entry (PLAN.md 4.2b) to prevent prior request leak on a reused worker thread.
    static void reset_principal();

    // F005: retrieve the principal resolved by authorize_request on THIS thread.
    // Valid ONLY synchronously at server_http_req construction time (get/post/del);
    // handlers MUST read req.principal instead (never call this lazily during
    // streaming, on_complete, or from a gcp async worker).
    static const server_auth_principal & principal_at_construction();

    // Register a dynamic route -> permission mapping (used for gcp compat paths,
    // whose paths are env-derived). Must be called before assert_routes_covered.
    static void register_route(const std::string & method,
                               const std::string & path_pattern,
                               uint32_t perm);

    // True iff the pattern is classified AND every classified method for it is
    // exactly PERM_INFER. Used to confine gcp /predict internal dispatch (S1).
    static bool is_infer_only(const std::string & normalized_path);

    // Method-aware startup assertion (S2): every (method, path) actually registered
    // must have an exact (method, pattern) entry in the table or a dynamic route.
    // Returns false and logs the offending route if any is unclassified. The caller
    // MUST abort startup on false.
    static bool assert_routes_covered(
        const std::vector<std::pair<std::string, std::string>> & registered_routes);

    // Lowercased identity header names (see server_auth_headers above). Used by
    // get_headers (server-http.cpp) to strip these from any header map forwarded
    // downstream (e.g. router mode child requests), so they stay in lockstep
    // with the headers middleware_authz honors.
    static const std::vector<std::string> & identity_headers();

    // F013: mid-stream access-token expiry.
    //
    // stream_deadline() returns the unix time (seconds) at or after which no further SSE
    // chunk may be written for this principal, or 0 meaning "never expires". It returns 0
    // whenever p.expires_at == 0, so API-key, mTLS, trusted-proxy and auth-disabled
    // requests are NEVER cut. Auth-method-agnostic by construction: it keys off
    // expires_at only and never inspects p.method, so any method that populates
    // expires_at (OIDC today, RFC-7662 introspection later) is covered with no change here.
    static int64_t stream_deadline(const server_auth_principal & p);

    // True iff deadline > 0 and the wall clock is at or past it. One time() call, no lock,
    // no allocation; deadline <= 0 always returns false. Called once per SSE chunk.
    static bool stream_expired(int64_t deadline);

    // The SSE chunk written immediately before an expired stream is cut. Default form is
    // "data: {\"error\":...}" used by every stream except Anthropic and Responses;
    // returns a reference to a function-local static built once, so there is no
    // per-chunk cost.
    static const std::string & sse_expired_chunk_oai();

    // F015: Prometheus text for the auth counters, appended to the /metrics body by
    // server_metrics_wrap (server-metrics.h). Returns "" when auth is disabled, so /metrics output
    // is byte-identical to pre-F015 in that mode. Never throws.
    static std::string metrics_prometheus();
};

// F015: Authentication failure reasons (400/401 status codes)
enum server_auth_fail_reason {
    AUTH_FAIL_MALFORMED_PATH,      // normalize_path returned NORM_REJECT (status 400)
    AUTH_FAIL_NO_CREDENTIAL,       // no Authorization and no X-Api-Key presented
    AUTH_FAIL_INVALID_KEY,         // API key presented but did not match
    AUTH_FAIL_MALFORMED,           // JWT failed structurally
    AUTH_FAIL_EXPIRED,             // JWT failed on exp/nbf
    AUTH_FAIL_AUD_MISMATCH,        // JWT failed aud/iss matching
    AUTH_FAIL_INTROSPECT_DENIED,   // RFC-7662 introspection returned active:false
    AUTH_FAIL_MTLS_REJECT,         // mTLS cert presented but no usable SAN
    AUTH_FAIL_UNKNOWN,             // (internal use only: a branch forgot to set t_fail_reason)
    AUTH_FAIL_COUNT                // sentinel for array sizing (includes UNKNOWN)
};

// F015: Authorization denial reasons (403 status code)
enum server_authz_deny_reason {
    AUTHZ_DENY_UNMAPPED_ROLE,      // authenticated but perms==0 (role map misconfiguration)
    AUTHZ_DENY_INSUFFICIENT_PERM,  // authenticated and perms!=0 but insufficient
    AUTHZ_DENY_COUNT               // sentinel for array sizing
};

// F015: Permission index for counters (maps permission bits to array indices)
inline int perm_index(uint32_t perm) {
    switch (perm) {
        case PERM_INFER:        return 0;
        case PERM_READ_STATE:   return 1;
        case PERM_METRICS:      return 2;
        case PERM_ADMIN_STATE:  return 3;
        case PERM_ADMIN_MODELS: return 4;
        case PERM_PROXY:        return 5;
        default:                return -1;
    }
}

// F015: Count of permission indices (excludes PERM_PUBLIC which is never used in authz denials)
static constexpr int PERM_INDEX_COUNT = 6;
