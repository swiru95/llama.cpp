#include "server-auth.h"
#include "server-oidc.h"
#include "common.h"
#include "log.h"
#include "vendor/sha256.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <limits>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <random>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#endif

#include "../vendor/nlohmann/json.hpp"
using json = nlohmann::ordered_json;

// Runtime route table and auth state
namespace {
    struct route_entry_rt {
        std::vector<std::string> path_segments;
        std::string method;
        uint32_t perm;
    };

    struct key_entry {
        uint32_t perms;
        std::string role;
    };

    // F007: CIDR entry for trusted proxies
    struct cidr {
        int      family;       // AF_INET or AF_INET6
        uint8_t  net[16];      // network bytes (4 used for v4, 16 for v6)
        int      bits;         // prefix length
    };

    // Global state
    std::vector<route_entry_rt> g_route_table;
    std::unordered_map<std::string, key_entry> g_key_perms;  // hash -> {perms, role}
    std::string g_api_prefix;
    std::string g_api_prefix_slash;  // precomputed g_api_prefix + "/" (avoid per-request concatenation)
    bool g_auth_enabled = false;  // true if policy or api_keys configured
    uint32_t g_default_perms = 0;  // default permissions for unmapped keys (or 0 for deny)

    // F005: request-scoped principal (cleared on middleware entry)
    thread_local server_auth_principal t_principal;

    // F015: current request's authentication failure reason (for metrics); defaults to UNKNOWN
    // so a forgotten branch is visible rather than inflating the busiest bucket
    thread_local server_auth_fail_reason t_fail_reason = AUTH_FAIL_UNKNOWN;

    // F015: method that was actually attempted when t_fail_reason was set (for the
    // auth_method metrics label). p.method stays AUTH_NONE for a failed/anonymous
    // principal by design (audit_emit and other readers rely on that), so this is a
    // separate metrics-only signal, reset alongside t_fail_reason.
    thread_local server_auth_method t_attempted_method = AUTH_NONE;

    // F006/F007: persistent role map and audit state
    std::unordered_map<std::string, uint32_t> g_role_perms;   // role name -> perms
    std::ofstream g_audit_ofs;                                // audit file stream
    std::mutex    g_audit_mtx;                                // mutex for audit writes
    bool          g_audit_enabled = false;                    // audit is configured and open
    std::string   g_audit_salt;                               // salt for subject hashing

    // F015: Prometheus counters. Indexed by enum, never by string key, so cardinality is
    // compile-time bounded. Relaxed ordering: these are observability counters, never read
    // to make a decision.
    std::atomic<uint64_t> g_authn_fail[AUTH_METHOD_COUNT][AUTH_FAIL_COUNT];
    std::atomic<uint64_t> g_authz_deny[AUTH_METHOD_COUNT][PERM_INDEX_COUNT][AUTHZ_DENY_COUNT];

    // F007: trusted proxies
    std::vector<cidr> g_trusted_proxies;                       // trusted peer CIDRs

    // F008d: mTLS role mapping
    struct mtls_map_entry {
        std::string pattern;
        bool wildcard;
        size_t prefix_len;  // length of prefix (pattern minus '*'), 0 if not wildcard
        uint32_t perms;
        std::string role;
    };
    std::string g_mtls_identity_source = "san_uri";            // "san_uri" | "san_dns"
    std::vector<mtls_map_entry> g_mtls_role_map;               // built in init

    // F009d: OIDC role mapping
    bool g_oidc_enabled = false;                               // set true after server_oidc::init succeeds
    std::string g_oidc_roles_claim = "realm_access.roles";     // dot-separated claim path
    std::vector<std::string> g_oidc_roles_claim_segs;          // pre-split segments (avoid per-request parse)
    std::unordered_map<std::string, uint32_t> g_oidc_role_map; // claim-role -> perms
    bool g_oidc_require_typ = false;                           // from policy oidc.require_at_jwt_typ

    // F010b: OIDC introspection
    bool g_introspect_enabled = false;                         // set true after server_oidc::init succeeds

    // F011: public endpoints (paths that require no auth)
    std::unordered_set<std::string> g_public_endpoints;        // normalized paths

    // F013: grace added to principal.expires_at before a stream is cut. Equals the OIDC
    // clock skew so the cut uses the same leeway that accepted the token.
    int64_t g_stream_expiry_grace_sec = 60;
}

// ============================================================================
// F001: Path normalization
// ============================================================================

server_norm_status server_auth::normalize_path(const std::string & raw_path,
                                                std::string & out_normalized) {
    // httplib already single-decodes req.path at parse time (httplib.cpp:7591).
    // We do NOT decode again. We inspect the already-once-decoded path and reject
    // any residual malformed sequences.

    // Step 1: Handle api_prefix (if configured). When g_api_prefix is empty (default),
    // operate on raw_path directly to avoid a full copy.
    const std::string * work_ptr = &raw_path;
    std::string work_copy;

    if (!g_api_prefix.empty()) {
        if (raw_path == g_api_prefix) {
            work_copy = "/";
            work_ptr = &work_copy;
        } else if (raw_path.rfind(g_api_prefix_slash, 0) == 0) {  // use precomputed g_api_prefix_slash
            work_copy = raw_path.substr(g_api_prefix.size());
            work_ptr = &work_copy;
        } else {
            return NORM_UNMATCHED;
        }
    }

    const std::string & work = *work_ptr;

    // Step 2: Reject non-canonical paths. Scan for:
    // - NUL byte, literal '%', backslash
    // - empty segment (consecutive '/'), trailing '/' (except root "/")
    // - whole '.' or '..' segment
    // Single combined pass through the path.

    // Check for trailing slash (except root "/")
    if (work.size() > 1 && work.back() == '/') {
        return NORM_REJECT;
    }

    // Check for empty path or missing leading slash
    if (work.empty() || work[0] != '/') {
        return NORM_REJECT;
    }

    // Combined scan: invalid chars and segment validation in one pass
    size_t prev = 0;
    for (size_t i = 0; i <= work.size(); ++i) {
        if (i == work.size() || work[i] == '/') {
            if (i == 0) {
                // Leading slash; skip it, don't treat as a segment
                prev = i + 1;
                continue;
            }
            size_t seg_len = i - prev;
            // Empty segment (consecutive '/', e.g., //slots or /slots//0)
            if (seg_len == 0) {
                return NORM_REJECT;
            }
            // Whole '.' or '..' segment (checked by length and first byte(s))
            if (seg_len == 1 && work[prev] == '.') {
                return NORM_REJECT;
            }
            if (seg_len == 2 && work[prev] == '.' && work[prev + 1] == '.') {
                return NORM_REJECT;
            }
            prev = i + 1;
        } else if (work[i] == '\0' || work[i] == '%' || work[i] == '\\') {
            // NUL, '%', or backslash
            return NORM_REJECT;
        }
    }

    // Step 3: Return normalized (unchanged from input in F001, since no repair)
    if (work_ptr == &work_copy) {
        out_normalized = work_copy;
    } else {
        out_normalized = raw_path;
    }
    return NORM_OK;
}

// ============================================================================
// F002 + F003: Permission model, policy, and route table
// ============================================================================

// Static route table (method, pattern, permission)
struct auth_route {
    const char * method;
    const char * pattern;
    uint32_t perm;
};

static const auth_route k_routes[] = {
    // health (public)
    { "GET",  "/health",                        PERM_PUBLIC },
    { "GET",  "/v1/health",                     PERM_PUBLIC },

    // public (deferred: /models stays public in PR1, matching today)
    { "GET",  "/models",                        PERM_PUBLIC },
    { "GET",  "/v1/models",                     PERM_PUBLIC },

    // read state
    { "GET",  "/props",                         PERM_READ_STATE },
    { "GET",  "/models/sse",                    PERM_READ_STATE },
    { "GET",  "/lora-adapters",                 PERM_READ_STATE },
    { "GET",  "/slots",                         PERM_READ_STATE },

    // metrics
    { "GET",  "/metrics",                       PERM_METRICS },

    // admin state
    { "POST", "/props",                         PERM_ADMIN_STATE },
    { "POST", "/slots/:id_slot",                PERM_ADMIN_STATE },
    { "POST", "/lora-adapters",                 PERM_ADMIN_STATE },

    // admin models (router mode)
    { "POST", "/models",                        PERM_ADMIN_MODELS },
    { "DELETE", "/models",                      PERM_ADMIN_MODELS },
    { "POST", "/models/load",                   PERM_ADMIN_MODELS },
    { "POST", "/models/unload",                 PERM_ADMIN_MODELS },

    // inference
    { "POST", "/completion",                    PERM_INFER },
    { "POST", "/completions",                   PERM_INFER },
    { "POST", "/v1/completions",                PERM_INFER },
    { "POST", "/chat/completions",              PERM_INFER },
    { "POST", "/v1/chat/completions",           PERM_INFER },
    { "POST", "/v1/chat/completions/control",   PERM_INFER },
    { "POST", "/v1/responses",                  PERM_INFER },
    { "POST", "/responses",                     PERM_INFER },
    { "POST", "/v1/audio/transcriptions",       PERM_INFER },
    { "POST", "/audio/transcriptions",          PERM_INFER },
    { "POST", "/v1/messages",                   PERM_INFER },
    { "POST", "/v1/messages/count_tokens",      PERM_INFER },
    { "POST", "/infill",                        PERM_INFER },
    { "POST", "/embedding",                     PERM_INFER },
    { "POST", "/embeddings",                    PERM_INFER },
    { "POST", "/v1/embeddings",                 PERM_INFER },
    { "POST", "/rerank",                        PERM_INFER },
    { "POST", "/reranking",                     PERM_INFER },
    { "POST", "/v1/rerank",                     PERM_INFER },
    { "POST", "/v1/reranking",                  PERM_INFER },
    { "POST", "/tokenize",                      PERM_INFER },
    { "POST", "/detokenize",                    PERM_INFER },
    { "POST", "/apply-template",                PERM_INFER },
    { "POST", "/chat/completions/input_tokens",    PERM_INFER },
    { "POST", "/v1/chat/completions/input_tokens", PERM_INFER },
    { "POST", "/responses/input_tokens",           PERM_INFER },
    { "POST", "/v1/responses/input_tokens",        PERM_INFER },

    // resumable streaming
    { "GET",    "/v1/stream",                   PERM_INFER },
    { "POST",   "/v1/streams/lookup",           PERM_INFER },
    { "DELETE", "/v1/stream",                   PERM_INFER },

    // proxy / agent tools
    { "GET",  "/cors-proxy",                    PERM_PROXY },
    { "POST", "/cors-proxy",                    PERM_PROXY },
    { "GET",  "/tools",                         PERM_PROXY },
    { "POST", "/tools",                         PERM_PROXY },
};

static const size_t k_routes_count = sizeof(k_routes) / sizeof(k_routes[0]);

// Split path by '/' - using find/substr for efficiency (no stringstream per call).
// Edge cases (must match std::getline behavior for backward compatibility):
// - split_path("/props") yields {"", "props"} (leading empty from leading slash)
// - split_path("/") yields {""} (single empty, NOT two; trailing getline fails on EOF)
// - split_path("") yields {} (empty vector, no leading slash = no segments)
static std::vector<std::string> split_path(const std::string & path) {
    std::vector<std::string> segments;
    if (path.empty()) {
        return segments;  // empty path -> empty vector
    }
    segments.reserve(path.size() / 2);  // typical estimate
    size_t start = 0;
    for (size_t i = 0; i <= path.size(); ++i) {
        if (i == path.size() || path[i] == '/') {
            // Only push if we found a '/' (i < size) or if there's content after last delim
            if (i < path.size() || start < path.size()) {
                segments.push_back(path.substr(start, i - start));
            }
            start = i + 1;
            if (i == path.size()) break;  // EOF: stop here
        }
    }
    return segments;
}

// Check if pattern matches normalized path
static bool path_matches(const std::vector<std::string> & pattern_segs,
                        const std::vector<std::string> & path_segs) {
    if (pattern_segs.size() != path_segs.size()) {
        return false;
    }
    for (size_t i = 0; i < pattern_segs.size(); ++i) {
        const auto & pat = pattern_segs[i];
        if (!pat.empty() && pat[0] == ':') {
            // Parameter segment matches any non-empty segment
            if (path_segs[i].empty()) {
                return false;
            }
        } else {
            // Literal match required
            if (pat != path_segs[i]) {
                return false;
            }
        }
    }
    return true;
}

// F007: Strip IPv4-mapped prefix from IPv6 addresses (e.g., ::ffff:127.0.0.1 -> 127.0.0.1).
// Avoids string construction for the prefix check.
static std::string strip_v4mapped_prefix(const std::string & addr) {
    if (addr.size() > 7 && addr.compare(0, 7, "::ffff:") == 0) {
        // Try to parse the remainder as IPv4 to confirm it's a valid v4-mapped address
        uint8_t buf[4];
        const char * candidate = addr.c_str() + 7;
        if (inet_pton(AF_INET, candidate, buf) == 1) {
            return addr.substr(7);
        }
    }
    return addr;
}

// F007: Prefix match for CIDR (full and partial byte match with bit mask)
static bool prefix_match(const uint8_t * a, const uint8_t * b, int bits) {
    int full_bytes = bits / 8;
    int remaining_bits = bits % 8;

    if (std::memcmp(a, b, full_bytes) != 0) {
        return false;
    }
    if (remaining_bits > 0) {
        uint8_t mask = 0xFF << (8 - remaining_bits);
        if ((a[full_bytes] & mask) != (b[full_bytes] & mask)) {
            return false;
        }
    }
    return true;
}

// F007: Check if a peer address is in a trusted CIDR
static bool peer_is_trusted(const std::string & peer_addr) {
    if (g_trusted_proxies.empty()) {
        return false;  // no config -> never trust
    }

    // Normalize IPv4-mapped peer
    std::string normalized = strip_v4mapped_prefix(peer_addr);

    // Try to parse as IPv4
    uint8_t pbytes[16] = {0};
    int pfamily;
    if (inet_pton(AF_INET, normalized.c_str(), pbytes) == 1) {
        pfamily = AF_INET;
    } else if (inet_pton(AF_INET6, normalized.c_str(), pbytes) == 1) {
        pfamily = AF_INET6;
    } else {
        return false;  // unparseable -> not trusted
    }

    // Check against each trusted CIDR
    for (const auto & c : g_trusted_proxies) {
        if (c.family == pfamily && prefix_match(pbytes, c.net, c.bits)) {
            return true;
        }
    }
    return false;
}

// F007: Split comma-separated string into tokens (trim whitespace, drop empty).
// Avoids stringstream per call.
static std::vector<std::string> split_csv(const std::string & s) {
    std::vector<std::string> result;
    result.reserve(10);  // typical estimate: ~10 tokens per header
    size_t start = 0;
    for (size_t i = 0; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == ',') {
            // Extract token [start, i)
            std::string token = s.substr(start, i - start);
            // Trim leading/trailing whitespace
            size_t tok_start = token.find_first_not_of(" \t\r\n");
            size_t tok_end = token.find_last_not_of(" \t\r\n");
            if (tok_start != std::string::npos) {
                result.push_back(token.substr(tok_start, tok_end - tok_start + 1));
            }
            start = i + 1;
            if (i == s.size()) break;
        }
    }
    return result;
}

// Parse permission name string to bitmask
static uint32_t perm_from_string(const std::string & name) {
    if (name == "INFER") return PERM_INFER;
    if (name == "READ_STATE") return PERM_READ_STATE;
    if (name == "METRICS") return PERM_METRICS;
    if (name == "ADMIN_STATE") return PERM_ADMIN_STATE;
    if (name == "ADMIN_MODELS") return PERM_ADMIN_MODELS;
    if (name == "PROXY") return PERM_PROXY;
    return 0;  // unknown
}

// F006: Convert permission bitmask to name (single bit only; "" if zero/multiple)
static const char * perm_to_string(uint32_t perm) {
    switch (perm) {
        case PERM_PUBLIC:       return "PUBLIC";
        case PERM_INFER:        return "INFER";
        case PERM_READ_STATE:   return "READ_STATE";
        case PERM_METRICS:      return "METRICS";
        case PERM_ADMIN_STATE:  return "ADMIN_STATE";
        case PERM_ADMIN_MODELS: return "ADMIN_MODELS";
        case PERM_PROXY:        return "PROXY";
        default:                return "";
    }
}

// F006: Convert auth method to string
static const char * auth_method_to_string(server_auth_method method) {
    switch (method) {
        case AUTH_NONE:           return "none";
        case AUTH_API_KEY:        return "api_key";
        case AUTH_TRUSTED_PROXY:  return "trusted_proxy";
        case AUTH_MTLS:           return "mtls";
        case AUTH_OIDC:           return "oidc";
        default:                  return "unknown";
    }
}

// F015: Map OIDC error string to auth failure reason
static server_auth_fail_reason oidc_error_to_fail_reason(const std::string & error) {
    // Errors from OIDC validation: see server-oidc.cpp
    if (error == "expired" || error.find("nbf") != std::string::npos) {
        return AUTH_FAIL_EXPIRED;
    } else if (error == "aud mismatch" || error == "iss mismatch") {
        return AUTH_FAIL_AUD_MISMATCH;
    } else {
        // Covers: malformed, no alg, no kid, alg not allowed, unknown kid, typ mismatch, no sub, no exp, verify failed
        return AUTH_FAIL_MALFORMED;
    }
}

// F015: Convert auth failure reason to string (for Prometheus labels)
static const char * auth_fail_reason_to_string(server_auth_fail_reason reason) {
    switch (reason) {
        case AUTH_FAIL_MALFORMED_PATH:  return "malformed_path";
        case AUTH_FAIL_NO_CREDENTIAL:   return "no_credential";
        case AUTH_FAIL_INVALID_KEY:     return "invalid_key";
        case AUTH_FAIL_MALFORMED:       return "malformed";
        case AUTH_FAIL_EXPIRED:         return "expired";
        case AUTH_FAIL_AUD_MISMATCH:    return "aud_mismatch";
        case AUTH_FAIL_INTROSPECT_DENIED: return "introspect_denied";
        case AUTH_FAIL_MTLS_REJECT:     return "mtls_reject";
        default:                        return "unknown";
    }
}

// F015: Convert authz deny reason to string (for Prometheus labels)
static const char * authz_deny_reason_to_string(server_authz_deny_reason reason) {
    switch (reason) {
        case AUTHZ_DENY_UNMAPPED_ROLE:     return "unmapped_role";
        case AUTHZ_DENY_INSUFFICIENT_PERM: return "insufficient_perm";
        default:                           return "unknown";
    }
}

// F006: ISO-8601 UTC timestamp
static std::string iso8601_utc_now() {
    time_t t = std::time(nullptr);
#ifdef _WIN32
    struct tm tm_buf;
    if (gmtime_s(&tm_buf, &t) != 0) return "";
#else
    struct tm tm_buf;
    if (gmtime_r(&t, &tm_buf) == nullptr) return "";
#endif
    char buf[32];
    if (std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf) == 0) {
        return "";
    }
    return std::string(buf);
}

// F006: Audit salt (per-process random or from LLAMA_AUTH_AUDIT_SALT env)
static std::string audit_salt() {
    const char * env = std::getenv("LLAMA_AUTH_AUDIT_SALT");
    if (env && env[0] != '\0') {
        return std::string(env);
    }
    // Generate per-process random salt (12 hex chars)
    static thread_local std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> dist(0, 15);
    std::string salt;
    for (int i = 0; i < 12; ++i) {
        int val = dist(rng);
        salt += (val < 10) ? ('0' + val) : ('a' + (val - 10));
    }
    return salt;
}

// F006: Generate a request ID
static std::string request_id_generate() {
    static thread_local std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> dist(0, 35);
    const char * chars = "0123456789abcdefghijklmnopqrstuvwxyz";
    std::string id = "req-";
    for (int i = 0; i < 12; ++i) {
        id += chars[dist(rng)];
    }
    return id;
}

// F006: Emit one audit line (thread-safe, fail-open). A raw request path can
// contain byte sequences that are not valid UTF-8 (e.g. an overlong percent-
// decoded sequence like %C0%80); json::dump() throws on those by default.
// Audit must never fail or alter the request outcome, so serialization goes
// through safe_json_to_str (server-common.h, replace-on-invalid-UTF-8) and
// the whole call is defensively wrapped.
static void audit_emit(const server_auth_request & r, const std::string & norm_path,
                       uint32_t need, bool matched, const server_auth_principal & p,
                       const server_auth_decision & d) {
    if (!g_audit_enabled) return;

    // Lazy request ID generation: only when audit is enabled
    std::string request_id = request_id_generate();

    try {
        // Build JSON line
        json line = json::object();
        line["ts"] = iso8601_utc_now();
        if (p.authenticated) {
            // Salted hash of subject (never the raw value)
            line["subject_hash"] = sha256_hex(p.subject + g_audit_salt);
        } else {
            line["subject_hash"] = "anonymous";
        }
        line["method"] = r.method;
        line["path"] = norm_path;
        line["decision"] = d.allowed ? "allow" : "deny";
        line["required_perm"] = matched ? perm_to_string(need) : "";
        line["auth_method"] = auth_method_to_string(p.method);
        line["peer_ip"] = r.peer_addr;
        line["request_id"] = request_id;

        const std::string serialized = safe_json_to_str(line);

        // Append to file (mutex-guarded, no per-line flush)
        std::lock_guard<std::mutex> lk(g_audit_mtx);
        if (g_audit_ofs.is_open()) {
            g_audit_ofs << serialized << "\n";
            // No flush() - rely on ofstream buffering, flush at process exit
        }
    } catch (...) {
        // Fail-open: audit is observability, never a gate. Drop the line.
    }
}

// Load policy from JSON file
static json load_policy_json(const std::string & path) {
    std::ifstream ifs(path);
    if (!ifs.is_open()) {
        SRV_ERR("failed to open policy file: %s\n", path.c_str());
        return nullptr;
    }
    try {
        json policy;
        ifs >> policy;
        return policy;
    } catch (const std::exception & e) {
        SRV_ERR("failed to parse policy file: %s\n", e.what());
        return nullptr;
    }
}

bool server_auth::enabled() {
    return g_auth_enabled;
}

// Split a dot-separated claim path into segments (e.g., "realm_access.roles" -> {"realm_access", "roles"})
static std::vector<std::string> split_oidc_claim_path(const std::string & path) {
    std::vector<std::string> segments;
    size_t start = 0;
    for (size_t i = 0; i <= path.size(); ++i) {
        if (i == path.size() || path[i] == '.') {
            if (i > start) {
                segments.push_back(path.substr(start, i - start));
            }
            start = i + 1;
            if (i == path.size()) break;
        }
    }
    return segments;
}

bool server_auth::init(const common_params & params) {
    g_api_prefix = params.api_prefix;
    g_api_prefix_slash = g_api_prefix.empty() ? "" : (g_api_prefix + "/");  // precomputed for normalize_path
    // F013: same leeway that jwt-cpp applied to exp at validation time
    g_stream_expiry_grace_sec = std::min<int64_t>(300, std::max<int64_t>(0, params.oidc_clock_skew));
    g_route_table.clear();
    g_key_perms.clear();
    g_role_perms.clear();
    g_auth_enabled = false;
    g_default_perms = 0;
    g_audit_enabled = false;
    g_public_endpoints.clear();  // F011
    g_mtls_identity_source = "san_uri";  // F008d
    g_mtls_role_map.clear();  // F008d
    g_oidc_enabled = false;  // F009d
    g_oidc_roles_claim = "realm_access.roles";  // F009d
    g_oidc_roles_claim_segs = split_oidc_claim_path(g_oidc_roles_claim);  // pre-split for extract_oidc_roles
    g_oidc_role_map.clear();  // F009d
    g_oidc_require_typ = false;  // F009d

    // Build runtime route table from static table
    for (size_t i = 0; i < k_routes_count; ++i) {
        route_entry_rt rt;
        rt.method = k_routes[i].method;
        rt.perm = k_routes[i].perm;
        rt.path_segments = split_path(k_routes[i].pattern);
        g_route_table.push_back(rt);
    }

    // F006: Open audit file if requested (independent of g_auth_enabled)
    if (!params.auth_audit_log.empty()) {
        g_audit_ofs.open(params.auth_audit_log, std::ios::out | std::ios::app);
        if (!g_audit_ofs.is_open()) {
            SRV_ERR("failed to open audit log: %s\n", params.auth_audit_log.c_str());
            return false;  // fail closed
        }
        g_audit_enabled = true;
        g_audit_salt = audit_salt();
        SRV_INF("audit log opened: %s\n", params.auth_audit_log.c_str());
    }

    // Determine operating mode and load policy
    json policy;
    bool has_policy_file = !params.auth_policy_file.empty();
    bool has_policy_inline = !params.auth_policy_inline.empty();  // F012c

    // F012c: Fail closed if both file and inline are set (ambiguous)
    if (has_policy_file && has_policy_inline) {
        SRV_ERR("%s", "cannot set both --auth-policy-file and inline auth_policy in config\n");
        return false;
    }

    bool has_policy = has_policy_file || has_policy_inline;  // F012c
    bool has_api_keys = !params.api_keys.empty();

    // F007: Parse and validate trusted proxies (before early returns)
    bool has_trusted_proxies = !params.auth_trusted_proxies.empty();

    // F008d: Detect if mTLS is enabled
    bool has_mtls = (params.mtls_required == "optional" || params.mtls_required == "required");

    // F009d: Detect if OIDC is enabled
    bool has_oidc = server_oidc::configured(params);

    // F010b: Detect if introspection is enabled
    bool has_introspect = server_oidc::introspection_configured(params);

    g_trusted_proxies.clear();
    if (has_trusted_proxies) {
        std::vector<std::string> cidrs = split_csv(params.auth_trusted_proxies);
        for (const auto & cidr_str : cidrs) {
            // Split on the last '/'
            size_t slash = cidr_str.rfind('/');
            std::string addr_part = (slash == std::string::npos) ? cidr_str : cidr_str.substr(0, slash);
            std::string bits_part = (slash == std::string::npos) ? "" : cidr_str.substr(slash + 1);

            // Parse prefix bits (if provided); reject explicit /0 (all-peers)
            int bits = 0;
            if (!bits_part.empty()) {
                try {
                    size_t pos = 0;
                    bits = std::stoi(bits_part, &pos);
                    if (pos != bits_part.size()) {
                        // trailing garbage after the number, e.g. "/8x" or "/24junk"
                        SRV_ERR("invalid --auth-trusted-proxies entry: %s\n", cidr_str.c_str());
                        return false;
                    }
                } catch (...) {
                    SRV_ERR("invalid --auth-trusted-proxies entry: %s\n", cidr_str.c_str());
                    return false;
                }
                // Reject explicit /0 (all-peers footgun)
                if (bits <= 0) {
                    SRV_ERR("invalid --auth-trusted-proxies entry '%s' trusts all peers; "
                        "specify the proxy's own address\n", cidr_str.c_str());
                    return false;
                }
            }

            // Try IPv4
            uint8_t buf[16] = {0};
            int family = 0;
            if (inet_pton(AF_INET, addr_part.c_str(), buf) == 1) {
                family = AF_INET;
                if (bits == 0) {
                    bits = 32;  // default: host-specific /32
                }
                if (bits > 32) {
                    SRV_ERR("invalid --auth-trusted-proxies entry '%s': prefix too large for IPv4\n",
                        cidr_str.c_str());
                    return false;
                }
            } else if (inet_pton(AF_INET6, addr_part.c_str(), buf) == 1) {
                // IPv6
                family = AF_INET6;
                if (bits == 0) {
                    bits = 128;  // default: host-specific /128
                }
                if (bits > 128) {
                    SRV_ERR("invalid --auth-trusted-proxies entry '%s': prefix too large for IPv6\n",
                        cidr_str.c_str());
                    return false;
                }
            } else {
                SRV_ERR("invalid --auth-trusted-proxies entry: %s\n", cidr_str.c_str());
                return false;
            }

            cidr c;
            c.family = family;
            c.bits = bits;
            std::memcpy(c.net, buf, 16);
            g_trusted_proxies.push_back(c);
        }
    }

    if (has_policy) {  // F012c: load from file OR inline
        if (has_policy_file) {
            policy = load_policy_json(params.auth_policy_file);
            if (policy.is_null()) {
                return false;
            }
        } else {  // has_policy_inline
            try {
                policy = json::parse(params.auth_policy_inline);
            } catch (const std::exception & e) {
                SRV_ERR("failed to parse inline auth_policy: %s\n", e.what());
                return false;
            }
        }

        if (!policy.is_object()) {
            SRV_ERR("%s", "policy must contain a JSON object\n");
            return false;
        }
        // F011: Parse public_endpoints (fail-closed on malformed, warn on unknown entries)
        if (policy.contains("public_endpoints")) {
            const auto & pe = policy["public_endpoints"];
            if (!pe.is_array()) {
                SRV_ERR("%s", "public_endpoints must be a JSON array\n");
                return false;
            }
            for (const auto & entry : pe) {
                if (!entry.is_string()) {
                    SRV_ERR("%s", "public_endpoints array entries must be strings\n");
                    return false;
                }
                const std::string & path = entry.get<std::string>();
                // Validate the path is well-formed (normalized form)
                std::string normalized;
                server_norm_status norm_st = normalize_path(path, normalized);
                if (norm_st != NORM_OK) {
                    SRV_ERR("public_endpoints entry '%s' is not a valid normalized path\n",
                            path.c_str());
                    return false;
                }
                // Check if this path matches any route in the table (any method)
                auto path_segs = split_path(normalized);
                bool found = false;
                for (const auto & route : g_route_table) {
                    if (path_matches(route.path_segments, path_segs)) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    SRV_WRN("public_endpoints entry '%s' does not match any registered route (ignored)\n",
                            path.c_str());
                } else {
                    g_public_endpoints.insert(normalized);
                }
            }
        }
    } else if (!has_api_keys && !has_trusted_proxies && !has_mtls && !has_oidc && !has_introspect) {
        // 4b: Auth-disabled mode: no policy, no keys, no proxies, no mTLS, no OIDC, no introspection
        g_auth_enabled = false;
        return true;
    } else {
        // Legacy super-user mode (no policy, but keys present) or trusted-proxy mode (keys may be absent) or mTLS mode
        if (has_api_keys) {
            g_default_perms = 0;  // unmapped keys denied
        }
    }

    // Auth is enabled if we reach here (policy, legacy keys, trusted proxies, mTLS, OIDC, or introspection)
    // NOTE: authorize_request depends on this OR coupling to skip expensive credential
    // resolution when auth is disabled. If adding a new credential source here, also
    // ensure resolve_principal is unreachable when that source alone is true and all
    // others are false.
    g_auth_enabled = has_policy || has_api_keys || has_trusted_proxies || has_mtls || has_oidc || has_introspect;

    // Load or use default roles
    json roles;
    if (!policy.is_null() && policy.contains("roles")) {
        // F012c: roles key present but malformed (e.g. null) must fail closed,
        // not silently fall back to the compiled-in default roles.
        if (!policy["roles"].is_object()) {
            SRV_ERR("%s", "policy roles must be a JSON object\n");
            return false;
        }
        roles = policy["roles"];
    } else {
        // Compiled-in default roles
        roles = json::object();
        roles["admin"] = json::array({
            "INFER", "READ_STATE", "METRICS", "ADMIN_STATE", "ADMIN_MODELS"
        });
        roles["user"] = json::array({"INFER"});
    }

    // Validate and build role -> perms map
    std::unordered_map<std::string, uint32_t> role_perms;
    for (auto & [role_name, perm_array] : roles.items()) {
        if (!perm_array.is_array()) {
            SRV_ERR("role '%s' permissions must be an array\n", role_name.c_str());
            return false;
        }
        uint32_t perms = 0;
        for (const auto & perm_name : perm_array) {
            if (!perm_name.is_string()) {
                SRV_ERR("permission must be a string in role '%s'\n", role_name.c_str());
                return false;
            }
            uint32_t p = perm_from_string(perm_name.get<std::string>());
            if (p == 0) {
                SRV_ERR("unknown permission '%s' in role '%s'\n",
                        perm_name.get<std::string>().c_str(), role_name.c_str());
                return false;
            }
            perms |= p;
        }
        role_perms[role_name] = perms;
    }

    // F006/F007: Persist role map for audit and trusted-proxy role mapping
    g_role_perms = role_perms;

    // F008d: Parse mTLS policy section (after g_role_perms is persisted)
    if (!policy.is_null() && policy.contains("mtls")) {
        const auto & mtls_obj = policy["mtls"];
        if (!mtls_obj.is_object()) {
            SRV_ERR("%s", "policy mtls section must be a JSON object\n");
            return false;
        }

        // Parse identity_source
        if (mtls_obj.contains("identity_source")) {
            const auto & src = mtls_obj["identity_source"];
            if (!src.is_string()) {
                SRV_ERR("%s", "mtls.identity_source must be a string\n");
                return false;
            }
            std::string src_str = src.get<std::string>();
            if (src_str != "san_uri" && src_str != "san_dns") {
                SRV_ERR("mtls.identity_source must be 'san_uri' or 'san_dns', got '%s'\n", src_str.c_str());
                return false;
            }
            g_mtls_identity_source = src_str;
        }

        // Parse role_map
        if (mtls_obj.contains("role_map")) {
            const auto & role_map = mtls_obj["role_map"];
            if (!role_map.is_object()) {
                SRV_ERR("%s", "mtls.role_map must be a JSON object\n");
                return false;
            }

            for (auto & [pattern, role_name_val] : role_map.items()) {
                if (!role_name_val.is_string()) {
                    SRV_ERR("mtls.role_map value for pattern '%s' must be a string\n", pattern.c_str());
                    return false;
                }
                std::string role_name = role_name_val.get<std::string>();

                // Validate role exists
                if (role_perms.find(role_name) == role_perms.end()) {
                    SRV_ERR("mtls.role_map references unknown role '%s'\n", role_name.c_str());
                    return false;
                }

                // Detect wildcard: a single trailing '*' is valid, '*' elsewhere is not
                bool is_wildcard = false;
                if (!pattern.empty() && pattern.back() == '*') {
                    // Check if there's only one '*' at the end
                    if (pattern.find('*') == pattern.size() - 1) {
                        is_wildcard = true;
                        // A bare '*' (empty prefix) is not a catch-all: mtls_lookup
                        // never selects a zero-length prefix, so it would silently
                        // match nothing. Reject it rather than deny-all confusingly.
                        if (pattern.size() == 1) {
                            SRV_ERR("%s", "mtls.role_map pattern '*' is not a catch-all; "
                                    "use an explicit prefix like 'spiffe://corp/*'\n");
                            return false;
                        }
                    } else {
                        SRV_ERR("mtls.role_map pattern '%s' has '*' in the middle; only trailing '*' is allowed\n",
                                pattern.c_str());
                        return false;
                    }
                } else if (pattern.find('*') != std::string::npos) {
                    // '*' is present but not at the end
                    SRV_ERR("mtls.role_map pattern '%s' has '*' in the middle; only trailing '*' is allowed\n",
                            pattern.c_str());
                    return false;
                }

                mtls_map_entry entry;
                entry.pattern = pattern;
                entry.wildcard = is_wildcard;
                entry.prefix_len = is_wildcard ? (pattern.size() - 1) : 0;
                entry.perms = role_perms[role_name];
                entry.role = role_name;
                g_mtls_role_map.push_back(entry);
            }
        }
    }

    // F009d: Parse OIDC policy section (after g_role_perms is persisted)
    g_oidc_roles_claim = "realm_access.roles";  // reset to default
    g_oidc_roles_claim_segs = split_oidc_claim_path(g_oidc_roles_claim);
    g_oidc_role_map.clear();
    g_oidc_require_typ = false;
    if (!policy.is_null() && policy.contains("oidc")) {
        const auto & oidc_obj = policy["oidc"];
        if (!oidc_obj.is_object()) {
            SRV_ERR("%s", "policy oidc section must be a JSON object\n");
            return false;
        }

        // Parse roles_claim (optional, default provided above)
        if (oidc_obj.contains("roles_claim")) {
            const auto & rc = oidc_obj["roles_claim"];
            if (!rc.is_string()) {
                SRV_ERR("%s", "oidc.roles_claim must be a string\n");
                return false;
            }
            g_oidc_roles_claim = rc.get<std::string>();
            g_oidc_roles_claim_segs = split_oidc_claim_path(g_oidc_roles_claim);
        }

        // Parse require_at_jwt_typ (optional, default false)
        if (oidc_obj.contains("require_at_jwt_typ")) {
            const auto & req_typ = oidc_obj["require_at_jwt_typ"];
            if (!req_typ.is_boolean()) {
                SRV_ERR("%s", "oidc.require_at_jwt_typ must be a boolean\n");
                return false;
            }
            g_oidc_require_typ = req_typ.get<bool>();
        }

        // Parse role_map (optional, but recommended when OIDC is used)
        if (oidc_obj.contains("role_map")) {
            const auto & role_map = oidc_obj["role_map"];
            if (!role_map.is_object()) {
                SRV_ERR("%s", "oidc.role_map must be a JSON object\n");
                return false;
            }

            for (auto & [claim_role, local_role_val] : role_map.items()) {
                if (!local_role_val.is_string()) {
                    SRV_ERR("oidc.role_map value for claim role '%s' must be a string\n", claim_role.c_str());
                    return false;
                }
                std::string local_role = local_role_val.get<std::string>();

                // Validate role exists
                if (role_perms.find(local_role) == role_perms.end()) {
                    SRV_ERR("oidc.role_map references unknown role '%s'\n", local_role.c_str());
                    return false;
                }

                g_oidc_role_map[claim_role] = role_perms[local_role];
            }
        }
    }

    // Load default_role
    std::string default_role;
    if (!policy.is_null() && policy.contains("default_role")) {
        const auto & dr = policy["default_role"];
        if (!dr.is_null()) {
            if (!dr.is_string()) {
                SRV_ERR("%s", "default_role must be a string or null");
                return false;
            }
            default_role = dr.get<std::string>();
            if (role_perms.find(default_role) == role_perms.end()) {
                SRV_ERR("default_role '%s' not found in roles\n", default_role.c_str());
                return false;
            }
            g_default_perms = role_perms[default_role];
        }
    }

    // Build key table. Mode is selected on whether a policy (file or inline) was provided,  // F012c
    // NOT on whether the policy happens to contain an api_keys object: when a
    // policy is present it is the single source of truth for valid keys, so a
    // policy that omits api_keys means "no keys" (not a fallback to legacy).
    if (has_policy) {  // F012c: file OR inline
        // RBAC mode: load keys from policy (missing/non-object api_keys = empty set)
        if (policy.contains("api_keys") && policy["api_keys"].is_object()) {
            const auto & api_keys = policy["api_keys"];
            for (auto & [hash, role_name] : api_keys.items()) {
                if (!role_name.is_string()) {
                    SRV_ERR("%s", "api_keys value must be a string (role name)");
                    return false;
                }
                std::string role_str = role_name.get<std::string>();
                if (role_perms.find(role_str) == role_perms.end()) {
                    SRV_ERR("role '%s' not found in api_keys\n", role_str.c_str());
                    return false;
                }
                std::string hash_lc = hash;
                std::transform(hash_lc.begin(), hash_lc.end(), hash_lc.begin(),
                               [](unsigned char c) { return std::tolower(c); });
                g_key_perms[hash_lc] = {role_perms[role_str], role_str};
            }
        }

        // Policy is the single source of truth: every configured --api-key must be
        // listed in policy.api_keys, else abort (runs even with zero policy keys).
        for (const auto & key : params.api_keys) {
            std::string hash = sha256_hex(key);
            if (g_key_perms.find(hash) == g_key_perms.end()) {
                SRV_ERR("%s", "an --api-key/--api-key-file entry is not present in the "
                    "auth_policy api_keys map; in RBAC mode the policy is the single "
                    "source of truth for valid keys\n");
                return false;
            }
        }
    } else if (has_api_keys) {
        // Legacy mode: hash the configured keys and give them PERM_ALL
        for (const auto & key : params.api_keys) {
            std::string hash = sha256_hex(key);
            g_key_perms[hash] = {PERM_ALL, "legacy"};
        }
    }

    // F009d/F010b: Initialize OIDC/introspection (MANDATORY initial JWKS fetch for OIDC, fail-closed at boot)
    if (has_oidc || has_introspect) {
        // Call set_require_typ BEFORE init (C3: set on every OIDC-enabled path)
        server_oidc::set_require_typ(g_oidc_require_typ);
        // Then init (performs JWKS discovery and fetch for OIDC; introspection config validation)
        if (!server_oidc::init(params)) {
            return false;
        }
        if (has_oidc) g_oidc_enabled = true;
        if (has_introspect) g_introspect_enabled = true;
    }

    // F008d: S1 defensive startup invariant (MANDATORY, fail-closed).
    // If mTLS is enabled but g_auth_enabled is somehow false, refuse to start.
    // This catches a half-applied enforcement-flip coupling (extending the auth-disabled
    // early return AND OR-ing has_mtls into g_auth_enabled are two separate edits).
    if (has_mtls && !g_auth_enabled) {
        SRV_ERR("%s", "mTLS is enabled but auth enforcement is off; refusing to start\n");
        return false;
    }

    // F009d: S1 defensive startup invariant (MANDATORY, fail-closed).
    // If OIDC is enabled but g_auth_enabled is somehow false, refuse to start.
    // This catches a half-applied enforcement-flip coupling.
    if (has_oidc && !g_auth_enabled) {
        SRV_ERR("%s", "OIDC is enabled but auth enforcement is off; refusing to start\n");
        return false;
    }

    // F010b: S1 defensive startup invariant (MANDATORY, fail-closed).
    // If introspection is enabled but g_auth_enabled is somehow false, refuse to start.
    if (has_introspect && !g_auth_enabled) {
        SRV_ERR("%s", "OIDC introspection is enabled but auth enforcement is off; refusing to start\n");
        return false;
    }

    // R12 item 6: Fail-closed if default_role + introspection (would bypass introspection via api-key fallback)
    if (has_introspect && g_default_perms != 0) {
        SRV_ERR("%s", "policy default_role cannot be combined with --oidc-introspection-url; "
                      "an unknown bearer would be authorized by the default role before introspection runs\n");
        return false;
    }

    // R13: Warn if introspection with no policy file (all tokens would get perms=0)
    if (has_introspect && g_oidc_role_map.empty()) {
        SRV_WRN("%s", "OIDC introspection is configured but policy has no oidc.role_map; "
                      "all introspected tokens will get perms=0 and be denied\n");
    }

    return true;
}

uint32_t server_auth::required_perm(const std::string & normalized_path,
                                     const std::string & method,
                                     bool & matched) {
    matched = false;
    auto path_segs = split_path(normalized_path);

    // Look for matching pattern with exact method
    for (const auto & route : g_route_table) {
        if (route.method == method && path_matches(route.path_segments, path_segs)) {
            matched = true;
            return route.perm;
        }
    }

    return PERM_PUBLIC;  // matched=false indicates unclassified
}

// F008d: mTLS role map lookup result
struct mtls_lookup_result {
    bool matched = false;
    uint32_t perms = 0;
    std::string role;
};

// F008d: Look up mTLS role mapping: exact match wins, then longest-prefix wildcard.
// Uses precomputed prefix_len to avoid substr/string construction per request.
// Returns {matched, perms, role}. Empty identity never matches.
static mtls_lookup_result mtls_lookup(const std::string & identity) {
    mtls_lookup_result result;
    if (identity.empty()) {
        return result;
    }

    // First pass: exact match
    for (const auto & entry : g_mtls_role_map) {
        if (!entry.wildcard && entry.pattern == identity) {
            result.matched = true;
            result.perms = entry.perms;
            result.role = entry.role;
            return result;
        }
    }

    // Second pass: longest-prefix wildcard (using precomputed prefix_len)
    size_t longest_prefix_len = 0;
    uint32_t longest_perms = 0;
    std::string longest_role;
    for (const auto & entry : g_mtls_role_map) {
        if (entry.wildcard && entry.prefix_len > 0) {
            // entry.prefix_len is the length of the pattern without the trailing '*'
            if (identity.size() >= entry.prefix_len &&
                identity.compare(0, entry.prefix_len, entry.pattern.data(), entry.prefix_len) == 0 &&
                entry.prefix_len > longest_prefix_len) {
                longest_prefix_len = entry.prefix_len;
                longest_perms = entry.perms;
                longest_role = entry.role;
            }
        }
    }

    if (longest_prefix_len > 0) {
        result.matched = true;
        result.perms = longest_perms;
        result.role = longest_role;
    }

    return result;
}

// F009d/F010b: Extract roles from OIDC claims JSON by following a precomputed dot-separated path.
// OQ-B2: If the terminal segment is "scope" or "scp", split the string value on whitespace.
// Returns empty vector on parse error, missing path, or wrong type (fail-closed).
// segments: pre-split claim path (avoids per-request istringstream parse).
static std::vector<std::string> extract_oidc_roles(const std::string & claims_json,
                                                    const std::vector<std::string> & segments) {
    std::vector<std::string> result;
    try {
        json claims = json::parse(claims_json);
        json * current = &claims;

        // Walk the dot-separated path
        for (const auto & seg : segments) {
            if (!current->is_object()) {
                return result;  // not an object -> cannot walk further
            }
            if (!current->contains(seg)) {
                return result;  // path segment missing
            }
            current = &((*current)[seg]);
        }

        // Terminal node: handle based on type and last segment name
        std::string last_segment = segments.empty() ? "" : segments.back();
        bool is_scope_claim = (last_segment == "scope" || last_segment == "scp");

        if (current->is_array()) {
            for (const auto & elem : *current) {
                if (elem.is_string()) {
                    result.push_back(elem.get<std::string>());
                }
            }
        } else if (current->is_string()) {
            // Single string value
            std::string value = current->get<std::string>();
            if (is_scope_claim) {
                // OQ-B2: Split scope/scp on whitespace
                std::istringstream iss(value);
                std::string role;
                while (iss >> role) {  // >> skips whitespace
                    if (!role.empty()) {
                        result.push_back(role);
                    }
                }
            } else {
                // Non-scope string: treat as single role
                result.push_back(value);
            }
        }
        // else: wrong type -> return empty (no roles)
    } catch (...) {
        // Parse error or other issue -> return empty (fail-closed)
    }
    return result;
}

// F005/F007/F009d: resolve principal from mTLS, trusted-proxy, OIDC, or API key
static server_auth_principal resolve_principal(const server_auth_request & req) {
    // F015: Reset failure reason at entry (reset must be adjacent to writes, per design)
    t_fail_reason = AUTH_FAIL_UNKNOWN;
    t_attempted_method = AUTH_NONE;

    // F008d: Precedence: mTLS -> trusted-proxy (if peer trusted and subject present) -> API key -> anonymous

    // 1. mTLS (highest precedence). A presented cert is chain-verified by the TLS stack.
    if (req.mtls_present) {
        // Pick identity per identity_source
        std::string identity = (g_mtls_identity_source == "san_dns") ? req.mtls_san_dns : req.mtls_san_uri;

        server_auth_principal p;
        p.authenticated = true;  // valid cert -> authenticated, even if unmapped
        p.method = AUTH_MTLS;
        p.issuer = "mtls";       // constant; never the CA DN (no PII)
        p.subject = identity;    // the SAN value (URI/DNS)
        p.perms = 0;

        mtls_lookup_result lookup_res = mtls_lookup(identity);
        if (lookup_res.matched) {
            p.perms = lookup_res.perms;
            if (!lookup_res.role.empty()) {
                p.roles = {lookup_res.role};
            }
        }
        // unmapped SAN or empty identity -> authenticated, perms=0 -> caller denies 403
        return p;
    }

    // F007: Precedence: trusted-proxy (if peer trusted and subject present) -> OIDC -> API key -> anonymous

    // Try trusted-proxy (F007): only if peer is in a trusted CIDR and X-Auth-Subject is set
    if (peer_is_trusted(req.peer_addr) && !req.x_auth_subject.empty()) {
        server_auth_principal p;
        p.authenticated = true;
        p.method = AUTH_TRUSTED_PROXY;
        p.issuer = "trusted-proxy";
        p.subject = req.x_auth_subject;  // opaque id from proxy
        p.roles = split_csv(req.x_auth_roles);  // may include unknown roles
        p.perms = 0;
        // Map known roles to perms; unknown roles contribute nothing (fail-closed)
        for (const auto & role : p.roles) {
            auto it = g_role_perms.find(role);
            if (it != g_role_perms.end()) {
                p.perms |= it->second;
            }
        }
        return p;
    }

    // F009d: Try OIDC (Bearer JWT token)
    // OIDC reads Authorization header only (not X-Api-Key)
    if (g_oidc_enabled) {
        std::string token = req.authorization;
        if (token.rfind("Bearer ", 0) == 0) {
            token = token.substr(7);
        }
        if (!token.empty() && server_oidc::looks_like_jwt(token)) {
            oidc_validation v = server_oidc::validate(token);
            if (v.ok) {
                server_auth_principal p;
                p.authenticated = true;
                p.method = AUTH_OIDC;
                p.issuer = v.issuer;
                p.subject = v.subject;
                p.expires_at = v.expires_at;
                p.roles = extract_oidc_roles(v.claims_json, g_oidc_roles_claim_segs);
                p.perms = 0;
                // Map known roles to perms; unknown roles contribute nothing (fail-closed)
                for (const auto & role : p.roles) {
                    auto it = g_oidc_role_map.find(role);
                    if (it != g_oidc_role_map.end()) {
                        p.perms |= it->second;
                    }
                }
                return p;  // unmapped roles -> perms=0 -> caller 403
            }
            // JWT-shaped but invalid -> do NOT fall through to API-key auth
            // A 3-segment token is unambiguously a JWT; treating it as an API key
            // is pointless and muddies audit. Return anonymous (caller answers 401).
            t_fail_reason = oidc_error_to_fail_reason(v.error);
            t_attempted_method = AUTH_OIDC;
            return server_auth_principal{};
        }
        // Not JWT-shaped -> fall through to API-key branch
    }

    // Try API key (Authorization or X-Api-Key header)
    std::string key = req.authorization;
    if (key.empty()) key = req.x_api_key;
    if (key.rfind("Bearer ", 0) == 0) key = key.substr(7);

    if (!key.empty()) {
        std::string hash = sha256_hex(key);
        auto it = g_key_perms.find(hash);
        if (it != g_key_perms.end()) {
            // Known key
            server_auth_principal p;
            p.authenticated = true;
            p.method = AUTH_API_KEY;
            p.subject = "apikey:" + hash.substr(0, 12);
            if (!it->second.role.empty()) {
                p.roles = {it->second.role};
            }
            p.perms = it->second.perms;
            return p;
        } else if (g_default_perms != 0) {
            // Unknown key with default_role
            server_auth_principal p;
            p.authenticated = true;
            p.method = AUTH_API_KEY;
            p.subject = "apikey:" + hash.substr(0, 12);
            p.perms = g_default_perms;
            return p;
        }
        // F015: Unknown key, no default -> fall through to anonymous
        t_fail_reason = AUTH_FAIL_INVALID_KEY;
        t_attempted_method = AUTH_API_KEY;
    }

    // F010b: Try introspection (RFC 7662 opaque-token introspection)
    // OQ-B1: opaque bearer branch sits AFTER API-key and BEFORE anonymous
    if (g_introspect_enabled) {
        std::string token = req.authorization;
        if (token.rfind("Bearer ", 0) == 0) {
            token = token.substr(7);
        }
        // Section 8.5 (binding, supersedes 3.4): reaching this point with a JWT-shaped
        // token implies g_oidc_enabled == false (the JWT block above always returns when
        // enabled), so introspect it unconditionally - introspection-only mode must still
        // introspect a JWT-formatted opaque token, not skip it.
        if (!token.empty()) {
            oidc_validation v = server_oidc::introspect(token);
            if (v.ok) {
                server_auth_principal p;
                p.authenticated = true;
                p.method = AUTH_OIDC;
                p.issuer = v.issuer;  // R11: configured issuer or "oidc-introspection"
                p.subject = v.subject;
                p.expires_at = v.expires_at;
                p.roles = extract_oidc_roles(v.claims_json, g_oidc_roles_claim_segs);
                p.perms = 0;
                // Map known roles to perms; unknown roles contribute nothing (fail-closed)
                for (const auto & role : p.roles) {
                    auto it = g_oidc_role_map.find(role);
                    if (it != g_oidc_role_map.end()) {
                        p.perms |= it->second;
                    }
                }
                return p;  // unmapped roles -> perms=0 -> caller 403
            }
            // F015: Introspection failed: fall through to anonymous (not an API key)
            t_fail_reason = AUTH_FAIL_INTROSPECT_DENIED;
            t_attempted_method = AUTH_OIDC;
        }
    }

    // F015: No valid credential -> unauthenticated. If we reach here without any method
    // explicitly failing, it means no credential was provided.
    if (t_fail_reason == AUTH_FAIL_UNKNOWN) {
        // Check if any credential was attempted (we would have set a reason if it failed)
        // If no reason is set and we're returning anonymous, default to NO_CREDENTIAL
        t_fail_reason = AUTH_FAIL_NO_CREDENTIAL;
    }
    return server_auth_principal{};
}

server_auth_decision server_auth::authorize_request(const server_auth_request & req) {
    // Path normalization is input validation and must run unconditionally,
    // before the auth-disabled allow-all short-circuit (a malformed path is
    // rejected regardless of whether auth is enabled).
    std::string norm;
    server_norm_status norm_status = normalize_path(req.raw_path, norm);
    if (norm_status == NORM_REJECT) {
        t_principal = server_auth_principal{};  // stays cleared
        server_auth_decision d{false, 400, ERROR_TYPE_INVALID_REQUEST, "invalid request path"};
        // F015: Increment counter before audit
        if (g_auth_enabled) {
            g_authn_fail[AUTH_NONE][AUTH_FAIL_MALFORMED_PATH]++;
        }
        // Audit the 400 error with raw path (not normalized)
        audit_emit(req, req.raw_path, 0, false, t_principal, d);
        return d;
    }

    // Classify the route regardless of g_auth_enabled to determine public vs protected
    bool matched = false;
    uint32_t need = PERM_PUBLIC;
    if (norm_status == NORM_OK) {
        need = required_perm(norm, req.method, matched);
    }
    const bool is_public_allow = matched && need == PERM_PUBLIC;

    // Auth-disabled mode: allow all (path already passed normalization above)
    if (!g_auth_enabled) {
        server_auth_decision d{true, 200, ERROR_TYPE_PERMISSION, ""};
        if (!is_public_allow) {
            // norm is only written by normalize_path on NORM_OK; use the raw path
            // for NORM_UNMATCHED so the audit line never logs an empty path.
            const std::string & audit_path = (norm_status == NORM_UNMATCHED) ? req.raw_path : norm;
            audit_emit(req, audit_path, 0, false, server_auth_principal{}, d);
        }
        return d;
    }

    // Auth is enabled beyond this point: resolve principal
    // Move assign to t_principal, then bind a const ref to avoid a copy.
    t_principal = resolve_principal(req);
    const server_auth_principal & p = t_principal;

    if (norm_status == NORM_UNMATCHED) {
        // Outside api_prefix: deny by default, require authentication
        server_auth_decision d;
        if (!p.authenticated) {
            d = {false, 401, ERROR_TYPE_AUTHENTICATION, "Invalid API Key"};
            // F015: Increment counter before audit (401 only)
            if (g_auth_enabled) {
                g_authn_fail[t_attempted_method][t_fail_reason]++;
            }
        } else {
            d = {true, 200, ERROR_TYPE_PERMISSION, ""};
        }
        audit_emit(req, req.raw_path, 0, false, p, d);
        return d;
    }
    // norm_status == NORM_OK below

    // 3c: Public routes (/health, /models GET, etc.) are NOT audited
    if (is_public_allow) {
        return {true, 200, ERROR_TYPE_PERMISSION, ""};
    }

    // F011: Check if path is in public_endpoints (opens route to unauthenticated access)
    if (g_public_endpoints.count(norm) > 0) {
        return {true, 200, ERROR_TYPE_PERMISSION, ""};
    }

    // Everything else requires authentication
    if (!p.authenticated) {
        server_auth_decision d{false, 401, ERROR_TYPE_AUTHENTICATION, "Invalid API Key"};
        // F015: Increment counter before audit
        if (g_auth_enabled) {
            g_authn_fail[t_attempted_method][t_fail_reason]++;
        }
        audit_emit(req, norm, need, matched, p, d);
        return d;
    }

    // Unclassified route: authenticated callers can proceed (httplib will 404)
    if (!matched) {
        server_auth_decision d{true, 200, ERROR_TYPE_PERMISSION, ""};
        audit_emit(req, norm, need, matched, p, d);
        return d;
    }

    // Check permission
    server_auth_decision d;
    if ((p.perms & need) == need) {
        d = {true, 200, ERROR_TYPE_PERMISSION, ""};
    } else {
        d = {false, 403, ERROR_TYPE_PERMISSION, "insufficient permissions"};
        // F015: Increment authz_deny counter (403 only)
        if (g_auth_enabled) {
            int perm_idx = perm_index(need);
            if (perm_idx >= 0 && perm_idx < PERM_INDEX_COUNT) {
                server_authz_deny_reason reason = (p.perms == 0) ? AUTHZ_DENY_UNMAPPED_ROLE : AUTHZ_DENY_INSUFFICIENT_PERM;
                g_authz_deny[p.method][perm_idx][reason]++;
            }
        }
    }
    audit_emit(req, norm, need, matched, p, d);
    return d;
}

void server_auth::register_route(const std::string & method,
                                 const std::string & path_pattern,
                                 uint32_t perm) {
    route_entry_rt rt;
    rt.method = method;
    rt.perm = perm;
    rt.path_segments = split_path(path_pattern);
    g_route_table.push_back(rt);
}

bool server_auth::is_infer_only(const std::string & normalized_path) {
    auto path_segs = split_path(normalized_path);

    // Find if pattern matches
    bool found = false;
    for (const auto & route : g_route_table) {
        if (path_matches(route.path_segments, path_segs)) {
            found = true;
            // Check if this method is INFER-only
            if (route.perm != PERM_INFER) {
                return false;  // Found a non-INFER method for this pattern
            }
        }
    }

    return found;  // true if found and all methods are INFER
}

void server_auth::reset_principal() {
    t_principal = server_auth_principal{};
}

const server_auth_principal & server_auth::principal_at_construction() {
    return t_principal;
}

bool server_auth::assert_routes_covered(
    const std::vector<std::pair<std::string, std::string>> & registered_routes) {
    // Check that every registered (method, path) has a matching table entry
    for (const auto & [method, path] : registered_routes) {
        auto path_segs = split_path(path);
        bool found = false;
        for (const auto & route : g_route_table) {
            if (route.method == method && path_matches(route.path_segments, path_segs)) {
                found = true;
                break;
            }
        }
        if (!found) {
            SRV_ERR("route '%s %s' has no auth policy entry; refusing to start\n",
                    method.c_str(), path.c_str());
            return false;
        }
    }
    return true;
}

const std::vector<std::string> & server_auth::identity_headers() {
    static const std::vector<std::string> headers = []() {
        std::vector<std::string> v = {
            server_auth_headers::X_AUTH_SUBJECT,
            server_auth_headers::X_AUTH_ROLES,
            server_auth_headers::X_FORWARDED_CLIENT_CERT,
        };
        for (auto & h : v) {
            std::transform(h.begin(), h.end(), h.begin(),
                           [](unsigned char c) { return std::tolower(c); });
        }
        return v;
    }();
    return headers;
}

// ============================================================================
// F013: mid-stream access-token expiry
// ============================================================================

int64_t server_auth::stream_deadline(const server_auth_principal & p) {
    if (p.expires_at <= 0) {
        return 0;  // no expiry: api key, mTLS, trusted proxy, or auth disabled
    }
    const int64_t max_deadline = std::numeric_limits<int64_t>::max();
    if (p.expires_at > max_deadline - g_stream_expiry_grace_sec) {
        return max_deadline;  // saturate: a far-future exp never cuts, but never wraps either
    }
    return p.expires_at + g_stream_expiry_grace_sec;
}

bool server_auth::stream_expired(int64_t deadline) {
    if (deadline <= 0) {
        return false;
    }
    return (int64_t) std::time(nullptr) >= deadline;
}

const std::string & server_auth::sse_expired_chunk_oai() {
    static const std::string chunk = format_oai_sse(
        json {{ "error", format_error_response("access token expired", ERROR_TYPE_AUTHENTICATION) }});
    return chunk;
}

// ============================================================================
// F015: Prometheus metrics exposition
// ============================================================================

std::string server_auth::metrics_prometheus() {
    if (!g_auth_enabled) {
        return "";  // byte-identical to pre-F015 when auth is disabled
    }

    std::ostringstream oss;

    // === llamacpp_auth_failures_total ===
    oss << "# HELP llamacpp_auth_failures_total Authentication failures by method and reason.\n";
    oss << "# TYPE llamacpp_auth_failures_total counter\n";

    for (int method_idx = 0; method_idx < AUTH_METHOD_COUNT; ++method_idx) {
        for (int reason_idx = 0; reason_idx < AUTH_FAIL_COUNT; ++reason_idx) {
            uint64_t val = g_authn_fail[method_idx][reason_idx].load(std::memory_order_relaxed);
            if (val > 0) {
                std::string method_str = auth_method_to_string((server_auth_method)method_idx);
                const char * reason_str = auth_fail_reason_to_string((server_auth_fail_reason)reason_idx);
                oss << "llamacpp_auth_failures_total{auth_method=\"" << method_str
                    << "\",reason=\"" << reason_str << "\"} " << val << "\n";
            }
        }
    }

    // === llamacpp_auth_authz_denied_total ===
    oss << "# HELP llamacpp_auth_authz_denied_total Authorization denials for an authenticated principal.\n";
    oss << "# TYPE llamacpp_auth_authz_denied_total counter\n";

    for (int method_idx = 0; method_idx < AUTH_METHOD_COUNT; ++method_idx) {
        for (int perm_idx = 0; perm_idx < PERM_INDEX_COUNT; ++perm_idx) {
            for (int reason_idx = 0; reason_idx < AUTHZ_DENY_COUNT; ++reason_idx) {
                uint64_t val = g_authz_deny[method_idx][perm_idx][reason_idx].load(std::memory_order_relaxed);
                if (val > 0) {
                    std::string method_str = auth_method_to_string((server_auth_method)method_idx);
                    uint32_t perm = 0;
                    switch (perm_idx) {
                        case 0: perm = PERM_INFER; break;
                        case 1: perm = PERM_READ_STATE; break;
                        case 2: perm = PERM_METRICS; break;
                        case 3: perm = PERM_ADMIN_STATE; break;
                        case 4: perm = PERM_ADMIN_MODELS; break;
                        case 5: perm = PERM_PROXY; break;
                    }
                    std::string perm_str = perm_to_string(perm);
                    const char * reason_str = authz_deny_reason_to_string((server_authz_deny_reason)reason_idx);
                    oss << "llamacpp_auth_authz_denied_total{auth_method=\"" << method_str
                        << "\",required_perm=\"" << perm_str
                        << "\",reason=\"" << reason_str << "\"} " << val << "\n";
                }
            }
        }
    }

    // === llamacpp_auth_jwks_refresh_total (from OIDC) ===
    // Emit BOTH series (including zeros) whenever JWKS-based OIDC is configured, and neither
    // when it is not, so rate() on the failure series is well-defined from the first scrape -
    // not gated on whether a refresh has happened yet (design section 4.5 / 7.6 OQ-B6).
    if (g_oidc_enabled) {
        uint64_t jwks_success = 0, jwks_failure = 0;
        server_oidc::jwks_refresh_counts(jwks_success, jwks_failure);
        oss << "# HELP llamacpp_auth_jwks_refresh_total JWKS refresh attempts by result.\n";
        oss << "# TYPE llamacpp_auth_jwks_refresh_total counter\n";
        oss << "llamacpp_auth_jwks_refresh_total{result=\"failure\"} " << jwks_failure << "\n";
        oss << "llamacpp_auth_jwks_refresh_total{result=\"success\"} " << jwks_success << "\n";
    }

    return oss.str();
}
