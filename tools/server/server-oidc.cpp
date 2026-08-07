#include "server-oidc.h"
#include "server-common.h"
#include "common.h"
#include "http.h"
#include "vendor/sha256.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <unordered_map>
#include <vector>

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
#define JWT_DISABLE_PICOJSON
#include <jwt-cpp/traits/nlohmann-json/traits.h>
#include <jwt-cpp/jwt.h>
#endif

// F009a: Check if OIDC is configured (pure params check, no network/crypto)
bool server_oidc::configured(const common_params & params) {
    return !params.oidc_issuer.empty() || !params.oidc_jwks_url.empty();
}

// F009a: Check if token has JWT shape (3 dot-separated base64url segments)
// Pure string check, no crypto. Base64url charset is [A-Za-z0-9_-]; real unpadded
// JWT segments never contain '=' (C-4), so it is not accepted here.
bool server_oidc::looks_like_jwt(const std::string & token) {
    // Count dots and verify segment structure
    int dot_count = 0;
    size_t prev = 0;

    for (size_t i = 0; i < token.length(); i++) {
        if (token[i] == '.') {
            // Each segment must be non-empty
            if (i == prev) {
                return false;
            }
            // Check that segment contains only base64url chars
            for (size_t j = prev; j < i; j++) {
                char c = token[j];
                if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                      (c >= '0' && c <= '9') || c == '_' || c == '-')) {
                    return false;
                }
            }
            dot_count++;
            prev = i + 1;
        }
    }

    // Must have exactly 2 dots (3 segments)
    if (dot_count != 2) {
        return false;
    }

    // Last segment must be non-empty and valid base64url
    if (prev >= token.length()) {
        return false;
    }
    for (size_t j = prev; j < token.length(); j++) {
        char c = token[j];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-')) {
            return false;
        }
    }

    return true;
}

// F010b: Check if introspection is configured (pure params check, no network/crypto)
bool server_oidc::introspection_configured(const common_params & params) {
    return !params.oidc_introspection_url.empty();
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT

// F009b/c: File-scope state (protected by g_jwks_mtx)
namespace {
    using traits = jwt::traits::nlohmann_json;

    // Configuration resolved at init time
    std::string g_oidc_issuer;
    std::string g_jwks_url;
    std::string g_oidc_ca_file;
    std::set<std::string> g_oidc_algs;
    std::vector<std::string> g_oidc_audiences;
    int g_oidc_clock_skew = 60;
    int g_oidc_http_timeout = 5;
    int g_jwks_ttl_fallback = 300;
    int g_unknown_kid_window = 300;
    // S-1 hardening: min seconds between expiry-triggered refresh ATTEMPTS (not just
    // successes), so a downed IdP cannot turn every post-TTL request into a blocking
    // HTTPS GET under g_jwks_mtx. Test-overridable, see LLAMA_OIDC_JWKS_REFRESH_MIN_INTERVAL_SECONDS.
    int g_jwks_refresh_min_interval = 30;
    // C-1 hardening: ceiling on the cache TTL (clamps a response Cache-Control:
    // max-age as well as the fallback). Test-overridable (S4), see
    // LLAMA_OIDC_JWKS_TTL_CEILING_SECONDS.
    int64_t g_jwks_ttl_ceiling = 86400;  // 24h
    bool g_oidc_require_typ = false;

    // JWKS cache state
    struct jwks_cache {
        std::string raw_jwks;
        std::set<std::string> kids;
        std::unordered_map<std::string, std::string> pems;  // derived from raw_jwks, replaced atomically
        int64_t expires_at = 0;
        int64_t last_refresh = 0; // last refresh ATTEMPT (set regardless of outcome, S-1)
        int64_t last_unknown_kid_refresh = 0;
    };

    std::mutex g_jwks_mtx;
    jwks_cache g_jwks_cache;

    // F015: JWKS refresh counters (incremented in refresh_jwks, exposed via server_oidc::jwks_refresh_counts)
    std::atomic<uint64_t> g_jwks_refresh_success;
    std::atomic<uint64_t> g_jwks_refresh_failure;

    // F010b: Introspection state (RFC 7662)
    bool        g_introspect_configured = false;
    std::string g_introspect_url;
    std::string g_introspect_client_id;
    std::string g_introspect_client_secret;         // read from file at init; never logged
    int         g_introspect_neg_ttl = 5;           // negative-result cache seconds (const-ish)
    int         g_introspect_max_pos_ttl = 60;      // positive-result cache ceiling (PLAN 4.4)

    struct introspect_cache_entry {
        int64_t         expires_at = 0;             // unix seconds this cache entry is valid until
        oidc_validation result;                     // ok + subject/issuer/expires_at/claims_json
    };
    std::mutex g_introspect_mtx;
    std::unordered_map<std::string, introspect_cache_entry> g_introspect_cache;  // key = sha256_hex(token)
    int     g_introspect_max_per_sec  = 20;   // env-overridable
    int64_t g_introspect_window_start = 0;
    int     g_introspect_window_count = 0;
    const size_t g_introspect_cache_max = 4096;

    // Random number generator for jitter
    std::random_device g_rng_seed;
    std::mt19937 g_rng(g_rng_seed());

    // Helper: hardened HTTPS GET, shared by JWKS fetch and discovery (S1/S5).
    // - S1: https-only (rejects http:// outright) and never follows redirects.
    // - S5: short connection/read timeouts and a response body size cap.
    // On success returns true, fills out_body, and sets out_max_age from a
    // usable "Cache-Control: max-age=<n>" response header (left untouched if
    // absent/malformed/<=0, so the caller's fallback TTL applies).
    bool https_get(const std::string & url, std::string & out_body, int64_t & out_max_age) {
        if (url.compare(0, 8, "https://") != 0) {
            SRV_WRN("OIDC: refusing non-https URL: %s\n", url.c_str());
            return false;
        }
        try {
            auto [cli, parts] = common_http_client(url);

            // S1: do NOT follow redirects - a redirect is a fetch FAILURE
            cli.set_follow_location(false);

            // S5: short timeouts
            cli.set_connection_timeout(std::chrono::seconds(g_oidc_http_timeout));
            cli.set_read_timeout(std::chrono::seconds(g_oidc_http_timeout));

            // S5 / S-2 hardening: cap response body size (1 MiB), enforced by httplib
            // itself DURING the streamed read (it aborts the read once the accumulated
            // body exceeds this), not after the whole body is already buffered - a
            // hostile IdP cannot OOM us by streaming past the cap within the timeout.
            const size_t max_body_size = 1024 * 1024;
            cli.set_payload_max_length(max_body_size);

#ifdef CPPHTTPLIB_SSL_ENABLED
            cli.enable_server_certificate_verification(true);  // MANDATORY
            if (!g_oidc_ca_file.empty()) {
                cli.set_ca_cert_path(g_oidc_ca_file);  // optional pin
            }
#endif

            auto res = cli.Get(parts.path);
            if (!res || res->status != 200) {
                SRV_WRN("OIDC: fetch failed or response too large for %s (HTTP %d)\n",
                        url.c_str(), res ? res->status : 0);
                return false;
            }

            std::string cache_control = res->get_header_value("Cache-Control");
            size_t max_age_pos = cache_control.find("max-age=");
            if (max_age_pos != std::string::npos) {
                try {
                    int64_t max_age = std::stoll(cache_control.substr(max_age_pos + 8));
                    if (max_age > 0) {
                        out_max_age = max_age;
                    }
                } catch (...) {
                    // malformed max-age -> ignore, caller keeps its fallback TTL
                }
            }

            out_body = res->body;
            return true;
        } catch (const std::exception & e) {
            SRV_WRN("OIDC: fetch exception for %s: %s\n", url.c_str(), e.what());
            return false;
        }
    }

    // Helper: fetch the JWKS from the configured URL
    bool fetch_jwks(std::string & out_raw_jwks, int64_t & out_max_age) {
        std::string body;
        if (!https_get(g_jwks_url, body, out_max_age)) {
            return false;
        }

        // Parse as JSON to validate
        try {
            nlohmann::json jwks_json = nlohmann::json::parse(body);
            // Verify it has a "keys" array with at least one key
            if (!jwks_json.contains("keys") || !jwks_json["keys"].is_array() ||
                jwks_json["keys"].empty()) {
                SRV_WRN("%s", "OIDC: JWKS has no keys\n");
                return false;
            }
        } catch (...) {
            SRV_WRN("%s", "OIDC: JWKS JSON parse failed\n");
            return false;
        }

        out_raw_jwks = std::move(body);
        return true;
    }

    // Helper: resolve the cache TTL for a refresh - Cache-Control max-age from the
    // response when usable, else the (test-overridable) fallback. C-1: clamp to a
    // (test-overridable) ceiling so a compromised/misbehaving IdP cannot pin stale
    // keys near-forever via an oversized max-age.
    int64_t get_cache_ttl(int64_t max_age_from_response) {
        int64_t ttl = (max_age_from_response > 0)
            ? max_age_from_response
            : (g_jwks_ttl_fallback > 0 ? g_jwks_ttl_fallback : 300);
        return std::min(ttl, g_jwks_ttl_ceiling);
    }

    // Forward declaration
    std::optional<std::string> jwk_to_pem(const jwt::jwk<traits> & jwk);

    // Helper: refresh JWKS (single-flight under mutex)
    // On success: replaces cache, sets expires_at, returns true
    // On failure: KEEPS existing cache (fail-static), returns false
    // S-1: last_refresh is anchored on the ATTEMPT (set first, before the network
    // call), not just on success - this is what lets jwks_get_key rate-limit
    // expiry-triggered refresh attempts against a down IdP.
    bool refresh_jwks() {
        g_jwks_cache.last_refresh = std::time(nullptr);

        std::string new_jwks;
        int64_t max_age = 0;
        if (!fetch_jwks(new_jwks, max_age)) {
            // Keep existing cache (fail-static)
            // F015: Increment failure counter
            g_jwks_refresh_failure++;
            return false;
        }

        // Parse to extract kids and derive PEMs
        try {
            auto parsed = jwt::parse_jwks<traits>(new_jwks);
            std::set<std::string> new_kids;
            std::unordered_map<std::string, std::string> new_pems;
            for (const auto & jwk : parsed) {
                if (!jwk.has_key_id()) {
                    continue;
                }
                std::string kid = jwk.get_key_id();
                // Duplicate kid: FIRST wins. This must match jwt-cpp's find_by_kid
                // (a std::find_if over a vector), which the pre-cache code used via
                // parsed.get_jwk(kid). Last-wins would let an appended duplicate-kid
                // entry override the legitimate key for that kid.
                if (!new_kids.insert(kid).second) {
                    continue;
                }
                // Derive PEM for this JWK (if convertible); an unconvertible key
                // (e.g. kty:oct) contributes a kid but no PEM, so it is rejected
                // by the two-level gate in jwks_get_key rather than refetched.
                auto pem_opt = jwk_to_pem(jwk);
                if (pem_opt) {
                    new_pems.emplace(kid, *pem_opt);
                }
            }

            int64_t now = std::time(nullptr);
            g_jwks_cache.raw_jwks = std::move(new_jwks);
            g_jwks_cache.kids = std::move(new_kids);
            g_jwks_cache.pems = std::move(new_pems);
            g_jwks_cache.expires_at = now + get_cache_ttl(max_age);
            g_jwks_cache.last_refresh = now;
            // F015: Increment success counter
            g_jwks_refresh_success++;
            return true;
        } catch (...) {
            SRV_WRN("%s", "OIDC: JWKS parse exception\n");
            // F015: Increment failure counter
            g_jwks_refresh_failure++;
            return false;
        }
    }

    // Helper: build public-key PEM from a JWK
    // Returns nullopt if the JWK cannot be converted to a PEM
    // Tries bare RSA/EC parameters first (n,e for RSA; crv,x,y for EC),
    // falls back to x5c if present. Rejects symmetric (oct) keys.
    std::optional<std::string> jwk_to_pem(const jwt::jwk<traits> & jwk) {
        try {
            // Get key type
            if (!jwk.has_key_type()) {
                return std::nullopt;
            }
            std::string kty = jwk.get_key_type();

            // Reject symmetric keys (oct): never use as HMAC secret
            if (kty == "oct") {
                return std::nullopt;
            }

            // Try bare RSA parameters (RFC 7518 Section 6.3)
            if (kty == "RSA") {
                try {
                    // Check if we have the required RSA parameters
                    auto n_claim = jwk.get_jwk_claim("n");
                    auto e_claim = jwk.get_jwk_claim("e");
                    if (n_claim.get_type() == jwt::json::type::string &&
                        e_claim.get_type() == jwt::json::type::string) {
                        std::string n = n_claim.as_string();
                        std::string e = e_claim.as_string();
                        if (!n.empty() && !e.empty()) {
                            // Use jwt-cpp's helper to build RSA public key from components
                            std::error_code ec;
                            std::string pem = jwt::helper::create_public_key_from_rsa_components(n, e, ec);
                            if (!ec && !pem.empty()) {
                                return pem;
                            }
                        }
                    }
                } catch (...) {
                    // Fall through to x5c
                }
            }

            // Try bare EC parameters (RFC 7518 Section 6.2)
            if (kty == "EC") {
                try {
                    if (jwk.has_curve()) {
                        auto x_claim = jwk.get_jwk_claim("x");
                        auto y_claim = jwk.get_jwk_claim("y");
                        if (x_claim.get_type() == jwt::json::type::string &&
                            y_claim.get_type() == jwt::json::type::string) {
                            std::string crv = jwk.get_curve();
                            std::string x = x_claim.as_string();
                            std::string y = y_claim.as_string();
                            if (!crv.empty() && !x.empty() && !y.empty()) {
                                // Use jwt-cpp's helper to build EC public key from components
                                std::error_code ec;
                                std::string pem = jwt::helper::create_public_key_from_ec_components(crv, x, y, ec);
                                if (!ec && !pem.empty()) {
                                    return pem;
                                }
                            }
                        }
                    }
                } catch (...) {
                    // Fall through to x5c
                }
            }

            // Fallback: try x5c (X.509 certificate chain)
            if (jwk.has_x5c()) {
                try {
                    std::string x5c_b64der = jwk.get_x5c_key_value();
                    std::string pem = jwt::helper::convert_base64_der_to_pem(x5c_b64der);
                    pem = jwt::helper::extract_pubkey_from_cert(pem);
                    return pem;
                } catch (...) {
                    // x5c conversion failed
                }
            }
        } catch (...) {
            // JWK processing failed
        }
        return std::nullopt;
    }

    // F010b/B2: Insert (or refresh) one cache entry, sweeping expired entries first if the
    // cache is at cap. Never clears the whole map (that would let an attacker flush
    // legitimate positive entries on demand). Skips the insert if still at cap after the
    // sweep; the caller's result is still returned to the request either way.
    void introspect_cache_insert(const std::string & token_hash, const oidc_validation & result, int64_t expires_at) {
        std::lock_guard<std::mutex> lock(g_introspect_mtx);
        if (g_introspect_cache.size() >= g_introspect_cache_max) {
            int64_t now = std::time(nullptr);
            for (auto it = g_introspect_cache.begin(); it != g_introspect_cache.end();) {
                if (it->second.expires_at <= now) {
                    it = g_introspect_cache.erase(it);
                } else {
                    ++it;
                }
            }
        }
        if (g_introspect_cache.size() < g_introspect_cache_max) {
            introspect_cache_entry entry;
            entry.expires_at = expires_at;
            entry.result = result;
            g_introspect_cache[token_hash] = entry;
        }
    }

    // F010b: RFC 3986 percent-encode a string (unreserved: A-Za-z0-9-_.~, encode everything else)
    std::string form_urlencode(const std::string & input) {
        std::string result;
        for (unsigned char c : input) {
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
                result += c;
            } else {
                result += '%';
                char hex[3];
                snprintf(hex, sizeof(hex), "%02X", c);
                result += hex;
            }
        }
        return result;
    }

    // F010b: RFC 7662 POST: token=<token> (application/x-www-form-urlencoded), HTTP Basic client auth.
    // https-only, no redirects, short timeouts, 1 MiB body cap, mandatory server-cert verification
    // with optional CA pin. On HTTP 200 returns the response body; any non-200 / redirect / oversize /
    // network error returns false.
    bool introspect_post(const std::string & token, std::string & out_body) {
        if (g_introspect_url.compare(0, 8, "https://") != 0) {
            return false;
        }
        try {
            auto [cli, parts] = common_http_client(g_introspect_url);

            // S1: do NOT follow redirects
            cli.set_follow_location(false);

            // S5: short timeouts
            cli.set_connection_timeout(std::chrono::seconds(g_oidc_http_timeout));
            cli.set_read_timeout(std::chrono::seconds(g_oidc_http_timeout));

            // S5 / S-2: cap response body size (1 MiB)
            const size_t max_body_size = 1024 * 1024;
            cli.set_payload_max_length(max_body_size);

#ifdef CPPHTTPLIB_SSL_ENABLED
            cli.enable_server_certificate_verification(true);  // MANDATORY
            if (!g_oidc_ca_file.empty()) {
                cli.set_ca_cert_path(g_oidc_ca_file);  // optional pin
            }
#endif

            // Client auth: HTTP Basic with client_id and secret
            cli.set_basic_auth(g_introspect_client_id, g_introspect_client_secret);

            // Body: token=<encoded>&token_type_hint=access_token
            std::string form = "token=" + form_urlencode(token) + "&token_type_hint=access_token";

            auto res = cli.Post(parts.path, form, "application/x-www-form-urlencoded");
            if (!res || res->status != 200) {
                return false;
            }

            out_body = res->body;
            return true;
        } catch (const std::exception &) {
            return false;
        }
    }
}

// F009b/F010b: init - config resolution and MANDATORY initial JWKS fetch
bool server_oidc::init(const common_params & params) {
    // Restructured for F010b: JWKS and introspection are independent
    bool jwks_cfg = configured(params);
    bool intro_cfg = introspection_configured(params);
    if (!jwks_cfg && !intro_cfg) {
        return true;  // no-op
    }

    // Note: this whole function is compiled only under CPPHTTPLIB_OPENSSL_SUPPORT (see the
    // #else block below for the no-OpenSSL stub, R6), so no runtime OpenSSL check is needed here.

    // BLOCKER B1 (F010b): audience REQUIRED for BOTH JWKS and introspection paths
    // (the design's section 3.3 note is overridden by section 8.1)
    {
        std::string aud_str = params.oidc_audience;
        if (aud_str.empty()) {
            SRV_ERR("%s", "OIDC: audience is required\n");
            return false;
        }
        std::istringstream iss(aud_str);
        std::string aud;
        g_oidc_audiences.clear();
        while (std::getline(iss, aud, ',')) {
            aud.erase(0, aud.find_first_not_of(" \t"));
            aud.erase(aud.find_last_not_of(" \t") + 1);
            if (!aud.empty()) {
                g_oidc_audiences.push_back(aud);
            }
        }
        if (g_oidc_audiences.empty()) {
            SRV_ERR("%s", "OIDC: at least one audience is required\n");
            return false;
        }
    }

    // CA file assignment (applies to BOTH paths)
    g_oidc_ca_file = params.oidc_ca_file;

    if (jwks_cfg) {
        // JWKS-only path: parse algs, issuer, clock-skew, discovery, mandatory JWKS fetch

        // Step 1: Parse and validate algs
        {
            std::string algs_str = params.oidc_algs.empty() ? "RS256,ES256" : params.oidc_algs;
            std::istringstream iss(algs_str);
            std::string alg;
            g_oidc_algs.clear();
            while (std::getline(iss, alg, ',')) {
                // Trim whitespace
                alg.erase(0, alg.find_first_not_of(" \t"));
                alg.erase(alg.find_last_not_of(" \t") + 1);

                // Check for invalid algs
                if (alg == "none" || alg.substr(0, 2) == "HS") {
                    SRV_ERR("OIDC: algorithm %s not allowed (none and HS* rejected)\n", alg.c_str());
                    return false;
                }
                // Only allow RS256/384/512 and ES256/384/512
                if (alg != "RS256" && alg != "RS384" && alg != "RS512" &&
                    alg != "ES256" && alg != "ES384" && alg != "ES512") {
                    SRV_ERR("OIDC: unsupported algorithm %s\n", alg.c_str());
                    return false;
                }
                g_oidc_algs.insert(alg);
            }
        }

        // Step 2: Validate issuer (C1: ALWAYS required for JWKS path)
        if (params.oidc_issuer.empty()) {
            SRV_ERR("%s", "OIDC: issuer is required (C1)\n");
            return false;
        }
        g_oidc_issuer = params.oidc_issuer;

        // Step 3: Resolve JWKS URL
        if (!params.oidc_jwks_url.empty()) {
            g_jwks_url = params.oidc_jwks_url;
        } else {
            // DISCOVERY: GET {issuer_without_trailing_slash}/.well-known/openid-configuration
            // via the same hardened helper as the JWKS fetch (S1: https-only + no
            // redirects; S5: timeouts + body size cap).
            std::string disc_url = g_oidc_issuer;
            if (!disc_url.empty() && disc_url.back() == '/') {
                disc_url.pop_back();
            }
            disc_url += "/.well-known/openid-configuration";

            std::string disc_body;
            int64_t unused_max_age = 0;
            if (!https_get(disc_url, disc_body, unused_max_age)) {
                SRV_ERR("OIDC: discovery failed for %s\n", disc_url.c_str());
                return false;
            }

            // Parse and extract jwks_uri
            try {
                nlohmann::json disc_json = nlohmann::json::parse(disc_body);
                if (!disc_json.contains("jwks_uri") || !disc_json["jwks_uri"].is_string()) {
                    SRV_ERR("%s", "OIDC: discovery response missing jwks_uri\n");
                    return false;
                }
                // C-2: OIDC Discovery mandates the discovery doc's issuer match the
                // configured issuer exactly - fail closed on mismatch (or absence)
                // rather than trusting whatever jwks_uri a spoofed/compromised
                // discovery response points at.
                if (!disc_json.contains("issuer") || !disc_json["issuer"].is_string() ||
                    disc_json["issuer"] != g_oidc_issuer) {
                    SRV_ERR("%s", "OIDC: discovery response issuer mismatch\n");
                    return false;
                }
                g_jwks_url = disc_json["jwks_uri"];
            } catch (...) {
                SRV_ERR("%s", "OIDC: discovery JSON parse failed\n");
                return false;
            }
        }

        // Verify JWKS URL is https (also covers the explicit --oidc-jwks-url path,
        // which does not go through https_get() until the fetch itself)
        if (g_jwks_url.substr(0, 8) != "https://") {
            SRV_ERR("OIDC: JWKS URL must be https (got %s)\n", g_jwks_url.c_str());
            return false;
        }

        // Step 4: Clock skew validation
        if (params.oidc_clock_skew < 0 || params.oidc_clock_skew > 300) {
            SRV_ERR("OIDC: clock-skew out of range [0,300]: %d\n", params.oidc_clock_skew);
            return false;
        }
        g_oidc_clock_skew = params.oidc_clock_skew;

        // Step 5: Read test-only env vars (S4) for TTL/rate-limit overrides. A malformed
        // value is ignored (default kept) - init() must never throw.
        {
            const char * ttl_env = std::getenv("LLAMA_OIDC_JWKS_TTL_SECONDS");
            if (ttl_env) {
                try {
                    int ttl = std::stoi(ttl_env, nullptr, 10);
                    if (ttl >= 0) g_jwks_ttl_fallback = ttl;
                } catch (...) {
                    // malformed -> keep default
                }
            }
        }
        {
            const char * window_env = std::getenv("LLAMA_OIDC_UNKNOWN_KID_WINDOW_SECONDS");
            if (window_env) {
                try {
                    int window = std::stoi(window_env, nullptr, 10);
                    if (window >= 0) g_unknown_kid_window = window;
                } catch (...) {
                    // malformed -> keep default
                }
            }
        }
        {
            const char * refresh_min_env = std::getenv("LLAMA_OIDC_JWKS_REFRESH_MIN_INTERVAL_SECONDS");
            if (refresh_min_env) {
                try {
                    int min_interval = std::stoi(refresh_min_env, nullptr, 10);
                    if (min_interval >= 0) g_jwks_refresh_min_interval = min_interval;
                } catch (...) {
                    // malformed -> keep default
                }
            }
        }
        {
            const char * ceiling_env = std::getenv("LLAMA_OIDC_JWKS_TTL_CEILING_SECONDS");
            if (ceiling_env) {
                try {
                    long long ceiling = std::stoll(ceiling_env, nullptr, 10);
                    if (ceiling > 0) g_jwks_ttl_ceiling = ceiling;
                } catch (...) {
                    // malformed -> keep default
                }
            }
        }

        // Step 6: MANDATORY initial JWKS fetch (fail-closed at boot per PLAN 4.2c, OQ2)
        {
            std::lock_guard<std::mutex> lock(g_jwks_mtx);
            if (!refresh_jwks()) {
                SRV_ERR("%s", "OIDC: initial JWKS fetch failed\n");
                return false;
            }
        }
    }

    if (intro_cfg) {
        // F010b: Introspection-only path: validate config and read secret from file

        // Validate introspection URL (HTTPS required)
        g_introspect_url = params.oidc_introspection_url;
        if (g_introspect_url.compare(0, 8, "https://") != 0) {
            SRV_ERR("%s", "OIDC introspection: URL must be https\n");
            return false;
        }

        // R9: Reject userinfo in URL (@ in authority = secret leak vector)
        size_t slashes = g_introspect_url.find("://");
        if (slashes != std::string::npos) {
            size_t auth_end = g_introspect_url.find('/', slashes + 3);
            std::string authority = g_introspect_url.substr(slashes + 3,
                (auth_end == std::string::npos) ? std::string::npos : auth_end - slashes - 3);
            if (authority.find('@') != std::string::npos) {
                SRV_ERR("%s", "OIDC introspection: userinfo in URL is not supported; use --oidc-client-id/--oidc-client-secret-file\n");
                return false;
            }
        }

        // Validate and store client_id (R9: reject ':' and non-printable)
        g_introspect_client_id = params.oidc_client_id;
        if (g_introspect_client_id.empty()) {
            SRV_ERR("%s", "OIDC introspection: client_id is required\n");
            return false;
        }
        for (unsigned char c : g_introspect_client_id) {
            if (c < 0x21 || c > 0x7E || c == ':') {
                SRV_ERR("%s", "OIDC introspection: client_id contains invalid characters (must be printable ASCII, no ':')\n");
                return false;
            }
        }

        // Read secret from file (R9: binary read, strip CR/LF, reject interior newline)
        if (params.oidc_client_secret_file.empty()) {
            SRV_ERR("%s", "OIDC introspection: client_secret_file is required\n");
            return false;
        }
        std::ifstream secret_file(params.oidc_client_secret_file, std::ios::binary);
        if (!secret_file.is_open()) {
            SRV_ERR("OIDC introspection: cannot open secret file: %s\n", params.oidc_client_secret_file.c_str());
            return false;
        }
        std::string secret((std::istreambuf_iterator<char>(secret_file)), std::istreambuf_iterator<char>());
        secret_file.close();

        // Strip trailing CR/LF
        while (!secret.empty() && (secret.back() == '\r' || secret.back() == '\n')) {
            secret.pop_back();
        }

        // Check for interior newline (fail-closed - likely the wrong file)
        if (secret.find('\n') != std::string::npos || secret.find('\r') != std::string::npos) {
            SRV_ERR("%s", "OIDC introspection: secret file contains interior newline (malformed)\n");
            return false;
        }

        // R9: Validate secret contains only printable ASCII
        if (secret.empty()) {
            SRV_ERR("%s", "OIDC introspection: secret file is empty\n");
            return false;
        }
        for (unsigned char c : secret) {
            if (c < 0x21 || c > 0x7E) {
                SRV_ERR("%s", "OIDC introspection: secret contains invalid characters (must be printable ASCII)\n");
                return false;
            }
        }

        g_introspect_client_secret = secret;

        // Read test-only env vars for introspection rate limit (R8)
        {
            const char * pos_ttl_env = std::getenv("LLAMA_OIDC_INTROSPECT_POS_TTL_SECONDS");
            if (pos_ttl_env) {
                try {
                    int ttl = std::stoi(pos_ttl_env, nullptr, 10);
                    if (ttl >= 0) g_introspect_max_pos_ttl = ttl;
                } catch (...) {
                    // malformed -> keep default
                }
            }
        }
        {
            const char * neg_ttl_env = std::getenv("LLAMA_OIDC_INTROSPECT_NEG_TTL_SECONDS");
            if (neg_ttl_env) {
                try {
                    int ttl = std::stoi(neg_ttl_env, nullptr, 10);
                    if (ttl >= 0) g_introspect_neg_ttl = ttl;
                } catch (...) {
                    // malformed -> keep default
                }
            }
        }
        {
            const char * max_per_sec_env = std::getenv("LLAMA_OIDC_INTROSPECT_MAX_PER_SECOND");
            if (max_per_sec_env) {
                try {
                    int max_ps = std::stoi(max_per_sec_env, nullptr, 10);
                    if (max_ps >= 0) g_introspect_max_per_sec = max_ps;
                } catch (...) {
                    // malformed -> keep default
                }
            }
        }

        g_introspect_configured = true;
    }

    return true;
}

// F009b: Get a public-key PEM from the cache by kid (S3: returned by value, not reference)
static std::optional<std::string> jwks_get_key(const std::string & kid) {
    std::lock_guard<std::mutex> lock(g_jwks_mtx);

    int64_t now = std::time(nullptr);

    // Check if cache is expired
    if (now >= g_jwks_cache.expires_at) {
        // S-1: rate-limit refresh ATTEMPTS, not just successes - once expires_at
        // is in the past, every validate() would otherwise re-enter refresh_jwks()
        // (a blocking HTTPS GET under g_jwks_mtx) on every single request while the
        // IdP is down. Fail-static: keep serving the stale cache between attempts.
        if (now - g_jwks_cache.last_refresh >= g_jwks_refresh_min_interval) {
            refresh_jwks();
        }
    }

    // If kid is known, look up the cached PEM
    // Two-level gate: check kids first (outer condition must stay, for oct-key security invariant)
    if (g_jwks_cache.kids.count(kid)) {
        auto it = g_jwks_cache.pems.find(kid);
        if (it != g_jwks_cache.pems.end()) {
            // S3: return by value (copy)
            return it->second;
        }
        // kid is known but has no PEM (e.g., oct symmetric key) -> reject
        return std::nullopt;
    }

    // Unknown kid: rate-limited refresh
    int64_t jitter = g_rng() % 31;  // 0..30 seconds
    int64_t refresh_window = g_unknown_kid_window + jitter;
    if (now - g_jwks_cache.last_unknown_kid_refresh >= refresh_window) {
        g_jwks_cache.last_unknown_kid_refresh = now;
        refresh_jwks();

        // Retry the lookup after refresh
        if (g_jwks_cache.kids.count(kid)) {
            auto it = g_jwks_cache.pems.find(kid);
            if (it != g_jwks_cache.pems.end()) {
                return it->second;
            }
        }
    }

    return std::nullopt;
}

// F009c: JWT verification core (fixed order per design section 4.3)
oidc_validation server_oidc::validate(const std::string & token) {
    oidc_validation v;
    v.ok = false;

    // Step 1: Shape check (cheap reject before any parse)
    if (!looks_like_jwt(token)) {
        v.error = "malformed";
        return v;
    }

    try {
        // Step 2: Decode header + payload (NO signature check yet)
        auto decoded = jwt::decode<traits>(token);

        // Step 3: Extract alg + kid from header
        if (!decoded.has_algorithm()) {
            v.error = "no alg";
            return v;
        }
        std::string alg = decoded.get_algorithm();

        if (!decoded.has_key_id()) {
            v.error = "no kid";
            return v;
        }
        std::string kid = decoded.get_key_id();

        // Step 4: ALG WHITELIST (our guard against algorithm confusion)
        if (alg == "none" || alg.substr(0, 2) == "HS") {
            v.error = "alg not allowed";
            return v;
        }
        if (g_oidc_algs.count(alg) == 0) {
            v.error = "alg not allowed";
            return v;
        }

        // Step 5: Resolve signing key by kid (rate-limited refresh on miss)
        auto pem_opt = jwks_get_key(kid);
        if (!pem_opt) {
            v.error = "unknown kid";
            return v;
        }
        std::string pem = *pem_opt;

        // Step 6: Build verifier with PINNED 6-way switch (S2: only asymmetric, no HMAC/none)
        auto verifier = jwt::verify<traits>()
            .leeway(g_oidc_clock_skew)
            .with_issuer(g_oidc_issuer);

        // CRITICAL: Bind exactly one algorithm from the whitelist
        if (alg == "RS256") {
            verifier.allow_algorithm(jwt::algorithm::rs256{pem, "", "", ""});
        } else if (alg == "RS384") {
            verifier.allow_algorithm(jwt::algorithm::rs384{pem, "", "", ""});
        } else if (alg == "RS512") {
            verifier.allow_algorithm(jwt::algorithm::rs512{pem, "", "", ""});
        } else if (alg == "ES256") {
            verifier.allow_algorithm(jwt::algorithm::es256{pem, "", "", ""});
        } else if (alg == "ES384") {
            verifier.allow_algorithm(jwt::algorithm::es384{pem, "", "", ""});
        } else if (alg == "ES512") {
            verifier.allow_algorithm(jwt::algorithm::es512{pem, "", "", ""});
        } else {
            // Should be unreachable after step 4
            v.error = "alg not allowed";
            return v;
        }

        // Verify signature, iss, exp/nbf/iat
        verifier.verify(decoded);

        // Step 7: AUDIENCE containment (our check, not jwt-cpp's with_audience)
        auto aud_set = decoded.get_audience();
        bool aud_match = false;
        for (const auto & configured_aud : g_oidc_audiences) {
            if (aud_set.count(configured_aud)) {
                aud_match = true;
                break;
            }
        }
        if (!aud_match) {
            v.error = "aud mismatch";
            return v;
        }

        // Step 8: Optional typ == "at+jwt"
        if (g_oidc_require_typ) {
            if (!decoded.has_type() || decoded.get_type() != "at+jwt") {
                v.error = "typ mismatch";
                return v;
            }
        }

        // Step 9: Success - fill result fields
        if (!decoded.has_subject()) {
            v.error = "no sub";
            return v;
        }
        v.subject = decoded.get_subject();
        v.issuer = g_oidc_issuer;  // verified by with_issuer

        if (!decoded.has_expires_at()) {
            v.error = "no exp";
            return v;
        }
        auto exp_timepoint = decoded.get_expires_at();
        v.expires_at = std::chrono::system_clock::to_time_t(exp_timepoint);

        // Get payload as JSON string (already parsed by jwt-cpp, we just get it back as string)
        v.claims_json = decoded.get_payload();

        v.ok = true;
        return v;
    } catch (...) {
        // Any jwt-cpp exception (bad sig, bad iss, expired exp, etc.) -> deny
        v.error = "verify failed";
        v.ok = false;
        return v;
    }
}

// F009c: Setter for require_at_jwt_typ (called from server-auth::init)
void server_oidc::set_require_typ(bool require_typ) {
    g_oidc_require_typ = require_typ;
}

// F015: Return JWKS refresh counter values
void server_oidc::jwks_refresh_counts(uint64_t & out_success, uint64_t & out_failure) {
    out_success = g_jwks_refresh_success.load(std::memory_order_relaxed);
    out_failure = g_jwks_refresh_failure.load(std::memory_order_relaxed);
}

// F010b: Introspect one opaque bearer token via RFC 7662
oidc_validation server_oidc::introspect(const std::string & token) {
    oidc_validation v;
    v.ok = false;

    if (!g_introspect_configured) {
        return v;
    }

    // B2: Pre-flight rejection with NO network call and NO cache write
    // Token length check (4096 bytes max)
    if (token.length() > 4096) {
        return v;
    }

    // Token charset check (RFC 6750 b64token + trailing '=': [A-Za-z0-9._~+/-=])
    for (unsigned char c : token) {
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '~' ||
              c == '+' || c == '/' || c == '-' || c == '=')) {
            return v;
        }
    }

    // Token hash for cache key
    std::string token_hash = sha256_hex(token);
    int64_t now = std::time(nullptr);

    // B2: Cache lookup and rate-limit accounting under mutex
    {
        std::lock_guard<std::mutex> lock(g_introspect_mtx);

        // Cache lookup: if entry exists and not expired, return it
        auto it = g_introspect_cache.find(token_hash);
        if (it != g_introspect_cache.end()) {
            if (now < it->second.expires_at) {
                // Cache hit (positive or negative)
                return it->second.result;
            }
        }

        // B2: Rate limiting (fixed-window counter)
        if (now != g_introspect_window_start) {
            g_introspect_window_start = now;
            g_introspect_window_count = 0;
        }
        if (++g_introspect_window_count > g_introspect_max_per_sec) {
            // Rate limit exceeded: deny without caching
            return v;
        }
    }

    // B2: POST issued WITHOUT holding mutex (do not serialize request threads on network call)
    std::string body;
    if (!introspect_post(token, body)) {
        // Network/endpoint failure: do NOT cache, return false
        return v;
    }

    // Parse response (RFC 7662)
    try {
        nlohmann::json resp = nlohmann::json::parse(body);
        bool active = resp.value("active", false);

        if (!active) {
            // Inactive token: cache negative result
            introspect_cache_insert(token_hash, v, now + g_introspect_neg_ttl);
            return v;
        }

        // Active token: validate required fields

        // BLOCKER B1: Check aud (string or array must intersect configured audiences)
        {
            bool aud_match = false;
            if (resp.contains("aud")) {
                try {
                    auto aud_val = resp["aud"];
                    std::vector<std::string> resp_auds;
                    if (aud_val.is_string()) {
                        resp_auds.push_back(aud_val.get<std::string>());
                    } else if (aud_val.is_array()) {
                        for (const auto & elem : aud_val) {
                            if (elem.is_string()) {
                                resp_auds.push_back(elem.get<std::string>());
                            }
                        }
                    }
                    // Check intersection with g_oidc_audiences
                    for (const auto & r_aud : resp_auds) {
                        if (std::find(g_oidc_audiences.begin(), g_oidc_audiences.end(), r_aud) != g_oidc_audiences.end()) {
                            aud_match = true;
                            break;
                        }
                    }
                } catch (...) {
                    // aud parsing failed -> no match
                }
            }
            if (!aud_match) {
                // Aud mismatch: cache as negative
                introspect_cache_insert(token_hash, v, now + g_introspect_neg_ttl);
                return v;
            }
        }

        // BLOCKER B1: Check iss (if issuer is configured, response iss must match)
        if (!g_oidc_issuer.empty()) {
            std::string resp_iss = resp.value("iss", "");
            if (resp_iss != g_oidc_issuer) {
                // Issuer mismatch: cache as negative
                introspect_cache_insert(token_hash, v, now + g_introspect_neg_ttl);
                return v;
            }
        }

        // BLOCKER B1: Clock checks on the response
        int64_t exp = resp.value("exp", (int64_t)0);
        int64_t nbf = resp.value("nbf", (int64_t)0);
        if (exp != 0 && exp + g_oidc_clock_skew <= now) {
            // Token already expired
            introspect_cache_insert(token_hash, v, now + g_introspect_neg_ttl);
            return v;
        }
        if (nbf != 0 && nbf > now + g_oidc_clock_skew) {
            // Token not yet valid
            introspect_cache_insert(token_hash, v, now + g_introspect_neg_ttl);
            return v;
        }

        // Extract subject (required)
        std::string sub = resp.value("sub", "");
        if (sub.empty()) {
            // No subject: cache as negative
            introspect_cache_insert(token_hash, v, now + g_introspect_neg_ttl);
            return v;
        }

        // R11: Set issuer (configured issuer if set, else literal constant)
        v.subject = sub;
        v.issuer = g_oidc_issuer.empty() ? "oidc-introspection" : g_oidc_issuer;
        v.expires_at = exp;
        v.claims_json = resp.dump();
        v.ok = true;

        // Cache positive result with TTL <= min(exp - now, max_pos_ttl)
        int64_t ttl = g_introspect_max_pos_ttl;
        if (exp > 0) {
            ttl = std::min<int64_t>(ttl, exp - now);
        }
        if (ttl < 0) ttl = 0;

        introspect_cache_insert(token_hash, v, now + ttl);

        return v;
    } catch (...) {
        // JSON parse error: do NOT cache, return false
        return v;
    }
}

#else

// No OpenSSL build: fail-closed stubs

bool server_oidc::init(const common_params & params) {
    // R6: Check BOTH JWKS and introspection configuration
    bool jwks_cfg = configured(params);
    bool intro_cfg = introspection_configured(params);
    if (!jwks_cfg && !intro_cfg) {
        return true;
    }
    SRV_ERR("%s", "OIDC: requires an OpenSSL-enabled build\n");
    return false;
}

oidc_validation server_oidc::validate(const std::string & token) {
    (void)token;
    oidc_validation v;
    v.ok = false;
    v.error = "no openssl";
    return v;
}

oidc_validation server_oidc::introspect(const std::string & token) {
    (void)token;
    oidc_validation v;
    v.ok = false;
    return v;
}

void server_oidc::set_require_typ(bool require_typ) {
    (void)require_typ;
}

void server_oidc::jwks_refresh_counts(uint64_t & out_success, uint64_t & out_failure) {
    out_success = 0;
    out_failure = 0;
}

#endif
