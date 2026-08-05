# PR4 design: OIDC JWT (access-token) validation

Status: in_design
Features: F009a (jwt-cpp vendor + CMake + flags/params + server-oidc skeleton),
F009b (JWKS discovery/fetch/cache + rate-limited refresh), F009c (JWT verification core),
F009d (roles-claim + policy oidc parse + resolve_principal branch + init enforcement-flip).

This document is the implementation contract for a Haiku-class coder. Every non-obvious
decision is settled here. Do not invent behavior that is not written down; if something is
missing, stop and ask the architect.

ASCII only in all code and docs (AGENTS.md): no em-dash, no unicode arrows, use `-` and `->`.

PR4 builds on merged PR1 (docs/design/pr1-rbac-core.md), PR2 (pr2-principal-proxy.md), and PR3
(pr3-mtls.md). It reuses those conventions verbatim: all policy logic in server-auth.{h,cpp}; a
NEW file pair server-oidc.{h,cpp} owns JWT/JWKS crypto; existing files get call sites only; fail
closed; deny-by-default; NO hand-rolled crypto (jwt-cpp does the JWT parse + signature verify).

--------------------------------------------------------------------------------
## 0. Scope and non-goals

llama-server is a RESOURCE SERVER only (PLAN.md section 9): it validates OIDC ACCESS tokens
(JWT) presented as `Authorization: Bearer`. It is NOT a relying party: no authorization-code
flow, no callback endpoint, no sessions, no cookies, no browser redirect. WebUI PKCE is PR5.

In scope for PR4:
- Vendor jwt-cpp (header-only) configured with the already-vendored nlohmann/json traits.
- server-oidc.{h,cpp}: JWKS URL resolution (discovery from `--oidc-issuer` OR explicit
  `--oidc-jwks-url`), a JWKS HTTPS client with mandatory server-cert verification, a JWKS cache
  with TTL + fail-static + rate-limited unknown-kid refresh, and local JWT verification in a
  fixed, testable order (alg whitelist + none/HS rejection are OURS; signature/iss/exp are
  jwt-cpp's).
- Wire OIDC into `resolve_principal` as a Bearer-token branch with `AUTH_OIDC`, mapping a
  configurable roles claim to local roles via a new policy `oidc` section; unmapped -> deny.
- Flip enforcement to deny-by-default when OIDC is configured, reusing the exact S1-style
  init invariant that mTLS/trusted-proxy already use.

Explicitly NOT in PR4 (do not implement, do not add fields/flags for these):
- RFC 7662 opaque-token introspection, `--oidc-introspection-url`, `--oidc-client-id`,
  `--oidc-client-secret-file` (PLAN.md 4.4/4.5). DEFERRED to PR5 (F010). PR4 needs NO secrets.
- WebUI PKCE public client (PR5).
- Cutting an in-flight SSE stream when the token `exp` passes mid-stream (PLAN.md 8.4). PR4
  POPULATES `principal.expires_at` from `exp` but does NOT check it in the generation loop.
  Documented residual risk; enforcing it is a later PR.
- A background JWKS refresh thread. PR4 refresh is LAZY on the request path (single-flight under
  a mutex), which removes a thread-lifetime/shutdown concern. Documented; a background refresher
  is deferred.

Hard rules (CLAUDE.md) honored:
- Fail closed: OIDC configured but misconfigured, no OpenSSL build, or the initial JWKS fetch
  fails -> `server_auth::init` returns false and the server aborts (PLAN.md 4.2c).
- No hand-rolled crypto: jwt-cpp parses the JWT and verifies the signature; the JWKS JSON parse
  and JWK->public-key conversion use jwt-cpp helpers. Our own code does string/shape checks, the
  alg whitelist, and role mapping only.
- No secrets on argv: pure JWT validation needs no client secret. Only URLs, a CA path, an alg
  list, and an integer skew are passed.
- Minimize footprint in existing files: server-http.cpp is UNCHANGED for PR4 (the middleware
  already reads `Authorization` into the DTO); server-auth.cpp gets the `resolve_principal`
  branch, the policy `oidc` parse, the enforcement flip, and the `AUTH_OIDC` audit string; all
  JWT/JWKS code is in server-oidc.cpp.

--------------------------------------------------------------------------------
## 1. Discrepancies between PLAN.md / the task framing and the current code

Anchors verified on branch `master` after PR3 merged (real line numbers).

| PLAN.md / task claim | Reality (verified) | Impact |
|---|---|---|
| jwt-cpp lives in `vendor/jwt-cpp/` (repo root); F009 `files` says the same | Repo convention is `tools/server/vendor/` (the SHA-256 vendor lives at `tools/server/vendor/sha256.*`). nlohmann/json is repo-root `vendor/nlohmann/json.hpp`, reachable as `<nlohmann/json.hpp>` because `common/CMakeLists.txt:129` adds `../vendor` PUBLIC and llama-server-impl links llama-common transitively. | Vendor jwt-cpp at `tools/server/vendor/jwt-cpp/`; its nlohmann traits `#include <nlohmann/json.hpp>` resolves with NO extra include dir. Corrected in features.json `files`. |
| JWKS client = `common/http.h` + `httplib::SSLClient` directly | `common/http.h` exposes `common_http_client(url)` returning `std::pair<httplib::Client, common_http_url>` (http.h:100). The `Client` facade wraps SSLClient for https and exposes `set_ca_cert_path` / `enable_server_certificate_verification` under `CPPHTTPLIB_SSL_ENABLED` (httplib.h:3985-3988). It THROWS on https without OpenSSL (http.h:107-116 = fail closed). | Reuse `common_http_client`; do not hand-roll an SSLClient. Set the CA + verification explicitly (section 4.2). |
| `--oidc-ca-file` is a MANDATORY explicit CA bundle (PLAN 4.4) | Requiring a CA path on every deployment is a footgun where the system store is correct. | DEVIATION (settled, flag OQ4-style note): `--oidc-ca-file` is OPTIONAL; when set it PINS verification to that CA, when unset verification stays ON against the system/default CA store (`enable_server_certificate_verification(true)`). Verification is NEVER disableable. Documented in the flag help. |
| `server_auth_method` needs `AUTH_OIDC` | enum is `{ AUTH_NONE, AUTH_API_KEY, AUTH_TRUSTED_PROXY, AUTH_MTLS }` (server-auth.h:30); `auth_method_to_string` has cases through `AUTH_MTLS` (server-auth.cpp:383-391) | Append `AUTH_OIDC` (stable values); add the `"oidc"` case. |
| policy has an `oidc` section (PLAN 4.1 default policy) | `server_auth::init` parses `roles`, `public_endpoints`, `mtls`, `default_role`, `api_keys` - it does NOT parse `oidc` (grep: zero `oidc` hits in server-auth.cpp) | F009d adds the `oidc` parse next to the `mtls` parse (server-auth.cpp:711-789). |
| resolve_principal precedence "mTLS -> trusted-proxy -> api-key" | Real: resolve_principal at server-auth.cpp:933; mTLS branch 937-957; trusted-proxy 962-978; API-key 980-1009; anonymous 1012. | OIDC branch inserts AFTER trusted-proxy (978) and BEFORE API-key (980). New chain: mTLS -> trusted-proxy -> OIDC -> API-key -> anonymous (section 5.3). |
| init enforcement flip anchors | Real: auth-disabled early return `else if (!has_api_keys && !has_trusted_proxies && !has_mtls)` at server-auth.cpp:657; `g_auth_enabled = has_policy_file \|\| has_api_keys \|\| has_trusted_proxies \|\| has_mtls;` at 669; S1 mTLS guard `if (has_mtls && !g_auth_enabled) return false;` at 857. | Add `!has_oidc` to 657, OR `has_oidc` into 669, add the parallel S1 OIDC guard after 860 (section 5.4). |
| server.cpp init hook | `server_auth::init(params)` at server.cpp:179 (single call, after `ctx_http.init` at 173). | server_oidc::init is called FROM inside server_auth::init; NO server.cpp change. |

None of these blocks the design. The load-bearing corrections: vendor path is under
`tools/server/`, `--oidc-ca-file` is optional (verification always on), and the JWKS client is
the `common_http_client` facade, not a raw SSLClient.

--------------------------------------------------------------------------------
## 2. Dependency: vendor jwt-cpp (F009a) - OQ1

Decision (flag as OQ1 for the challenger): use jwt-cpp (header-only, MIT) rather than a
hand-rolled `EVP_DigestVerify`. PLAN.md 4.4/9 mandates jwt-cpp; a hand-rolled path would mean
writing our own base64url + JWK->EVP_PKEY + signature dispatch, i.e. MORE of our own crypto,
which the hard rules forbid. jwt-cpp is the vendored library's tested code.

Vendoring:
- Place the jwt-cpp `include/` tree at `tools/server/vendor/jwt-cpp/` (header-only; nothing to
  compile). Pin a released tag (target v0.7.x - the challenger confirms the exact tag in OQ1);
  keep the upstream `LICENSE` file alongside it.
- Configure jwt-cpp to use nlohmann/json (already vendored), NOT its bundled picojson:
  - In server-oidc.cpp, BEFORE including jwt-cpp: `#define JWT_DISABLE_PICOJSON`.
  - Include the nlohmann traits: `#include <jwt-cpp/traits/nlohmann-json/traits.h>` then
    `#include <jwt-cpp/jwt.h>`. The traits header does `#include <nlohmann/json.hpp>`, which
    already resolves (section 1). Use the `jwt::traits::nlohmann_json` trait type throughout
    (`jwt::decode<traits>`, `jwt::verify<...>`, `jwt::jwks<traits>`).
- jwt-cpp requires a TLS backend (OpenSSL). This build has OpenSSL via cpp-httplib, which defines
  `CPPHTTPLIB_OPENSSL_SUPPORT` PUBLICLY and links OpenSSL (see pr3-mtls.md section 1). So all
  jwt-cpp usage in server-oidc.cpp is gated on `#ifdef CPPHTTPLIB_OPENSSL_SUPPORT`; the `#else`
  branch makes `server_oidc::init` return false when OIDC is configured (fail closed) and
  `validate` return `ok=false`. This mirrors server-mtls.cpp exactly.

CMake wiring (tools/server/CMakeLists.txt, in the `llama-server-impl` target, next to the
server-mtls entries at CMakeLists.txt:46-47):
- Add sources `server-oidc.cpp` and `server-oidc.h`.
- Add `target_include_directories(${TARGET} PRIVATE vendor/jwt-cpp/include)` (so
  `<jwt-cpp/jwt.h>` and `<jwt-cpp/traits/nlohmann-json/traits.h>` resolve).
- NO new link libraries: OpenSSL is already linked transitively via `cpp-httplib`.
- NO new CMake option. Do NOT add `LLAMA_SERVER_OIDC` (PR3 set the precedent: mTLS added no
  option and gates on the OpenSSL macro at compile time and on the flags at run time). OIDC
  code compiles always; it is inert unless the flags are set, and refuses to start (fail closed)
  if the flags are set on a no-OpenSSL build.

--------------------------------------------------------------------------------
## 3. server-oidc.h contract (F009a)

server-oidc.h stays free of jwt-cpp / OpenSSL / httplib types (like server-mtls.h): only
std types cross the boundary. The verified claims come back as a JSON STRING so the header does
not need nlohmann; server-auth re-parses it for role extraction (cheap; the payload is small and
was already parsed by jwt-cpp - re-parse can only fail on our own re-serialization, treated as
fail-closed).

```cpp
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
};
```

--------------------------------------------------------------------------------
## 4. server-oidc.cpp internals

### 4.1 Config resolution (server_oidc::init, F009b)

Read from `common_params` (section 6):
- `oidc_issuer`, `oidc_jwks_url`, `oidc_audience` (comma list), `oidc_algs` (comma list, default
  `RS256,ES256`), `oidc_ca_file`, `oidc_clock_skew` (int, default 60).

Steps (fail closed on any error; each is `SRV_ERR` + `return false`):
1. If not `configured(params)` -> return true (no-op).
2. `#ifndef CPPHTTPLIB_OPENSSL_SUPPORT` -> `SRV_ERR("OIDC requires an OpenSSL-enabled build")`;
   return false.
3. Parse `oidc_algs` into a set; every entry must be one of `RS256,RS384,RS512,ES256,ES384,ES512`
   (the asymmetric algs jwt-cpp supports). `none` or any `HS*` in the list -> fail (an operator
   must never whitelist a symmetric alg for JWKS keys). Empty list -> default `{RS256,ES256}`.
4. Parse `oidc_audience` (comma list via the existing split helper) into `g_oidc_audiences`.
   Empty -> fail: audience checking is mandatory (an access token without an intended audience is
   not verifiable). (Issuer may be empty ONLY if `--oidc-jwks-url` is set AND we skip discovery;
   but iss verification then cannot run -> see step 5.)
5. **`--oidc-issuer` is ALWAYS required (C1, adopted).** An empty `oidc_issuer` -> `SRV_ERR` +
   return false, EVEN when `--oidc-jwks-url` is set. Rationale: if the issuer is empty, `iss`
   verification is skipped, and when a JWKS is shared across issuers/tenants a token from a
   different issuer signed by a key that happens to be in that JWKS would pass. Requiring the
   issuer removes that footgun. Resolve the JWKS URL and store `g_oidc_issuer = oidc_issuer`
   (now guaranteed non-empty, so `with_issuer` always runs in validate):
   - If `oidc_jwks_url` set -> `g_jwks_url = oidc_jwks_url` (discovery skipped).
   - Else -> DISCOVERY: GET `{issuer_without_trailing_slash}/.well-known/openid-configuration`,
     parse JSON, read `jwks_uri` (string, required) -> `g_jwks_url`. A failed or malformed
     discovery response -> fail.
   - Clamp `oidc_clock_skew` to `[0, 300]`; a value > 300 -> fail (a huge skew defeats exp/nbf).
6. Read the S4 test-only env vars (`g_jwks_ttl_fallback`, `g_unknown_kid_window`) and set
   `g_oidc_http_timeout` (default 5s).
7. Initial MANDATORY JWKS fetch (section 4.2). On failure -> fail (PLAN 4.2c). On success the
   cache holds the keys and its expiry.

Store resolved config in file-scope `namespace {}` state (mirrors server-auth.cpp style):
`g_oidc_configured`, `g_oidc_issuer` (non-empty), `g_jwks_url`, `g_oidc_ca_file`,
`g_oidc_audiences` (vector<string>), `g_oidc_algs` (set<string>), `g_oidc_clock_skew` (int),
`g_oidc_http_timeout` (int seconds), `g_jwks_ttl_fallback` (int, S4), `g_unknown_kid_window`
(int, S4), and `g_oidc_require_typ` (bool, set via `set_require_typ`).

### 4.2 JWKS client + cache + refresh (F009b)

HTTP client: reuse `common_http_client(url)` from common/http.h. After building the client:
```
auto [cli, parts] = common_http_client(url);      // throws on https-without-OpenSSL -> caught, fail
cli.set_follow_location(false);                   // S1: NEVER follow redirects (see below)
cli.set_connection_timeout(g_oidc_http_timeout);  // S5: short, e.g. 5s
cli.set_read_timeout(g_oidc_http_timeout);        // S5: short, e.g. 5s
#ifdef CPPHTTPLIB_SSL_ENABLED
if (parts.scheme == "https") {
    cli.enable_server_certificate_verification(true);   // MANDATORY, never disabled
    if (!g_oidc_ca_file.empty()) cli.set_ca_cert_path(g_oidc_ca_file);  // pin; else system store
}
#endif
```
- **S1 (SSRF + TLS downgrade guard - load-bearing).** `common_http_client` calls
  `set_follow_location(true)` unconditionally (common/http.h:124). Our https-only check inspects
  only the operator-configured URL string, so a compromised or malicious IdP could answer the
  JWKS/discovery GET with `302 -> http://169.254.169.254/...` (cloud metadata) or an internal
  host, and httplib would follow it to a plaintext/internal target on the boot/request thread -
  blind SSRF and a downgrade past the https-only gate. We therefore FORCE
  `cli.set_follow_location(false)`: a redirect is treated as a fetch FAILURE (a well-behaved IdP
  serves JWKS/discovery directly, no redirect). Do NOT re-enable redirects.
- **S5 (slow/hostile IdP guard).** `common_http_client` sets no timeouts; with the hard-fail-at-
  boot posture (OQ2), an IdP that accepts TCP but never responds would hang `server_auth::init`
  (server.cpp:179) before the server ever listens. Set a short explicit connection AND read
  timeout (`g_oidc_http_timeout`, default 5s) and treat a timeout as a fetch failure (fail closed
  at boot / fail-static at runtime). Also cap the response body: if the JWKS/discovery body
  exceeds a sane limit (e.g. 1 MiB) treat the fetch as failed, so a hostile IdP cannot OOM the
  process by streaming an unbounded body.
- A plain `http://` JWKS/discovery URL is REJECTED at init (`SRV_ERR`): JWKS/discovery MUST be
  https (fail closed against a downgrade/MITM). This is stricter than common_http_client (which
  allows http) and is our responsibility.
- `cli.Get(path)`; a redirect (3xx), a non-200, a body over the size cap, a body that does not
  parse as JSON, or a JWKS with zero keys -> the fetch FAILS (returns false to the caller). The
  caller decides fail-static vs fail-hard.

Cache state (mutex `g_jwks_mtx` guards all of it):
```
struct jwks_cache {
    std::string raw_jwks;                 // the raw JWKS JSON body (fed to jwt-cpp)
    std::set<std::string> kids;           // kids present, for O(1) unknown-kid detection
    int64_t expires_at   = 0;             // unix seconds; refresh when now >= expires_at
    int64_t last_refresh = 0;             // last successful or attempted network refresh
    int64_t last_unknown_kid_refresh = 0; // rate-limit window anchor for unknown-kid refresh
};
```

`refresh_jwks()` (holds `g_jwks_mtx`): fetch the JWKS; on SUCCESS replace `raw_jwks`+`kids`, set
`expires_at = now + ttl`, `last_refresh = now`, return true. On FAILURE: KEEP the existing cache
untouched (fail-STATIC - last known keys stay valid), log a `SRV_WRN`, return false. TTL comes
from the response `Cache-Control: max-age=<n>` header if present and > 0, else the fallback
`g_jwks_ttl_fallback` (default 300s; test-overridable per S4).

`jwks_get_key(kid) -> std::optional<std::string>` (holds `g_jwks_mtx`), used by validate.
**S3 (no TOCTOU / dangling reference - load-bearing): it returns the public-key PEM BY VALUE (a
self-contained `std::string` copy), NEVER a reference/iterator into the cache.** jwt-cpp's
`verify()` runs AFTER this call returns and OUTSIDE `g_jwks_mtx`; if we returned a reference into
`raw_jwks`/an internal key map, a concurrent `refresh_jwks()` on another httplib worker could
invalidate it mid-verify (use-after-free / torn read). Returning a value means verify always runs
against a stable local copy. Steps:
1. If `now >= expires_at`: attempt `refresh_jwks()` (single-flight under the mutex; on failure
   keep serving stale keys - fail-static).
2. If `kid` is in `kids`: build the key from that JWK (jwt-cpp - section 4.3) and return the PEM
   by value.
3. If `kid` NOT known: unknown-kid refresh, RATE-LIMITED - only if
   `now - last_unknown_kid_refresh >= g_unknown_kid_window + jitter(0..30)`; set
   `last_unknown_kid_refresh = now` and attempt one `refresh_jwks()`, then re-check `kids`. This
   caps IdP hits from a flood of forged/rotated kids at <= ~1 per window (DoS-amplification guard,
   PLAN 4.4 step 3).
4. Still unknown -> return `std::nullopt`.

The jitter is `rng() % 31` seconds added to the window (avoids synchronized herds across
replicas). `now` is `std::time(nullptr)`.

**S4 (test-injectable timing - the TTL fallback and the unknown-kid window must be overridable so
CI does not sleep 5 min).** Two hidden, TEST-ONLY env vars are read ONCE in `server_oidc::init`
and stored in file-scope state; they are NOT `--flags` and are undocumented for operators:
- `LLAMA_OIDC_JWKS_TTL_SECONDS` -> `g_jwks_ttl_fallback` (default 300). Overrides the fallback
  TTL used when the response has no usable `Cache-Control: max-age`.
- `LLAMA_OIDC_UNKNOWN_KID_WINDOW_SECONDS` -> `g_unknown_kid_window` (default 300). Overrides the
  unknown-kid refresh rate-limit window.
Both parse as non-negative integers; a malformed value is ignored (keep the default). A test sets
them to a small value (e.g. 1) to exercise key rotation and fail-static-after-expiry in seconds.
Document in code that these exist solely for the test suite and must never be set in production.

Build note: no background thread. All refresh happens on the request thread under the mutex.
Under contention many requests serialize on `g_jwks_mtx` briefly during a refresh; acceptable for
PR4 (documented; a bounded async refresher is deferred).

### 4.3 JWT verification order (server_oidc::validate, F009c) - CRITICAL

The order is fixed and each step is a distinct, testable gate. Split of responsibility:
- OUR code enforces: shape, alg whitelist + `none`/`HS*` rejection, kid resolution, aud
  containment, optional `typ`.
- jwt-cpp enforces (once we hand it the right key + single alg): signature, iss (via
  `with_issuer`), and exp/nbf/iat with leeway.

```
oidc_validation validate(token):
    v.ok = false
    // 1. Shape (cheap reject before any parse)
    if !looks_like_jwt(token): return v with error="malformed"

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    try:
        // 2. Decode header+payload (NO signature check yet)
        auto decoded = jwt::decode<traits>(token)

        // 3. Extract alg + kid from the HEADER
        if !decoded.has_algorithm(): return error="no alg"
        std::string alg = decoded.get_algorithm()        // e.g. "RS256"
        if !decoded.has_key_id():   return error="no kid"
        std::string kid = decoded.get_key_id()

        // 4. ALG WHITELIST (OURS - the algorithm-confusion guard).
        //    - reject "none" explicitly
        //    - reject any HS* (a JWKS public key must NEVER be used as an HMAC secret)
        //    - alg must be in g_oidc_algs (all asymmetric)
        if alg == "none" || alg starts_with "HS": return error="alg not allowed"
        if g_oidc_algs.count(alg) == 0:              return error="alg not allowed"

        // 5. Resolve the signing key by kid (rate-limited refresh on miss - section 4.2).
        //    jwks_get_key returns the public-key PEM BY VALUE (S3), or nullopt.
        std::optional<std::string> pem = jwks_get_key(kid)  // built from the JWK for this kid
        if !pem: return error="unknown kid"

        // 6. Signature + iss + exp/nbf/iat via jwt-cpp, bound to the SINGLE asymmetric alg.
        //    S2 (pinned - this is where alg-confusion bugs are born): an EXPLICIT 6-way switch on
        //    the header alg (already whitelisted in step 4). NO hsXXX, NO none, NO generic verifier
        //    is EVER constructed, so a public key can never be used as an HMAC secret.
        auto verifier = jwt::verify<traits>().leeway(g_oidc_clock_skew).with_issuer(g_oidc_issuer);
        switch (alg):
            case "RS256": verifier.allow_algorithm(jwt::algorithm::rs256{*pem, "", "", ""}); break;
            case "RS384": verifier.allow_algorithm(jwt::algorithm::rs384{*pem, "", "", ""}); break;
            case "RS512": verifier.allow_algorithm(jwt::algorithm::rs512{*pem, "", "", ""}); break;
            case "ES256": verifier.allow_algorithm(jwt::algorithm::es256{*pem, "", "", ""}); break;
            case "ES384": verifier.allow_algorithm(jwt::algorithm::es384{*pem, "", "", ""}); break;
            case "ES512": verifier.allow_algorithm(jwt::algorithm::es512{*pem, "", "", ""}); break;
            default:      return error="alg not allowed";   // unreachable after step 4; belt-and-suspenders
        verifier.verify(decoded)                       // throws on bad sig / iss / exp / nbf
        // g_oidc_issuer is guaranteed non-empty (C1), so with_issuer always runs.

        // 7. AUDIENCE containment (OURS): the token aud (string or array) must contain at least
        //    one configured audience. jwt-cpp with_audience semantics differ, so check directly.
        auto aud = decoded.get_audience()              // set<string>
        if none of g_oidc_audiences is in aud: return error="aud mismatch"

        // 8. Optional typ == "at+jwt" (guards against an ID token used as an access token).
        if g_oidc_require_at_jwt_typ:
            if !decoded.has_type() || decoded.get_type() != "at+jwt": return error="typ mismatch"

        // 9. Success: fill sub / iss / exp / claims_json
        v.subject     = decoded.get_subject()          // "sub"; empty -> error="no sub"
        v.issuer      = g_oidc_issuer                   // verified
        v.expires_at  = decoded.get_expires_at() as unix seconds
        v.claims_json = decoded.get_payload()           // serialized payload
        v.ok          = true
        return v
    catch (...):
        return v with error="verify failed"             // any jwt-cpp throw -> deny (fail closed)
#else
    return v with error="no openssl"
#endif
```

Notes for the coder:
- **JWK -> public-key PEM (pinned, S2/OQ1).** In `jwks_get_key`, obtain the JWK with
  `jwt::parse_jwks<traits>(raw_jwks).get_jwk(kid)` and convert it to a public-key PEM using
  jwt-cpp's own helper (e.g. the library's `jwt::helper` / X.509 or RSA/EC public-key builder that
  ships with the pinned tag - confirm the exact call in OQ1). Do NOT hand-build an `EVP_PKEY`.
  Return that PEM by value (S3).
- **Type-mismatch is fail-closed.** The verifier switch (step 6) binds the algorithm FAMILY from
  the header; if the JWK's key type cannot satisfy the requested alg - an RSA JWK presented for an
  `ES*` alg, an EC JWK for an `RS*` alg, or (critically) an `oct` (symmetric) JWK for ANY alg - the
  PEM conversion fails or the `verify` throws; treat either as `unknown kid` / verify-failure ->
  deny. An `oct` JWK must NEVER reach an HMAC verifier because no HMAC verifier is ever constructed.
- Bind exactly one algorithm - the one from the header, after it passed the whitelist.
- `get_expires_at()` returns a `std::chrono::system_clock::time_point`; convert to unix seconds.
- A missing `exp` (jwt-cpp: `has_expires_at()==false`) -> deny ("no exp"): an access token with
  no expiry is not acceptable.
- `claims_json` is the raw payload string jwt-cpp already holds (`get_payload()`); do not
  re-serialize field by field.

### 4.4 looks_like_jwt (F009a)

Split `token` on `.`; require exactly 3 parts, each non-empty, each character in the base64url
charset `[A-Za-z0-9_-]` (padding `=` tolerated at a segment end). No crypto. This lets an opaque
API key (no dots, or wrong shape) fall through to API-key auth in resolve_principal.

--------------------------------------------------------------------------------
## 5. server-auth wiring (F009d)

### 5.1 Policy `oidc` section (parsed in server_auth::init, next to the mtls parse ~server-auth.cpp:711-789)

Extend the policy JSON (PLAN.md 4.1) with an optional `oidc` object:

```json
"oidc": {
  "roles_claim": "realm_access.roles",
  "role_map": { "llm-admins": "admin", "llm-users": "user" },
  "require_at_jwt_typ": false
}
```

- `roles_claim` (string, default `"realm_access.roles"`): a dot-separated path into the token
  claims whose terminal value is an array of role strings (or a single role string). Absent ->
  default.
- `role_map` (object: claim-role-string -> local role name): EXACT match only (NO wildcards -
  unlike mTLS; OIDC role names are opaque IdP strings, a prefix wildcard has no meaning). Each
  value MUST be an existing role in `roles` (or the compiled-in defaults), else `init` fails
  (same fail-closed rule as `api_keys` / `mtls.role_map`).
- `require_at_jwt_typ` (bool, default false): when true, `validate` requires header
  `typ == "at+jwt"`. It is a VALIDATION policy owned by server_oidc, but its single source of
  truth is the policy `oidc` section. Wiring (C3, settled - no waffling): server-auth::init reads
  this bool into the local `g_oidc_require_typ`, then calls `server_oidc::set_require_typ(bool)`.
  There is NO `--oidc-require-typ` flag and NO `common_params` field for it.
- Absent `oidc` object -> empty role map -> every validated token is unmapped -> denied (403).
  To AUTHORIZE OIDC users an operator MUST supply `--auth-policy-file` with an `oidc.role_map`.
  Document in the flag help.

New file-scope state in server-auth.cpp (next to `g_mtls_identity_source` / `g_mtls_role_map`):
```cpp
bool        g_oidc_enabled = false;                 // set true after server_oidc::init succeeds
std::string g_oidc_roles_claim = "realm_access.roles";
std::unordered_map<std::string, uint32_t> g_oidc_role_map;  // claim-role -> perms
bool        g_oidc_require_typ = false;             // from policy oidc.require_at_jwt_typ
```

`set_require_typ` contract (C3): `server_auth::init` MUST call
`server_oidc::set_require_typ(g_oidc_require_typ)` on EVERY OIDC-enabled path, BEFORE
`server_oidc::init(params)` and BEFORE setting `g_oidc_enabled = true` - including OIDC-only mode
with no policy file (where `g_oidc_require_typ` stays the default `false`, which must still be
pushed so a prior/stale value can never linger). `server_oidc` stores it in a file-scope bool that
defaults to `false`.

### 5.2 roles-claim extraction helper (server-auth.cpp)

`static std::vector<std::string> extract_oidc_roles(const std::string & claims_json, const std::string & path)`:
- Parse `claims_json` with nlohmann (`json::parse`, in a try; on parse error -> `{}` -> perms 0
  -> 403, fail closed).
- Split `path` on `.`; walk each segment as an object key. If any segment is missing or the
  current node is not an object -> return `{}`.
- Terminal node: if it is an array, collect each string element (skip non-strings); if it is a
  string, return `{that}`; otherwise `{}`.

### 5.3 resolve_principal OIDC branch (server-auth.cpp, insert after the trusted-proxy block ~line 978, before the API-key block ~line 980)

New precedence: mTLS -> trusted-proxy -> **OIDC** -> API key -> anonymous.

```
// 3. OIDC Bearer token (after trusted-proxy, before API key)
if (g_oidc_enabled) {
    std::string token = req.authorization;                 // OIDC only reads Authorization, not X-Api-Key
    if (token.rfind("Bearer ", 0) == 0) token = token.substr(7);
    if (!token.empty() && server_oidc::looks_like_jwt(token)) {
        oidc_validation v = server_oidc::validate(token);
        if (v.ok) {
            server_auth_principal p;
            p.authenticated = true;
            p.method        = AUTH_OIDC;
            p.issuer        = v.issuer;
            p.subject       = v.subject;
            p.expires_at    = v.expires_at;
            p.roles         = extract_oidc_roles(v.claims_json, g_oidc_roles_claim); // raw claim roles
            p.perms         = 0;
            for (const auto & role : p.roles) {
                auto it = g_oidc_role_map.find(role);
                if (it != g_oidc_role_map.end()) p.perms |= it->second;  // unknown -> nothing (fail-closed)
            }
            return p;                                        // unmapped roles -> perms=0 -> caller 403
        }
        // JWT-shaped but INVALID -> do NOT fall through to API-key auth. A 3-segment token is
        // unambiguously a JWT; treating it as an API key is pointless and muddies audit. Return
        // anonymous so the caller answers 401 (OQ3).
        return server_auth_principal{};
    }
    // Not JWT-shaped -> fall through to the API-key branch (an opaque API key still works).
}
```

Decisions (mirror the mTLS/trusted-proxy fail-closed contract):
- Valid token, roles map to something -> authenticated with those perms.
- Valid token, roles unmapped or roles claim absent -> authenticated, perms=0 -> 403 on any
  CLASSIFIED protected route (no default role). Same C4 accuracy note as PR3: on an unclassified
  or out-of-prefix path an authenticated principal returns allow and httplib 404s (unchanged
  PR1/PR2 behavior).
- JWT-shaped but invalid (bad sig, wrong iss/aud, expired, unknown kid, etc.) -> anonymous ->
  401. NO API-key fallback (OQ3).
- Non-JWT Bearer (opaque, no dots) -> API-key branch (unchanged).
- OIDC is skipped entirely when `g_oidc_enabled` is false.
- Authorization is ONLY on `p.perms` (the F007 Q4 hard rule): no code branches on role names or
  on the raw sub/claims.

### 5.4 init: enforcement flip (S1 pattern) + server_oidc::init call

Reuse the EXACT S1 pattern mTLS uses:
1. `bool has_oidc = server_oidc::configured(params);` alongside `has_mtls` (server-auth.cpp:540).
2. Extend the auth-disabled early return (server-auth.cpp:657) to also require `!has_oidc`:
   `else if (!has_api_keys && !has_trusted_proxies && !has_mtls && !has_oidc)`.
3. OR `has_oidc` into `g_auth_enabled` (server-auth.cpp:669):
   `g_auth_enabled = has_policy_file || has_api_keys || has_trusted_proxies || has_mtls || has_oidc;`
4. After `g_role_perms` is persisted and AFTER the policy `oidc` parse (5.1), if `has_oidc`:
   - call `server_oidc::set_require_typ(g_oidc_require_typ)`;
   - `if (!server_oidc::init(params)) return false;` (this does the MANDATORY JWKS fetch and any
     config validation; on failure the server aborts - PLAN 4.2c);
   - `g_oidc_enabled = true;` (only after a successful server_oidc::init).
5. S1 defensive invariant (MANDATORY, parallel to the mTLS guard at server-auth.cpp:857), as the
   LAST check before `init` returns true:
   ```cpp
   if (has_oidc && !g_auth_enabled) {
       SRV_ERR("%s", "OIDC is enabled but auth enforcement is off; refusing to start\n");
       return false;   // fail closed
   }
   ```
   Place it next to the existing `if (has_mtls && !g_auth_enabled)` guard.

Ordering: server_oidc::init runs INSIDE server_auth::init (server.cpp:179), after ctx_http.init
(server.cpp:173). No server.cpp change. If server_oidc::init returns false, server_auth::init
returns false and main aborts (both fail-closed).

### 5.5 audit + enum

- Append `AUTH_OIDC` to `server_auth_method` (server-auth.h:30):
  `{ AUTH_NONE, AUTH_API_KEY, AUTH_TRUSTED_PROXY, AUTH_MTLS, AUTH_OIDC }` (stable values).
- Add `case AUTH_OIDC: return "oidc";` to `auth_method_to_string` (server-auth.cpp:383-391).
- The audit `subject_hash` is `sha256_hex(p.subject + salt)` where `p.subject` is the `sub`
  claim - so the raw `sub` is NEVER logged (only its salted hash). The token, its header, the
  claims, and the `Authorization` value are NEVER logged (existing audit field set is exhaustive;
  do not add claim fields). `issuer` in the principal is the verified `iss`; it is NOT written to
  the audit line (the audit schema is fixed at 9 fields).

--------------------------------------------------------------------------------
## 6. Config: flags and common_params

### 6.1 common/common.h (near the auth/ssl block, common.h:646-657)

```cpp
std::string oidc_issuer      = "";          // --oidc-issuer (discovery base)
std::string oidc_jwks_url    = "";          // --oidc-jwks-url (overrides discovery)
std::string oidc_audience    = "";          // --oidc-audience (comma-separated; >=1 required)
std::string oidc_algs        = "RS256,ES256";// --oidc-algs (comma-separated asymmetric algs)
std::string oidc_ca_file     = "";          // --oidc-ca-file (optional CA pin; verify always on)
int         oidc_clock_skew  = 60;          // --oidc-clock-skew seconds (clamped 0..300)
```

(`oidc_require_at_jwt_typ` is NOT a flag; it comes from the policy `oidc` section - section 5.1.)

### 6.2 common/arg.cpp (follow the --auth-policy-file / --mtls-* pattern, arg.cpp:3374-3466)

Six flags, all `.set_examples({LLAMA_EXAMPLE_SERVER})` with env vars:
- `--oidc-issuer URL` (`LLAMA_ARG_OIDC_ISSUER`). Help: the IdP issuer; used for OIDC discovery of
  the JWKS endpoint and as the exact `iss` the token must carry. REQUIRED whenever OIDC is used,
  even alongside `--oidc-jwks-url` (C1: an empty issuer would skip `iss` verification and let a
  token from another issuer that is signed by a key in a shared JWKS pass). Setting `--oidc-issuer`
  or `--oidc-jwks-url` ENABLES auth enforcement (deny-by-default) and requires an
  `--auth-policy-file` with an `oidc.role_map` to authorize any user.
- `--oidc-jwks-url URL` (`LLAMA_ARG_OIDC_JWKS_URL`). Help: explicit JWKS endpoint; overrides
  discovery. Must be https. Redirects are NOT followed (an IdP must serve JWKS directly).
- `--oidc-audience STR[,STR...]` (`LLAMA_ARG_OIDC_AUDIENCE`). Help: at least one required; the
  token `aud` must contain one of these.
- `--oidc-algs RS256,ES256` (`LLAMA_ARG_OIDC_ALGS`). Help: allowed signature algorithms
  (asymmetric only). `none` and `HS*` are rejected (algorithm confusion). Default `RS256,ES256`.
- `--oidc-ca-file PATH` (`LLAMA_ARG_OIDC_CA_FILE`). Help: optional CA bundle to PIN verification
  of the IdP/JWKS TLS certificate; when unset, the system CA store is used. Server-certificate
  verification is ALWAYS on and cannot be disabled. Not a secret.
- `--oidc-clock-skew SEC` (`LLAMA_ARG_OIDC_CLOCK_SKEW`, `std::stoi`). Help: leeway for
  exp/nbf/iat, default 60, clamped to [0,300].

Help must also state: llama-server validates ACCESS tokens locally as a resource server; it does
NOT implement the authorization-code flow, sessions, or cookies. Opaque-token introspection is a
future option. No client secret is used or accepted on the command line.

C2 note (must appear in the `--oidc-*` help): once OIDC is enabled, an `Authorization: Bearer`
value with JWT shape (three dot-separated base64url segments) is routed to OIDC validation and, if
invalid, returns 401 with NO fallback to API-key auth. An API key that happens to be coincidentally
JWT-shaped would therefore be rejected; keep API keys non-dotted, or expect them to be treated as
JWTs. (This is fail-closed and reveals no oracle: a JWT-shaped-invalid token and an unknown opaque
key both return the same 401.)

--------------------------------------------------------------------------------
## 7. Data flow

```
Client -> Authorization: Bearer <JWT>
pre_routing_handler (server-http.cpp, UNCHANGED for PR4)
  reset_principal(); CORS/OPTIONS/state/frontend carve-outs
  middleware_authz: build server_auth_request ar (ar.authorization already carries the Bearer)
                    [PR3 mTLS extract_identity call, unchanged]
                    server_auth::authorize_request(ar):
                       resolve_principal: mTLS -> trusted-proxy -> OIDC -> API key
                         OIDC branch: looks_like_jwt? -> server_oidc::validate(token)
                                       -> extract_oidc_roles -> g_oidc_role_map -> perms
                       deny-by-default authz on p.perms (unchanged)
                       audit_emit (auth_method="oidc")
server_oidc (server-oidc.cpp)
  validate: shape -> alg whitelist (none/HS reject) -> jwks_get_key(kid) (rate-limited refresh)
            -> jwt-cpp verify (sig+iss+exp/nbf/iat) -> aud containment -> optional typ
  JWKS cache: lazy refresh on expiry (fail-static), rate-limited unknown-kid refresh
```

--------------------------------------------------------------------------------
## 8. Fail-closed behavior summary

| Condition | Behavior |
|---|---|
| OIDC configured, build has no OpenSSL | server_oidc::init returns false -> server_auth::init false -> abort |
| OIDC configured, misconfig (bad alg list, no audience, empty issuer (C1), skew > 300, http JWKS URL, bad discovery) | server_oidc::init returns false -> abort |
| OIDC configured, initial JWKS fetch fails / times out at startup | server_oidc::init returns false -> abort (PLAN 4.2c, S5) - OQ2 |
| JWKS/discovery endpoint 302-redirects (to http:// or another host) | not followed (S1); treated as fetch failure -> fail-closed |
| JWKS/discovery response over the body size cap, or IdP hangs past the timeout | fetch failure (S5); fail-closed at boot / fail-static at runtime |
| Token kid resolves to an RSA JWK for ES*, an EC JWK for RS*, or an oct (symmetric) JWK | key build/verify fails -> treated as unknown kid -> deny (401); no HMAC verifier is ever built (S2) |
| OIDC enabled but g_auth_enabled ended false (half-applied flip) | S1 guard: server_auth::init returns false -> abort |
| Token: alg `none` or any `HS*` | validate error, deny (401) - alg-confusion guard |
| Token: alg not in `--oidc-algs` | validate error, deny (401) |
| Token: unknown kid (after rate-limited refresh) | validate error, deny (401) |
| Token: bad signature / wrong iss / expired exp / future nbf / bad iat | jwt-cpp throws -> caught -> deny (401) |
| Token: aud does not contain a configured audience | validate error, deny (401) |
| Token: missing exp or missing sub | validate error, deny (401) |
| Token: `require_at_jwt_typ` set and typ != "at+jwt" | validate error, deny (401) |
| Valid token, roles claim absent or roles unmapped | authenticated, perms=0 -> 403 on protected route (no default role) |
| JWT-shaped but invalid | anonymous -> 401; NO API-key fallback (OQ3) |
| Non-JWT Bearer (opaque) | falls through to API-key auth (unchanged) |
| IdP unreachable at RUNTIME (cache expired) | keep last-known keys (fail-static); tokens with a known kid still validate |
| Flood of forged/unknown kids | at most ~1 IdP refresh / 5 min (+jitter) - DoS-amplification guard |
| claims_json re-parse fails or roles claim wrong type | empty roles -> perms=0 -> 403 |
| Token exp passes mid-SSE-stream | NOT enforced in PR4 (expires_at populated, not checked in the loop) - documented residual risk |

--------------------------------------------------------------------------------
## 9. Test strategy (for the test-planner; coder threads flags only)

New file `tools/server/tests/unit/test_oidc.py`. Needs a MOCK IdP and a way to MINT/SIGN JWTs.

Harness requirements (test-planner confirms and installs):
- A mock IdP served by python `http.server` (or Flask) exposing:
  `/.well-known/openid-configuration` -> `{ "jwks_uri": ".../jwks.json", "issuer": "<iss>" }`,
  and `/jwks.json` -> the JWKS for the test signing key(s). It must serve over HTTPS with a test
  server cert whose CA the test passes as `--oidc-ca-file` (or use `--oidc-jwks-url` to an https
  mock). If HTTPS in the mock is impractical, the test-planner may need a localhost TLS cert
  fixture (reuse the mTLS fixture's CA generation).
- Token minting: PyJWT + cryptography (RS256/ES256 signing, custom header kid, custom claims) OR
  manual signing with `cryptography`. The test venv likely needs `PyJWT` and `cryptography` -
  flag for the test-planner to add to the requirements and confirm availability.
- `ServerProcess` (utils.py) gains: `oidc_issuer`, `oidc_jwks_url`, `oidc_audience`, `oidc_algs`,
  `oidc_ca_file`, `oidc_clock_skew`, each appended to `server_args` when set (mirror the
  `auth_policy_file` / `mtls_*` pattern).

Cases - NEGATIVE FIRST (they matter most):
1. `alg: none` token -> 401 (never a role).
2. HS256 token signed with the JWKS RSA PUBLIC key as the HMAC secret (algorithm confusion) ->
   401. This is the single most important test.
3. Wrong `aud` -> 401.
4. Wrong `iss` -> 401.
5. `exp` in the past -> 401 (also test exactly within vs beyond clock-skew).
6. `nbf` in the future (beyond skew) -> 401.
7. Unknown `kid` -> 401; and assert the IdP is not hammered (a burst of unknown-kid tokens
   triggers at most one JWKS refetch within the rate-limit window).
8. Malformed token (2 segments, empty segment, non-base64url) -> 401.
9. JWKS endpoint down at STARTUP -> server refuses to start (OQ2). Also: an IdP that accepts TCP
   but never responds -> server refuses to start within the timeout (S5), does not hang.
10. Key rotation: a new kid appears in the JWKS; a token with the new kid validates after the
    (rate-limited) refresh; the mock returns the new key. Use the S4 test env vars
    (LLAMA_OIDC_JWKS_TTL_SECONDS / LLAMA_OIDC_UNKNOWN_KID_WINDOW_SECONDS set to ~1s) so this and
    case 11 run in seconds, not 5 minutes.
11. IdP down at RUNTIME after a successful start -> a token with a still-cached kid validates
    (fail-static); a token with a brand-new kid fails (fail-static, not fail-open).
17. S1 (SSRF/downgrade): a JWKS or discovery endpoint that answers with 302 -> http://... or ->
    another host is NOT followed; init treats it as a fetch failure (server refuses to start).
18. S2 (type mismatch): a token whose kid maps to an oct (symmetric) JWK, or an RSA JWK used with
    an ES* alg (and vice versa), is rejected (401); no HMAC path is reachable.
19. C1: OIDC configured with `--oidc-jwks-url` but NO `--oidc-issuer` -> server refuses to start.
12. Missing roles claim -> authenticated but 403 on a protected route.
13. Unmapped role -> authenticated but 403.
Positive:
14. Valid RS256 token, roles map to `admin` -> `POST /slots/0` (ADMIN_STATE) succeeds; audit
    `auth_method=oidc`, non-anonymous `subject_hash`.
15. Valid ES256 token, roles map to `user` -> `POST /completions` succeeds; `POST /slots/0` -> 403.
16. Disambiguation: with OIDC enabled AND an API key configured, an opaque (non-JWT) Bearer API
    key still authenticates via the API-key path; a JWT-shaped-but-invalid Bearer gets 401 and is
    NOT retried as an API key.

--------------------------------------------------------------------------------
## 10. Feature mapping

- F009a: vendor jwt-cpp (tools/server/vendor/jwt-cpp) + CMake include dir + six flags +
  common_params fields + utils.py threading + server-oidc.h contract + gated stubs
  (`configured`, `looks_like_jwt` real; `init`/`validate` stubbed to fail-closed until F009b/c).
  Files: tools/server/vendor/jwt-cpp/, tools/server/CMakeLists.txt, common/common.h,
  common/arg.cpp, tools/server/tests/utils.py, tools/server/server-oidc.h, server-oidc.cpp.
  Sections 2, 3, 6.
- F009b: server_oidc::init config resolution + discovery + JWKS HTTPS client (mandatory verify +
  optional CA pin) + cache + TTL + fail-static + rate-limited unknown-kid refresh. Files:
  tools/server/server-oidc.cpp (+.h if a state accessor is needed). Sections 4.1, 4.2.
- F009c: server_oidc::validate verification core (shape, alg whitelist + none/HS rejection, kid
  resolution call, jwt-cpp sig+iss+exp/nbf/iat, aud containment, optional typ) + set_require_typ.
  Files: tools/server/server-oidc.cpp, tools/server/server-oidc.h. Sections 4.3, 4.4.
- F009d: policy `oidc` parse + `g_oidc_*` state + extract_oidc_roles + resolve_principal OIDC
  branch + init enforcement flip (S1) + AUTH_OIDC enum/audit. Files: tools/server/server-auth.h,
  tools/server/server-auth.cpp. Sections 5.

Suggested implementation order: F009a -> F009b -> F009c -> F009d (matches depends_on).

--------------------------------------------------------------------------------
## 11. Open questions for the challenger

- OQ1 (jwt-cpp vendoring + traits + JWK->key path): confirm the pinned jwt-cpp tag (target
  v0.7.x), that `JWT_DISABLE_PICOJSON` + the nlohmann traits header compile against the vendored
  nlohmann/json, and the EXACT jwt-cpp API for turning a JWK (by kid) into an asymmetric verifier
  without any hand-built `EVP_PKEY`. Confirm the LICENSE file is vendored.
- OQ2 (startup fail-closed on JWKS-unreachable): PLAN 4.2c mandates hard-fail (server does not
  start) if the initial JWKS fetch fails. This couples llama-server boot to IdP reachability.
  Confirm hard-fail vs a bounded startup retry / a start-and-serve-static-once-reachable grace.
  Design currently hard-fails.
- OQ3 (Bearer JWT-vs-api-key disambiguation): a JWT-shaped token (3 base64url segments) is routed
  to OIDC and, if invalid, returns 401 with NO API-key fallback; a non-JWT Bearer falls through to
  API-key auth. Confirm this cannot (a) let a valid API key that happens to be 3-dot-shaped be
  misrouted to OIDC (accept as fail-closed?), or (b) allow probing. Confirm OIDC precedence sits
  after trusted-proxy and before API-key.
- Alg-confusion enforcement point: we reject `none`/`HS*` in our code BEFORE jwt-cpp and only ever
  build an asymmetric verifier bound to the header alg + the JWKS public key. Confirm jwt-cpp is
  never handed an HMAC verifier, so a public key can never be used as an HMAC secret.
- JWKS DoS / rate-limit: unknown-kid refresh is capped at ~1 / 5 min (+0..30s jitter); expiry
  refresh is single-flight under a mutex; IdP-down is fail-static. Confirm the window and that a
  flood of distinct forged kids cannot amplify to the IdP; confirm lazy (no background thread) is
  acceptable.
- Clock-skew bounds: default 60s, clamped to [0,300], applied as jwt-cpp leeway to exp/nbf/iat.
  Confirm the upper clamp (reject > 300) and that leeway is applied to all three claims.
- `--oidc-ca-file` optional (verification always on, system store fallback): confirm this
  deviation from PLAN's "explicit CA" wording is acceptable, or require the CA path when the JWKS
  URL is https.
- Audience check done by us (containment) rather than jwt-cpp `with_audience`: confirm semantics
  (token aud must contain >=1 configured audience; multiple configured audiences are OR-ed).

--------------------------------------------------------------------------------
## 12. Challenger review outcomes (resolved)

The challenger (Fable) reviewed this design: NO blockers. The algorithm-confusion posture is
structurally sound (whitelist-before-key-lookup, asymmetric-verifier-only, an oct JWK never
reaches an HMAC path, global JWKS rate-limit, fail-static never accepts, iss/aud/skew clean, S1
enforcement flip verified). The should-fixes and considers are folded in:

- **S1 (SSRF + TLS downgrade in the boot path).** RESOLVED in section 4.2: the JWKS/discovery
  client sets `set_follow_location(false)` so a malicious IdP cannot 302-redirect us to
  `http://169.254.169.254/...` or an internal host past the https-only gate. A redirect is a
  fetch failure. Test 17 added.
- **S2 (pin the verifier construction).** RESOLVED in section 4.3 step 6: an explicit 6-way switch
  (RS256/384/512 -> `jwt::algorithm::rsXXX{pem,"","",""}`, ES256/384/512 -> `esXXX{...}`); the PEM
  comes from `jwt::parse_jwks<traits>(raw).get_jwk(kid)` + a jwt-cpp public-key helper (never a
  hand-built `EVP_PKEY`); no `hsXXX`/`none`/generic verifier is ever constructed; an oct JWK or a
  key-type/alg mismatch -> unknown-kid/verify-failure -> deny. Hard F009c criterion. Test 18.
- **S3 (TOCTOU / dangling key).** RESOLVED in section 4.2: `jwks_get_key` returns the public-key
  PEM BY VALUE (`std::optional<std::string>`), never a reference/iterator into the cache, so
  `verify` (which runs outside `g_jwks_mtx`) cannot race a concurrent refresh.
- **S4 (untestable timing).** RESOLVED in section 4.2: the fallback TTL and the unknown-kid window
  are test-injectable via hidden env vars `LLAMA_OIDC_JWKS_TTL_SECONDS` /
  `LLAMA_OIDC_UNKNOWN_KID_WINDOW_SECONDS` (read only in `server_oidc::init`, not `--flags`), so
  rotation (test 10) and runtime fail-static (test 11) run in seconds.
- **S5 (boot hang / OOM on slow/hostile IdP).** RESOLVED in section 4.2: explicit short
  connection + read timeouts (`g_oidc_http_timeout`, default 5s) and a response body size cap; a
  timeout or oversize body is a fetch failure. Test 9 extended.
- **C1 (shared-JWKS issuer confusion).** ADOPTED in section 4.1 step 5: `--oidc-issuer` is now
  ALWAYS required (empty issuer -> hard startup error), even with an explicit `--oidc-jwks-url`,
  so `with_issuer` always runs. Test 19; flag help updated.
- **C2 (dotted API key routed to OIDC).** Documented in the `--oidc-*` flag help (section 6.2):
  fail-closed, no probing oracle. Test 16 already covers the disambiguation.
- **C3 (require_at_jwt_typ prose).** Cleaned up in section 5.1: single source of truth is the
  policy `oidc` section; `server_auth::init` calls `server_oidc::set_require_typ(...)` on every
  OIDC-enabled path (including OIDC-only/no-policy, pushing the default `false`) before
  `g_oidc_enabled = true`. No flag, no `common_params` field.
- **C4 (exp not enforced mid-SSE).** Kept as a documented residual (PLAN 8.4); a new backlog
  feature F013 (stage PR5, todo) tracks "enforce token exp during long SSE streams" so it is not
  lost.

Confirmed CLEAN by the challenger (no change): the two-macro split (`CPPHTTPLIB_SSL_ENABLED` for
the HTTP client vs `CPPHTTPLIB_OPENSSL_SUPPORT` for jwt-cpp); the middleware already populates
`ar.authorization` (no server-http.cpp change); the mTLS -> trusted-proxy -> OIDC -> API-key
precedence; and audit logging only the salted `subject_hash`.
