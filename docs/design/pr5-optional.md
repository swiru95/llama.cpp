# PR5 design: optional hardening (CRL / introspection / WebUI PKCE)

Status: in_design
Features: F010a (mTLS CRL), F010b (OIDC RFC-7662 opaque-token introspection),
F010c (WebUI PKCE public client - RECOMMENDED DEFERRAL). Also in PR5, tracked separately:
F013 (enforce token exp during long SSE streams - already a backlog feature, NOT part of F010).

This document is the implementation contract for a Haiku-class coder. Every non-obvious decision
is settled here. Do not invent behavior that is not written down; if something is missing, stop
and ask the architect.

ASCII only in all code and docs (AGENTS.md): no em-dash, no unicode arrows, use `-` and `->`.

PR5 builds on merged PR1-PR4. It reuses those conventions verbatim: all policy logic in
server-auth.{h,cpp}; CRL extends the NEW file server-mtls.cpp; introspection extends the NEW file
server-oidc.cpp; existing files get call sites only; fail closed; deny-by-default; NO hand-rolled
crypto. The three sub-features are INDEPENDENT: any subset can ship without the others.

--------------------------------------------------------------------------------
## 0. Scope, effort, and per-part recommendation (read this first)

PR5 is OPTIONAL and needs-dependent (PLAN.md section 5, row 5; PLAN.md 3 marks the WebUI row
"optional"). The three pieces do not depend on each other. Effort is estimated for one engineer
who knows this repo (S = <1 day, M = 1-3 days incl. tests, L = >3 days).

| Sub | Piece | Effort | Recommendation | One-line reason |
|---|---|---|---|---|
| F010a | mTLS CRL | M | DO-NOW (if you run mTLS) | Small, self-contained in server-mtls.cpp, fail-closed, low rebase risk; adds real revocation for the compromised-but-unexpired cert gap PR3 left open. |
| F010b | OIDC introspection | M-L | DO-NOW ONLY IF you must accept OPAQUE tokens; otherwise DEFER | JWT access tokens are already fully covered by PR4. Introspection is pure additive value for IdPs that hand out non-JWT bearers; it adds an outbound POST, a client secret, and a token cache. |
| F010c | WebUI PKCE | L | DEFER to oauth2-proxy (PLAN section 9) | The frontend is a full SvelteKit/Svelte-5 PWA under `tools/ui/` (moved from `tools/server/webui/`), adapter-static (no server callback route), and a fast-moving upstream subtree. A browser PKCE flow is a large frontend feature with a high perpetual rebase cost; oauth2-proxy delivers the same browser login in variant B with none of that cost. |

Honest summary for the orchestrator: F010a is the clear win. F010b is worth it only for the
opaque-token use case (many deployments never need it - Keycloak/Auth0/Entra issue JWT access
tokens that PR4 validates locally without a network round-trip per request). F010c is
high-effort/low-marginal-value inside the binary and should be an external proxy concern.

--------------------------------------------------------------------------------
## 1. Discrepancies between PLAN.md / the task framing and the current code

Anchors verified on `master` after PR4 merged. THESE MATTER - the plan's line numbers and the
task framing rot.

| PLAN.md / task claim | Reality (verified) | Impact |
|---|---|---|
| WebUI lives in `tools/server/webui/` (PLAN.md 3, 9; task item 3) | The directory `tools/server/webui/` DOES NOT EXIST. The frontend is at `tools/ui/` - a SvelteKit (Svelte 5) + Vite + TypeScript PWA (`tools/ui/package.json` name `llama-ui`, `@sveltejs/adapter-static`, `@sveltejs/kit` 2.x, `@vite-pwa/sveltekit`, Playwright/Storybook). It is embedded into the binary via `tools/ui/embed.cpp` -> `llama_ui_get_assets()` and served by `server-http.cpp` (frontend_paths, server-http.cpp:235-241, 458). | F010c is materially LARGER and higher-rebase-cost than PLAN implies. Auth today: a single `apiKey` string in the settings store, injected as `Authorization: Bearer <apiKey>` by `getAuthHeaders()` in `tools/ui/src/lib/utils/api-headers.ts:16-21`. See section 4 and the DEFER recommendation. |
| mTLS ctx is reached via `srv->ssl_context()` (PLAN 4.3) | Reached via `static_cast<httplib::SSLServer*>(srv.get())->tls_context()` (server-http.cpp:153-154), already wired in PR3's `harden_context` call. | F010a extends the EXISTING `harden_context` path; no new server-http.cpp code. |
| CRL via `X509_STORE_load_locations` + `X509_STORE_set_flags` (PLAN 4.3) | The client CA is loaded by httplib via `SSL_CTX_load_verify_locations` (httplib.cpp:13156, called from `set_client_ca_file` 12862), which populates the SSL_CTX DEFAULT store. So the CRL must be added to THAT same store, obtained with `SSL_CTX_get_cert_store(c)`. `X509_STORE_load_locations` cannot prove a CRL was actually present (fail-open risk). | F010a parses the CRL PEM explicitly and `X509_STORE_add_crl`s each, requiring >=1 (fail-closed if the CRL cannot load), then sets `X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL`. See section 2.3. |
| Introspection is a small add to server-oidc (task 2) | `server_oidc::init`/`configured` today assume a JWKS path (issuer or jwks-url). The existing hardened HTTP helper `https_get` (server-oidc.cpp:125) is GET-only and https-only. There is no POST/basic-auth helper and no token cache. | F010b adds an introspection-only config path (introspection can be configured WITHOUT a JWKS), a new hardened POST helper, and a token-hash cache. `has_oidc` in server-auth.cpp:546 must widen to include introspection (section 3.5). |
| `AUTH_OIDC` distinguishes JWT vs introspection | enum `{ AUTH_NONE, AUTH_API_KEY, AUTH_TRUSTED_PROXY, AUTH_MTLS, AUTH_OIDC }` (server-auth.h:30). | F010b REUSES `AUTH_OIDC` for introspected principals (no enum churn); `issuer` differentiates. Section 3.4. |
| `--oidc-client-secret-file` secret handling | No such flag/field exists yet. | Secret is read from the FILE at init (never argv, never env value logged), stored in server-oidc.cpp file-scope state. Section 3.2. |
| F010 coarse scope also lists `/cors-proxy`+`/tools` SSRF hardening and Prometheus auth metrics (features.json F010 description; PLAN 7, 8.1) | Those are NOT part of this decomposition (the task scoped F010 to CRL/introspection/PKCE). | Called out here so they are not silently dropped: they remain in the F010 umbrella as UNSCHEDULED. If wanted, the architect should cut separate features (suggested F014 SSRF-hardening, F015 auth metrics). Section 5. |

None of these blocks F010a or F010b. The load-bearing correction is the WebUI relocation +
framework, which drives the F010c deferral.

--------------------------------------------------------------------------------
## 2. F010a - mTLS CRL (certificate revocation)

DO-NOW. Effort M (the code is small; the test fixture - generate a CA, a client cert, then a CRL
revoking it - is the bulk of the work). security_sensitive: true. depends_on: F008d.

### 2.1 Goal and fail-closed contract

Load an operator-supplied CRL into the mTLS verification store and turn on CRL checking for the
whole client-cert chain, so a revoked-but-unexpired client certificate is rejected at the TLS
handshake (never reaches authz). This closes the PR3 residual risk (pr3-mtls.md section 9: a
compromised cert stays valid until expiry).

Fail-closed rules (all -> `harden_context` returns false -> `ctx_http.init` returns false ->
server aborts):
- `--mtls-crl-file` set but the file cannot be opened / parsed / contains zero CRLs.
- `--mtls-crl-file` set while `--mtls-required` is `off` (a CRL with no client-cert verification
  is a configuration error; do NOT silently ignore it - unlike a stray CA file, a CRL signals
  clear revocation intent). This check lives in `server_mtls::configure` (SRV_ERR + return false).
- Built without OpenSSL (already fail-closed: harden_context returns false in the `#else`).

Operational cost (document in flag help and README, per PLAN 4.3 / section 8):
- OpenSSL loads the CRL ONCE at startup; there is no runtime reload in F010a. A rotated CRL
  requires a server restart. Runtime CRL reload/refresh is explicitly OUT OF SCOPE (OQ-A2).
- `X509_V_FLAG_CRL_CHECK_ALL` requires a CRL to be present for EVERY CA in the client-cert chain
  (leaf issuer AND every intermediate up to a self-signed root that the chain includes). If a CRL
  is missing for any CA in the chain, verification FAILS (fail-closed) with
  `X509_V_ERR_UNABLE_TO_GET_CRL`. With the PR3 default `--mtls-verify-depth 1` (leaf signed
  directly by a configured CA), one CRL for the issuing CA suffices. Deeper PKIs must supply a CRL
  for each CA. This is a fail-closed footgun and MUST be stated in the flag help.
- Also fail-closed by nature: once a CRL's own `nextUpdate` time passes, OpenSSL treats it as
  expired and rejects ALL clients whose chain requires it. An operator who enables CRL takes on
  the duty of keeping the CRL fresh (and restarting). The realistic alternative remains
  short-lived certs (PR3); CRL is for operators who need explicit revocation.

### 2.2 Flag + params (F010a config surface)

common/common.h (next to the mTLS block, common.h:655-659):
```cpp
std::string mtls_crl_file = "";   // F010a: --mtls-crl-file (PEM CRL bundle; revocation checking)
```

common/arg.cpp (follow the `--mtls-*` pattern, arg.cpp around the existing mtls flags):
- `--mtls-crl-file PATH` (env `LLAMA_ARG_MTLS_CRL_FILE`), `.set_examples({LLAMA_EXAMPLE_SERVER})`,
  setter stores the raw path into `params.mtls_crl_file`. Help text MUST state:
  - PEM file containing one or more X.509 CRLs; enables revocation checking for the client-cert
    chain (`X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL`).
  - Requires `--mtls-required optional|required`; setting it with mTLS off aborts startup.
  - A CRL is needed for EVERY CA in the chain (with the default verify-depth 1, one CRL for the
    issuing CA). A missing or expired CRL for any CA in the chain rejects the handshake
    (fail-closed).
  - The CRL is loaded once at startup; rotating it requires a restart. Short-lived certs are the
    lower-maintenance alternative.
  - Not a secret (a CRL is public); it is a path, safe on argv.

Thread `mtls_crl_file` into `ServerProcess` (tools/server/tests/utils.py) mirroring the other
`mtls_*` fields (append `--mtls-crl-file <path>` to `server_args` when set).

### 2.3 server-mtls changes

server-mtls.h - add one field to `server_mtls_config`:
```cpp
struct server_mtls_config {
    // ... existing PR3 fields ...
    std::string crl_file;   // F010a: PEM CRL bundle (empty = no revocation checking)
};
```
No new public function: CRL is applied inside the existing `harden_context`, so there is exactly
one TLS-context call site (server-http.cpp is UNCHANGED for F010a).

`server_mtls::configure` (server-mtls.cpp:18) - after the existing mode/CA validation, add:
```cpp
if (!params.mtls_crl_file.empty() && !enabled) {
    SRV_ERR("%s", "--mtls-crl-file requires --mtls-required optional or required\n");
    return false;   // fail closed
}
out.crl_file = params.mtls_crl_file;
```

`server_mtls::harden_context` (server-mtls.cpp:80) - inside the existing
`#ifdef CPPHTTPLIB_OPENSSL_SUPPORT` block, within the `if (cfg.enabled) { ... }` section (after
`SSL_CTX_set_verify_depth` and the optional-mode verify override), add:
```cpp
if (!cfg.crl_file.empty()) {
    if (!load_crl_file(c, cfg.crl_file)) {
        return false;   // fail closed: CRL requested but could not be loaded
    }
}
```

New internal helper (server-mtls.cpp, file-scope static, inside
`#ifdef CPPHTTPLIB_OPENSSL_SUPPORT` since it uses OpenSSL X509 types directly):
```cpp
// Load one or more PEM CRLs from crl_file into ctx's verification store and turn on
// full-chain CRL checking. Returns false (fail-closed) if the file cannot be opened,
// contains no CRL, or a store operation fails.
static bool load_crl_file(SSL_CTX * c, const std::string & crl_file);
```
Implementation (settled - the coder writes exactly this shape, no invention):
1. `X509_STORE * store = SSL_CTX_get_cert_store(c);` (same store httplib populated with the client
   CA via `SSL_CTX_load_verify_locations`). If null -> SRV_ERR, return false.
2. Open the file with `BIO * bio = BIO_new_file(crl_file.c_str(), "r");` null -> SRV_ERR (cannot
   open), return false.
3. Loop `PEM_read_bio_X509_CRL(bio, ...)`; for each non-null CRL, `X509_STORE_add_crl(store, crl)`
   (on failure -> `X509_CRL_free`, `BIO_free`, SRV_ERR, return false), then `X509_CRL_free(crl)`
   (add_crl up-refs). Count how many were added.
4. `BIO_free(bio);`
5. If count == 0 -> SRV_ERR ("no CRL found in --mtls-crl-file"), return false (fail-closed - a file
   that parsed but held no CRL must not silently disable revocation).
6. `X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);` (returns void
   in current OpenSSL; no error path).
7. SRV_INF a one-line "loaded N CRL(s), revocation checking enabled" (no cert/CRL contents), return
   true.

Notes:
- Uses `<openssl/x509.h>` / `<openssl/pem.h>` / `<openssl/bio.h>`, included ONLY inside the
  existing `#ifdef CPPHTTPLIB_OPENSSL_SUPPORT` in server-mtls.cpp (server-mtls.h stays OpenSSL-free
  - the field is a plain std::string).
- This is NOT hand-rolled crypto: revocation checking itself is performed by OpenSSL's chain
  verification (SSL_VERIFY_PEER) once the flags are set; we only load the CRL and flip the flags.
- Ordering: `harden_context` runs after the httplib ctor loaded the client CA (server-http.cpp:132
  then :154), so the store already contains the issuer CA the CRL refers to. Correct as-is.

### 2.4 F010a fail-closed summary

| Condition | Behavior |
|---|---|
| `--mtls-crl-file` with `--mtls-required off` | `configure` returns false -> abort |
| CRL file cannot be opened | `load_crl_file` returns false -> `harden_context` false -> abort |
| CRL file parses but contains zero CRLs | `load_crl_file` returns false -> abort |
| `X509_STORE_add_crl` fails | `load_crl_file` returns false -> abort |
| Built without OpenSSL, `--mtls-crl-file` set with mTLS on | mTLS already aborts (no-SSL `#else`); the CRL never reaches OpenSSL |
| Revoked client cert presented | rejected at TLS handshake (X509_V_ERR_CERT_REVOKED); never reaches authz |
| CRL missing for a CA in the chain, or CRL past nextUpdate | handshake rejected for affected clients (fail-closed; documented cost) |
| Valid (non-revoked) client cert | handshake succeeds; PR3 SAN->role path unchanged |

### 2.5 F010a test strategy (for the test-planner)

Extend `tools/server/tests/unit/test_mtls.py`. The fixture already generates a CA + client certs;
add: generate a CRL signed by the CA that revokes the serial of a chosen client cert, write it to
a PEM file (the `cryptography` lib: `x509.CertificateRevocationListBuilder`).
Cases (negative first):
1. A REVOKED client cert (its serial is on the CRL) -> handshake REJECTED (transport/SSL error,
   not an HTTP status), in both `optional` and `required` mode.
2. A valid NON-revoked client cert from the same CA, with `--mtls-crl-file` set -> handshake
   succeeds and the PR3 SAN->role authz still applies (admin cert -> POST /slots/0 200,
   user cert -> 403 on /slots/0).
3. Startup fail-closed: `--mtls-crl-file <path>` with `--mtls-required off` -> server refuses to
   start; `--mtls-crl-file <nonexistent>` -> refuses to start; a file with no CRL (e.g. a plain
   cert PEM) -> refuses to start.
4. (Best-effort, may be environment/time dependent) a CRL whose `nextUpdate` is in the past ->
   the handshake is rejected even for a non-revoked cert (documents the freshness cost). The
   test-planner decides whether to gate this on OpenSSL behavior.

--------------------------------------------------------------------------------
## 3. F010b - OIDC RFC-7662 opaque-token introspection

DO-NOW ONLY IF opaque tokens are required; else DEFER. Effort M-L. security_sensitive: true.
depends_on: F009d.

### 3.1 Goal

For a Bearer token that is NOT a JWT (opaque), optionally validate it by RFC 7662 introspection:
POST the token to `--oidc-introspection-url` authenticated with the resource server's client
credentials, read `active`, and (when active) build an `AUTH_OIDC` principal with roles mapped
exactly like the JWT path. Results are cached by token hash with a short TTL. This is purely
additive: the JWT path (PR4) is unchanged and takes precedence for JWT-shaped tokens.

### 3.2 Flags + params + secret handling (F010b config surface)

common/common.h (next to the oidc block, common.h:661-666):
```cpp
std::string oidc_introspection_url  = "";  // F010b: --oidc-introspection-url (RFC 7662 endpoint)
std::string oidc_client_id          = "";  // F010b: --oidc-client-id (introspection client auth)
std::string oidc_client_secret_file = "";  // F010b: --oidc-client-secret-file (secret from FILE)
```

common/arg.cpp (follow the `--oidc-*` pattern, arg.cpp:3539+), all
`.set_examples({LLAMA_EXAMPLE_SERVER})` with env vars:
- `--oidc-introspection-url URL` (`LLAMA_ARG_OIDC_INTROSPECTION_URL`). Help: RFC 7662 endpoint for
  validating OPAQUE (non-JWT) bearer tokens; must be https; redirects are not followed; enabling it
  turns deny-by-default enforcement on (same as `--oidc-issuer`).
- `--oidc-client-id STR` (`LLAMA_ARG_OIDC_CLIENT_ID`). Help: client id for introspection endpoint
  auth (HTTP Basic). Not a secret.
- `--oidc-client-secret-file PATH` (`LLAMA_ARG_OIDC_CLIENT_SECRET_FILE`). Help: FILE containing the
  introspection client secret; the secret is NEVER passed on the command line or logged. The FILE
  is read once at startup.

Secret handling (hard rule): `server_oidc::init` reads the secret from the file (whole file,
trim a single trailing newline), stores it in file-scope `g_introspect_client_secret`. The secret
value is never logged, never placed in `error`, never audited. If `--oidc-introspection-url` is set
but `--oidc-client-id` or `--oidc-client-secret-file` is missing/unreadable/empty -> init returns
false (fail-closed).

Thread the three flags into `ServerProcess` (utils.py) mirroring the `oidc_*` pattern.

### 3.3 server-oidc changes

server-oidc.h - add two declarations to `struct server_oidc`:
```cpp
// True iff introspection is configured: --oidc-introspection-url is set. Pure param check.
static bool introspection_configured(const common_params & params);

// Introspect one opaque bearer token via RFC 7662 (POST + client-credential auth). Never throws.
// Caches by token hash (positive TTL <= min(exp-now, 60s); negative TTL a few seconds). Returns
// an oidc_validation exactly like validate(): ok=true with subject/issuer/expires_at/claims_json
// on active==true, ok=false otherwise. Safe only after a successful init.
static oidc_validation introspect(const std::string & token);
```
`oidc_validation` (server-oidc.h:11) is REUSED as-is. `claims_json` carries the whole introspection
response JSON so server-auth's `extract_oidc_roles` maps roles identically to the JWT path.

server-oidc.cpp new file-scope state (namespace `{}`, next to the JWKS state):
```cpp
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
```
Include `tools/server/vendor/sha256.h` for `sha256_hex` (already used across the tree). The cache
key is the token HASH, never the token; the token is never stored.

`server_oidc::introspection_configured(params)` -> `!params.oidc_introspection_url.empty()`.

`server_oidc::init` (server-oidc.cpp) - restructure the top so JWKS and introspection are
INDEPENDENT (either or both):
1. `bool jwks_cfg = configured(params);` (issuer or jwks-url, existing).
   `bool intro_cfg = introspection_configured(params);`
   If neither -> return true (no-op).
2. `#ifndef CPPHTTPLIB_OPENSSL_SUPPORT` -> SRV_ERR, return false (both paths need TLS).
3. If `jwks_cfg`: run the EXISTING JWKS init (issuer required (C1), alg/audience/skew parse,
   discovery, mandatory initial fetch). Unchanged.
4. If `intro_cfg`: validate the introspection config:
   - `g_introspect_url = params.oidc_introspection_url`; it MUST start with `https://` else
     SRV_ERR + return false.
   - `g_introspect_client_id = params.oidc_client_id`; empty -> SRV_ERR + return false.
   - Read `params.oidc_client_secret_file`: open the file; on failure -> SRV_ERR + return false;
     read all bytes, strip one trailing `\n`; empty secret -> SRV_ERR + return false;
     `g_introspect_client_secret = <bytes>`.
   - Reuse `g_oidc_clock_skew`/`g_oidc_ca_file`/`g_oidc_http_timeout` (already parsed for JWKS; if
     JWKS is not configured, still read `oidc_ca_file` and `oidc_clock_skew` from params so
     introspection-only mode has a CA pin and skew). NOTE for the coder: move the
     `g_oidc_ca_file = params.oidc_ca_file;` assignment so it runs on BOTH paths (today it is set
     in the JWKS branch only).
   - `g_introspect_configured = true;`.
   NO initial network call for introspection (there is nothing to prefetch; the endpoint is hit
   per-token). This differs from JWKS (which prefetches keys).
5. Return true.

Note: `--oidc-audience` is REQUIRED for the JWKS path but is NOT meaningful for pure introspection
(the IdP owns audience checking). If ONLY introspection is configured (no issuer/jwks), the audience
requirement is skipped. Document: for introspection-only mode, audience/algs/issuer JWT rules do
not apply.

New hardened POST helper (server-oidc.cpp, file-scope static, mirrors `https_get` at :125):
```cpp
// RFC 7662 POST: token=<token> (application/x-www-form-urlencoded), HTTP Basic client auth.
// https-only, no redirects, short timeouts, 1 MiB body cap, mandatory server-cert verification
// with optional CA pin (reuses the g_oidc_ca_file / g_oidc_http_timeout settings). On HTTP 200
// returns the response body; any non-200 / redirect / oversize / network error returns false.
static bool introspect_post(const std::string & token, std::string & out_body);
```
Implementation shape (settled):
- `if (g_introspect_url.compare(0, 8, "https://") != 0) return false;`
- `auto [cli, parts] = common_http_client(g_introspect_url);`
- `cli.set_follow_location(false);` (S1), `set_connection_timeout`/`set_read_timeout`
  (`g_oidc_http_timeout`), `cli.set_payload_max_length(1 MiB)` (S5/S-2).
- `#ifdef CPPHTTPLIB_SSL_ENABLED cli.enable_server_certificate_verification(true); if
  (!g_oidc_ca_file.empty()) cli.set_ca_cert_path(g_oidc_ca_file); #endif`
- Client auth: `cli.set_basic_auth(g_introspect_client_id, g_introspect_client_secret);` (httplib
  builds the `Authorization: Basic` header; do NOT hand-build it). This is the RFC 7662
  recommended client authentication.
- Body: `std::string form = "token=" + url_encode(token);` (percent-encode the token value; reuse
  an existing encoder - httplib exposes `httplib::detail::encode_query_param`, OR restrict to the
  base64url/opaque charset which needs no encoding; the coder uses httplib's encoder to be safe).
  Add `&token_type_hint=access_token`.
- `auto res = cli.Post(parts.path, form, "application/x-www-form-urlencoded");`
- `if (!res || res->status != 200) return false;` else `out_body = res->body; return true;`

`server_oidc::introspect(token)` (settled order):
1. `v.ok = false;`. `#ifndef CPPHTTPLIB_OPENSSL_SUPPORT return v; #endif`.
2. `if (!g_introspect_configured) return v;`
3. `key = sha256_hex(token); now = std::time(nullptr);`
4. Cache lookup under `g_introspect_mtx`: if an entry exists and `now < entry.expires_at`, return
   a COPY of `entry.result` (positive OR negative cache hit - both are cached).
5. Miss: `std::string body; if (!introspect_post(token, body)) { /* network/endpoint failure:
   fail-closed, do NOT cache (so a transient outage is retried), return v (ok=false) */ return v; }`
6. Parse `body` with nlohmann in a try; on parse error -> return v (ok=false), do NOT cache.
7. `bool active = json.value("active", false);` (RFC 7662: `active` is REQUIRED; treat missing as
   false, fail-closed).
8. If `!active`: build a negative result (`v.ok=false`), cache it with
   `expires_at = now + g_introspect_neg_ttl` (a few seconds only), return v.
9. If `active`:
   - `v.subject = json.value("sub", "");` (empty sub -> treat as failure: v.ok stays false, cache
     negative, return - a principal with no subject is not usable).
   - `v.issuer = json.value("iss", g_introspect_url);` (fallback to a constant so audit has a
     stable non-PII issuer; never a secret).
   - `int64_t exp = json.value("exp", (int64_t)0); v.expires_at = exp;`
   - `v.claims_json = json.dump();` (whole response, for role extraction).
   - `v.ok = true;`
   - Positive TTL: `ttl = g_introspect_max_pos_ttl;` if `exp > 0` then
     `ttl = std::min<int64_t>(ttl, exp - now);` if `ttl < 0` ttl = 0. Cache with
     `expires_at = now + ttl` (PLAN 4.4: TTL <= min(exp, 60s)). Return v.

Never log the token, the secret, or the response body. `error` is not populated with any token/
secret data.

### 3.4 server-auth wiring (resolve_principal) for introspection

The OIDC branch (server-auth.cpp:1112-1145) currently: JWT-shaped -> validate; non-JWT-shaped ->
fall through to API key. Insert introspection for the non-JWT-shaped case. New precedence within
the Bearer handling:

```
if (g_oidc_enabled) {                 // JWT path (unchanged)
    ... looks_like_jwt(token) -> validate -> principal / 401-no-fallthrough ...
    // (non-JWT-shaped falls out of the JWT block)
}
if (g_introspect_enabled) {           // F010b: opaque-token path
    std::string token = req.authorization;
    if (token.rfind("Bearer ", 0) == 0) token = token.substr(7);
    if (!token.empty() && !server_oidc::looks_like_jwt(token)) {
        oidc_validation v = server_oidc::introspect(token);
        if (v.ok) {
            server_auth_principal p;
            p.authenticated = true;
            p.method     = AUTH_OIDC;         // reuse; issuer distinguishes
            p.issuer     = v.issuer;
            p.subject    = v.subject;
            p.expires_at = v.expires_at;
            p.roles      = extract_oidc_roles(v.claims_json, g_oidc_roles_claim);
            p.perms      = 0;
            for (const auto & role : p.roles) {
                auto it = g_oidc_role_map.find(role);
                if (it != g_oidc_role_map.end()) p.perms |= it->second;
            }
            return p;                          // unmapped roles -> perms=0 -> caller 403
        }
        // inactive/error: FALL THROUGH to API-key auth. An opaque bearer that is not a valid
        // introspection token may still be a llama-server API key (local hash compare, no
        // network, no oracle). Do NOT return anonymous here.
    }
}
// ... existing API-key branch ...
```

Decisions (settled; mirror the fail-closed contract):
- Only the `Authorization: Bearer` value is introspected (not `X-Api-Key`), matching the JWT path.
- JWT-shaped tokens NEVER reach introspection (the JWT block already returned or fell through only
  for non-JWT shape). So a JWT is validated locally (PR4), an opaque token is introspected.
- Active token, roles map -> authenticated with those perms. Active, roles unmapped/absent ->
  authenticated, perms=0 -> 403 (no default role). Same C4 accuracy note as PR3/PR4.
- Inactive or endpoint error -> fall through to API-key auth; if that also fails -> anonymous ->
  401. Rationale for fall-through (vs the JWT 401-no-fallthrough): an opaque string is genuinely
  ambiguous between "IdP opaque token" and "llama-server API key"; the API-key check is a local
  constant-time hash lookup with no timing oracle worth speaking of. FLAGGED as OQ-B1 for the
  challenger (the alternative is: introspection configured => opaque bearer is ALWAYS an
  introspection token, inactive => 401 no fallthrough; that breaks mixed api-key+introspection
  deployments).
- Authorization is ONLY on `p.perms` (F007 Q4): no branching on role names or raw sub.
- Roles claim: reuse `g_oidc_roles_claim` (default `realm_access.roles`). RFC 7662 responses often
  carry roles under `scope` (space-delimited string) or a custom claim; `extract_oidc_roles`
  already handles a string terminal (returns `{that}`) or an array. If an operator's IdP puts
  roles in `scope` as a space-delimited list, that is a single string and maps as one role name;
  splitting `scope` on spaces is NOT in scope for F010b (document; OQ-B2). Operators should map a
  claim that is an array or a single role string.

### 3.5 server-auth init: enforcement flip for introspection

Reuse the exact S1 pattern (parallel to mTLS/OIDC). In `server_auth::init`:
- Add file-scope `bool g_introspect_enabled = false;` next to `g_oidc_enabled`.
- `bool has_introspect = server_oidc::introspection_configured(params);` next to `has_oidc`
  (server-auth.cpp:546).
- Widen the auth-disabled early return (server-auth.cpp:673): add `&& !has_introspect`.
- OR into `g_auth_enabled` (server-auth.cpp:685): `... || has_oidc || has_introspect`.
- The single `server_oidc::init(params)` call already covers introspection (section 3.3 folds both
  into one init). Set `g_introspect_enabled = has_introspect;` after `server_oidc::init` returns
  true (alongside `g_oidc_enabled = true;` at server-auth.cpp:934 - note `g_oidc_enabled` should be
  set only when `has_oidc`, and `g_introspect_enabled` only when `has_introspect`; do not conflate).
- S1 defensive invariant (parallel to the mTLS/OIDC guards): as a final check before init returns
  true, `if (has_introspect && !g_auth_enabled) { SRV_ERR(...); return false; }`.
- `has_oidc` currently gates `server_oidc::init`; change the guard so init runs when
  `has_oidc || has_introspect` (both need it).

### 3.6 F010b fail-closed summary

| Condition | Behavior |
|---|---|
| Introspection configured, no OpenSSL build | server_oidc::init returns false -> abort |
| `--oidc-introspection-url` set, missing/unreadable/empty client-id or secret file | init returns false -> abort |
| introspection URL not https | init returns false -> abort |
| Introspection endpoint 302-redirects / times out / oversize body | fetch failure -> introspect returns ok=false; not cached; token denied (falls to api-key -> likely 401) |
| Endpoint returns `active:false` | ok=false; cached a few seconds; token denied |
| Endpoint returns `active:true` but no `sub` | ok=false (unusable principal); cached negative |
| Active token, roles unmapped/absent | authenticated, perms=0 -> 403 (no default role) |
| Active token, roles map to a role | authenticated with those perms |
| Opaque bearer, introspection inactive, but a valid API key value | falls through to api-key auth (OQ-B1) |
| JWT-shaped bearer | never introspected; handled by the PR4 JWT path |
| Endpoint transient outage for a token cached positive & unexpired | served from cache until TTL (<= min(exp,60s)) |
| Token exp passes mid-SSE stream | NOT enforced here (F013); expires_at is populated |

### 3.7 F010b test strategy (for the test-planner)

New cases in `tools/server/tests/unit/test_oidc.py`, reusing the mock-IdP fixture. Add a mock
introspection endpoint (POST) to the fixture that returns configurable JSON. Cases (negative
first):
1. Opaque bearer, endpoint returns `active:false` -> 401 on a protected route (and falls to
   api-key if one is configured; without an api-key -> 401).
2. Opaque bearer, endpoint returns `active:true` with a role claim mapped to `user` ->
   POST /completions 200, POST /slots/0 403.
3. Opaque bearer, endpoint `active:true` mapped to `admin` -> POST /slots/0 200; audit
   auth_method=oidc, non-anonymous subject_hash; grep the audit log and the process output for the
   token and the client secret -> zero matches.
4. Caching: two identical opaque tokens within the TTL cause exactly ONE POST to the mock endpoint
   (assert the mock's call count); a negative result is cached only a few seconds.
5. `active:true` with no `sub` -> denied.
6. Endpoint unreachable / non-200 / redirect -> denied (fail-closed), and with an api-key
   configured the same opaque value is NOT accepted as an api-key unless it actually matches a key.
7. Startup fail-closed: `--oidc-introspection-url http://...` (non-https) -> refuse to start;
   `--oidc-introspection-url` with no `--oidc-client-id` -> refuse to start; with a nonexistent
   secret file -> refuse to start.
8. Disambiguation: with BOTH JWT-OIDC and introspection configured, a JWT-shaped token is validated
   locally (no introspection POST is made - assert the mock is not called), an opaque token is
   introspected.
9. Introspection-only mode (no `--oidc-issuer`/`--oidc-jwks-url`, only introspection flags):
   enforcement is on (anonymous -> 401), an active opaque token authenticates.

Requires the test venv to be able to run an https mock POST endpoint (reuse the mTLS/OIDC CA
fixture for the mock's TLS cert, passed via `--oidc-ca-file`).

--------------------------------------------------------------------------------
## 4. F010c - WebUI PKCE public client (RECOMMENDED DEFERRAL)

DEFER to oauth2-proxy (PLAN section 9). Effort L. security_sensitive: true. depends_on: F009d.
Status recorded as `in_design` but the RECOMMENDATION is to NOT implement inside the binary/subtree
now. This section documents (a) why, and (b) the minimal shape if the orchestrator overrides.

### 4.1 Why defer (verified reasons)

- The frontend is NOT `tools/server/webui/` (which does not exist). It is `tools/ui/`, a full
  SvelteKit (Svelte 5) + Vite + TypeScript PWA (`@sveltejs/adapter-static`,
  `@vite-pwa/sveltekit`, Storybook, Playwright). It compiles to static assets embedded via
  `tools/ui/embed.cpp` and served by server-http.cpp. This is a large, actively-developed upstream
  subtree - exactly the kind of surface AGENTS.md / CLAUDE.md warn carries a high perpetual rebase
  cost. A PKCE flow woven into it will conflict on nearly every UI rebase.
- `adapter-static` means there is NO server-side route to receive the OAuth redirect/callback and
  NO session backend - by design (PLAN section 9: "do not implement sessions and cookies in C++").
  A browser PKCE flow must be entirely client-side (redirect handling on a static route, token in
  sessionStorage/memory), plus token refresh and expiry handling.
- The IdP must be configured to allow the SPA as a public client with the exact redirect URI and
  to send permissive CORS for the token endpoint - deployment-specific config the server cannot
  own.
- oauth2-proxy in front of llama-server delivers the same browser login with zero binary/subtree
  change, and llama-server already supports the resulting identity via trusted-proxy headers (PR2)
  and Bearer tokens (PR4). This is the variant-B recommendation the plan already prefers.

Current auth injection point (for whoever picks this up later): `getAuthHeaders()` in
`tools/ui/src/lib/utils/api-headers.ts:16-21` reads `config().apiKey` and emits
`Authorization: Bearer <apiKey>`. A PKCE implementation would replace/augment that single function
to emit the OAuth access token instead of the static api key.

### 4.2 Minimal shape IF overridden (do not build without an explicit scope decision)

Public-client Authorization Code + PKCE (S256), entirely in the browser:
1. Config delivery: the SPA needs `authorize_url`, `token_url`, `client_id`, `scope`, and the
   redirect URI. Deliver via a small read-only addition to the server `/props` response (public),
   OR a build-time env. No secret (public client has none).
2. Login: generate `code_verifier` (43-128 char random) + `code_challenge = base64url(SHA256(
   verifier))` via Web Crypto (`crypto.subtle.digest`); store the verifier in `sessionStorage`;
   redirect to `authorize_url?response_type=code&code_challenge_method=S256&...`.
3. Callback: a static SPA route (e.g. `/` handling `?code=...&state=...`) reads the code, exchanges
   it at `token_url` with the stored verifier (public client, no secret) for an access token; store
   in memory/sessionStorage.
4. Use: `getAuthHeaders()` returns the access token as `Bearer`. On 401, re-initiate login (or use
   a refresh token if the IdP issues one to public clients).
5. The access token is then validated server-side by PR4 (JWT) or F010b (opaque) with NO server
   change - the browser is just another Bearer client.

Files (if built): `tools/ui/src/lib/**` (a new `auth/pkce.ts`, changes to `api-headers.ts`, the
settings store, and a callback route); NO C++ change beyond optionally surfacing the IdP config in
`/props`. Because it is a pure frontend feature validated by the existing server auth, it can be
added at any time without touching PR1-PR4 server code. Given the rebase cost, keep it OUT of this
fork and use oauth2-proxy.

--------------------------------------------------------------------------------
## 5. Out of the original F010 coarse scope (not silently dropped)

The coarse F010 description (features.json) and PLAN 7/8.1 also list, under "optional hardening":
- `/cors-proxy` + `/tools` SSRF hardening (PERM_PROXY, host allowlist, private-address block) -
  PLAN section 8.1. This is a real residual risk but is NOT one of the three pieces this task
  decomposed. Recommend a SEPARATE feature (suggested id F014, security_sensitive) if wanted; it
  touches the proxy handlers, not server-mtls/server-oidc.
- Prometheus auth metrics (`llamacpp_auth_failures_total`, `_jwks_refresh_total`,
  `_authz_denied_total`) - PLAN section 7. Also a separate concern (suggested id F015). Metrics
  emission would live in server-auth.cpp counters exposed via the existing `/metrics` handler.

Neither is designed here. They remain tracked under the F010 umbrella as UNSCHEDULED so a future
architect pass can pick them up. Flag to the orchestrator: if "all features" truly means these too,
request a follow-up decomposition.

--------------------------------------------------------------------------------
## 6. Feature mapping

- F010a: `--mtls-crl-file` + `server_mtls_config.crl_file` + `configure` validation +
  `load_crl_file` + `harden_context` CRL block + utils.py threading. Files: common/common.h,
  common/arg.cpp, tools/server/server-mtls.h, tools/server/server-mtls.cpp,
  tools/server/tests/utils.py. Sections 2.
- F010b: three flags + params + secret-from-file + `introspection_configured`/`introspect` +
  `introspect_post` + init restructure + resolve_principal opaque branch + init enforcement flip +
  utils.py threading. Files: common/common.h, common/arg.cpp, tools/server/server-oidc.h,
  tools/server/server-oidc.cpp, tools/server/server-auth.cpp, tools/server/tests/utils.py.
  Sections 3.
- F010c: RECOMMENDED DEFERRAL; if built, `tools/ui/src/lib/**` only. Section 4.

Suggested order (independent): F010a first (smallest, highest value), then F010b if opaque tokens
are needed, F010c deferred.

--------------------------------------------------------------------------------
## 7. Open questions for the challenger

- OQ-A1 (CRL_CHECK_ALL vs CRL_CHECK): the design sets BOTH flags (full-chain revocation, PLAN 4.3).
  With verify-depth 1 this needs one CRL (the issuer's). Confirm full-chain is the right default vs
  leaf-only (`CRL_CHECK` alone), given it fail-closes when a CRL for any chain CA is missing/expired.
- OQ-A2 (no runtime CRL reload): the CRL is loaded once at startup; rotation needs a restart.
  Confirm this is acceptable for PR5 (a SIGHUP/inotify reload is a larger feature; the plan itself
  recommends short-lived certs instead).
- OQ-B1 (opaque-bearer fall-through): when introspection returns inactive/error, the design falls
  through to API-key auth (an opaque string may be an api key). Confirm this vs "introspection
  configured => opaque bearer is always an introspection token, inactive => 401 no fallthrough".
  The trade-off is mixed api-key+introspection deployments vs a marginal timing distinction.
- OQ-B2 (roles from introspection): the design reuses `g_oidc_roles_claim` + `extract_oidc_roles`
  on the introspection response. RFC 7662 commonly returns roles in `scope` (space-delimited
  string). The design does NOT split `scope`; operators must expose an array/string claim. Confirm,
  or decide to add space-split handling for a `scope` claim.
- OQ-B3 (negative-cache duration / no-cache-on-error): negatives cached `g_introspect_neg_ttl` (5s);
  network/parse errors are NOT cached (retried next request). Confirm the 5s window and the
  don't-cache-errors choice (bounded IdP load vs staleness after a revoke).
- OQ-B4 (AUTH_OIDC reuse): introspected principals use `AUTH_OIDC` with `issuer` set to the token's
  `iss` (or the introspection URL). Confirm this is preferable to adding a new
  `AUTH_OIDC_INTROSPECT` enum value (the design avoids enum churn; audit still shows auth_method
  "oidc").
- OQ-C1 (F010c deferral): confirm deferring WebUI PKCE to oauth2-proxy given the `tools/ui`
  SvelteKit relocation and rebase cost, rather than implementing it in-tree.
- OQ-5 (out-of-scope pieces): confirm that `/cors-proxy`+`/tools` SSRF hardening (PLAN 8.1) and
  Prometheus auth metrics (PLAN 7) should be tracked as separate features (F014/F015) rather than
  folded into PR5.

--------------------------------------------------------------------------------
## 8. Challenger revisions (BINDING - these override any conflicting text above)

Applied after the adversarial design-challenge pass. Where sections 0-7 conflict, THIS section
wins. The coder implements section 8 as written; sections 2 and 3 remain the narrative contract
only where section 8 is silent. F010c was NOT reviewed in this pass (explicitly out of scope);
its DEFER recommendation stands unchallenged, and OQ-C1 is left to the orchestrator.

### 8.0 Anchor corrections (the section-1/2/3 line numbers are STALE - use these)

Verified against the current tree. The coder MUST re-grep, not trust either list.

| Design text says | Actual (verified) |
|---|---|
| `has_oidc` at server-auth.cpp:546 | server-auth.cpp:564 (`bool has_oidc = server_oidc::configured(params);`) |
| auth-disabled early return at server-auth.cpp:673 | server-auth.cpp:692 (`} else if (!has_api_keys && !has_trusted_proxies && !has_mtls && !has_oidc) {`) |
| `g_auth_enabled` OR at server-auth.cpp:685 | server-auth.cpp:704 |
| `g_oidc_enabled = true` at server-auth.cpp:934 | server-auth.cpp:959, inside `if (has_oidc) { ... }` at 952-960 |
| resolve_principal OIDC branch at server-auth.cpp:1112-1145 | server-auth.cpp:1139-1170; the API-key branch is 1172-1201; `return server_auth_principal{}` (anonymous) at 1204 |
| S1 invariants | already present at server-auth.cpp:966 (mTLS) and :974 (OIDC); the new one goes next to them |
| `server_mtls::configure` at server-mtls.cpp:18 | correct (18) |
| `server_mtls::harden_context` at server-mtls.cpp:80 | correct (80); the `if (cfg.enabled)` block is 96-105 |
| `https_get` at server-oidc.cpp:125 | correct (125) |
| `server_oidc::init` | server-oidc.cpp:342 |

Two structural facts section 3 does not state and the coder will get wrong otherwise:

1. Everything from `namespace { ... }` (server-oidc.cpp:80) through `set_require_typ` is inside
   `#ifdef CPPHTTPLIB_OPENSSL_SUPPORT` (opened at :77). There is a SECOND, no-OpenSSL
   implementation block at server-oidc.cpp:711-735 (`#else`) with its own `init`, `validate`,
   `set_require_typ`. Every new function needs a stub there too (R6).
2. `server_oidc::configured(params)` returns true when `--oidc-issuer` is set. Therefore
   "introspection-only mode" means NO `--oidc-issuer` AND NO `--oidc-jwks-url`. Setting
   `--oidc-issuer` alongside introspection turns the FULL JWKS path on (mandatory audience,
   discovery, mandatory initial JWKS fetch). Say this in the flag help.

### 8.1 BLOCKER B1 (F010b) - introspection with no audience binding is a cross-service token-replay hole

Section 3.3 note ("`--oidc-audience` ... is NOT meaningful for pure introspection - the IdP owns
audience checking") is WRONG and it is the most serious defect in the design.

Failure scenario: operator runs Keycloak realm `corp` with two clients, `llama` (this server) and
`wiki` (a low-trust internal app). Both are introspected against the same realm endpoint. RFC 7662
does not require the introspection endpoint to scope its answer to the calling resource server, and
Keycloak/Auth0/Okta all return `active: true` for ANY unexpired realm token when the caller
presents valid client credentials. An attacker who obtains a `wiki` access token (much softer
target - it is a normal SPA token, it appears in browser storage, in Referer logs, in a wiki
plugin) replays it as `Authorization: Bearer <wiki-token>` against llama-server. Introspection says
active, `sub` is present, `realm_access.roles` contains the user's REALM roles - which is exactly
what `oidc.role_map` maps. The attacker now has whatever llama-server role that realm role maps to,
up to and including admin, with a token that was never issued for llama-server. PR4's JWT path is
immune to this because it enforces audience containment (server-oidc.cpp:656-668); the
introspection path as designed removes that control entirely.

BINDING FIX (all four parts are mandatory):

- `--oidc-audience` is REQUIRED whenever introspection is configured, exactly as for JWKS. Move the
  existing audience parse (server-oidc.cpp:374-395, "Step 2") so it runs when
  `jwks_cfg || intro_cfg`, not only inside the JWKS branch. Empty -> `init` returns false.
- `introspect()` MUST enforce audience containment on the introspection response before setting
  `v.ok = true`: read `aud` from the response; accept a JSON string or a JSON array of strings;
  require at least one element to be in `g_oidc_audiences`. Absent `aud`, wrong-typed `aud`, or no
  intersection -> DENY (negative-cache it, same as `active:false`). No opt-out flag: an IdP that
  cannot return `aud` on introspection is unsupported by F010b, and that is a documented limit,
  not a runtime toggle.
- If `--oidc-issuer` is set (i.e. the JWKS path is also on), the introspection response MUST carry
  `iss` equal to the configured issuer; absent or mismatched -> DENY. In introspection-only mode
  (no issuer configured) there is nothing to compare against, so no `iss` check runs - this is one
  more reason the audience check above is not optional.
- Clock checks on the response (the IdP is trusted but `active` is not a time check in every
  implementation): if `exp` is present and `exp + g_oidc_clock_skew <= now` -> DENY. If `nbf` is
  present and `nbf > now + g_oidc_clock_skew` -> DENY. Note this also removes the section-3.3
  step-9 bug where an `active:true` response with an already-past `exp` was accepted with a
  clamped TTL of 0.

Section 3.3's "Note: ... the audience requirement is skipped" paragraph is DELETED.

### 8.2 BLOCKER B2 (F010b) - unauthenticated attackers control an outbound POST amplifier and an unbounded cache

`resolve_principal` is called at server-auth.cpp:1225, BEFORE the route is classified (:1231-1236)
and before the public-route short-circuit (:1264). So a request to a PUBLIC route - `GET /health`,
no credential required - that carries `Authorization: Bearer <random>` reaches the introspection
branch. As designed, every distinct token value causes one outbound HTTPS POST to the operator's
IdP, and every `active:false` answer inserts a permanent-until-expiry entry into
`g_introspect_cache`, which has no size cap and no eviction (entries expire logically but are never
erased). Two consequences, both reachable by an unauthenticated remote client:

- IdP amplification / DoS: one cheap inbound request = one authenticated outbound POST to the IdP.
  A single client can convert a few thousand requests per second into the same load against the
  organisation's identity provider, using the server's own client credentials. This is a nastier
  version of the JWKS problem PR4 already had to fix with the S-1 refresh rate limit
  (server-oidc.cpp:96, `g_jwks_refresh_min_interval`).
- Memory exhaustion: distinct random tokens each add a cache entry that is never reclaimed. Even
  with a 5 s negative TTL, at a few thousand distinct tokens per second the map grows without
  bound because nothing ever erases expired entries.

BINDING FIX (all five parts mandatory; each mirrors an existing precedent in this file):

- Pre-flight rejection with NO network call and NO cache write: token length > 4096 bytes -> deny;
  token containing any byte outside the RFC 6750 `b64token` charset
  `[A-Za-z0-9._~+/-]` plus trailing `=` -> deny. (This is a cheap filter, not the security
  control; B1 and the checks below are.)
- Global fixed-window rate limit on introspection POSTs, in the same file-scope state and under the
  same mutex as the cache:
  ```cpp
  int     g_introspect_max_per_sec  = 20;   // env-overridable, see R8
  int64_t g_introspect_window_start = 0;
  int     g_introspect_window_count = 0;
  ```
  Before issuing a POST: if `now != g_introspect_window_start` reset `window_start = now,
  window_count = 0`; if `++g_introspect_window_count > g_introspect_max_per_sec` -> return
  `ok=false` WITHOUT posting and WITHOUT caching. Denying under flood is fail-closed and
  acceptable; a legitimate deployment holding steady above 20 introspections/second is a caching
  problem, not a correctness one, and the limit is env-tunable.
- Hard cache cap: `const size_t g_introspect_cache_max = 4096;`. Before inserting, if
  `g_introspect_cache.size() >= g_introspect_cache_max`, sweep and erase every entry whose
  `expires_at <= now`; if the map is STILL at the cap, skip the insert (the result is still
  returned to the caller). Never clear the whole map on overflow - that would let an attacker flush
  legitimate positive entries on demand.
- The POST MUST NOT be issued while holding `g_introspect_mtx`. Section 3.3's step 4/5 ordering is
  ambiguous and the obvious reading (copy the `refresh_jwks` shape, which does hold `g_jwks_mtx`
  across the network call) turns every cache miss into a global serialization point: one slow IdP
  response stalls every request thread in the process. Required shape: lock -> cache lookup and
  rate-limit accounting -> UNLOCK -> POST + parse -> lock -> insert -> unlock. A duplicate
  concurrent POST for the same token is acceptable; a stalled server is not.
- Document in the flag help that `--oidc-introspection-url` makes every unauthenticated request
  carrying a Bearer header a potential outbound request, and that the endpoint should be reachable
  only from the server.

### 8.3 Binding revisions - F010a (mTLS CRL)

R1 (should-fix) - a CRL with no `nextUpdate` is a silent forever-CRL; a CRL already past
`nextUpdate` is a boot-time brick. Both must be caught at startup.
The task asked whether a stale CRL is fail-open. Answer: OpenSSL treats a CRL whose `nextUpdate`
has passed as `X509_V_ERR_CRL_HAS_EXPIRED` and fails the handshake, so an EXPIRED CRL is
fail-CLOSED. But a CRL with NO `nextUpdate` field at all never expires, and since F010a has no
runtime reload (OQ-A2), such a CRL silently pins the revocation list to whatever was on disk at
boot, forever - that IS a fail-open path, and it is exactly what a hand-rolled
`x509.CertificateRevocationListBuilder` fixture or a minimal CA script produces if
`next_update` is omitted. In `load_crl_file`, for each parsed CRL:
- `const ASN1_TIME * nu = X509_CRL_get0_nextUpdate(crl);` if `nu == nullptr` -> SRV_ERR
  ("CRL has no nextUpdate; refusing to load a CRL that never expires") -> return false.
- `X509_cmp_current_time(nu) < 0` (nextUpdate already in the past) -> SRV_ERR -> return false.
  Rationale: such a CRL rejects EVERY client at handshake time; failing at startup with a clear
  message is strictly better than a server that boots healthy and then 100%-rejects mTLS.
- Additionally SRV_WRN if `nextUpdate` is less than 24 h away (the operator has a restart to
  schedule). Do NOT log the CRL issuer DN (CLAUDE.md: never log full DNs); logging the count and
  the nextUpdate timestamp is fine, a timestamp is not PII.

R2 (should-fix) - section 2.1/2.2 help text about CRL_CHECK_ALL is factually wrong for the root
and will make operators chase a CRL they cannot produce. OpenSSL's `check_revocation()` drops the
last chain element when it is self-signed, so with `X509_V_FLAG_CRL_CHECK_ALL` and the default
`--mtls-verify-depth 1` (leaf + self-signed root) only the LEAF is CRL-checked and exactly ONE
CRL - the one issued by the client CA - is needed. Fix the help text and section 2.1 bullet 2 to
say "a CRL is required for every non-self-signed CA in the chain; with the default verify-depth 1
that is exactly one CRL, issued by the configured client CA. A self-signed root does not need its
own CRL."

R3 (consider) - `load_crl_file` cannot tell that the loaded CRL has anything to do with the
configured client CA. Pointing `--mtls-crl-file` at an unrelated (but valid, unexpired) CRL passes
every check in section 2.3 and the server boots, then rejects all clients with
`X509_V_ERR_UNABLE_TO_GET_CRL`. Do not add issuer-matching logic (it would need the CA DN, which we
must not log anyway); instead the flag help must name `X509_V_ERR_UNABLE_TO_GET_CRL` as the symptom
of a mismatched CRL so the operator can diagnose it from `openssl s_client` output.

R4 (should-fix) - in `optional` mode, revocation degrades to anonymous rather than blocking the
client. `harden_context` keeps `SSL_VERIFY_PEER` without `FAIL_IF_NO_PEER_CERT` for optional mode
(server-mtls.cpp:102-104), so a client whose cert is revoked has its HANDSHAKE rejected, then
simply reconnects presenting NO cert and is treated as anonymous - after which any other credential
(API key, Bearer) still works. This is correct behaviour, not a bug, but the F010a acceptance
criterion "rejected at the TLS handshake in both optional and required mode" must be read as "the
connection that presents the revoked cert fails"; the test must NOT additionally assert that the
revoked identity cannot reach the server by other means. State this in the flag help: in `optional`
mode a CRL revokes the mTLS IDENTITY, it does not blocklist the client.

R5 (confirmed correct, do not change) - the ordering and store choice in section 2.3 are right.
`harden_context` is called at server-http.cpp:154, after the 4-arg `httplib::SSLServer` ctor
(server-http.cpp:131-137) has loaded the client CA into the CTX default store, and after the
`is_valid()` check at :146. mTLS without a server cert/key already aborts at server-http.cpp:121-124,
so a `crl_file` that survives `configure()` is GUARANTEED to reach `harden_context`; there is no
path where the CRL is silently skipped. `SSL_CTX_get_cert_store` is the correct store.
`server-http.cpp` stays unchanged.

### 8.4 Binding revisions - F010b (introspection), beyond B1/B2

R6 (blocker-adjacent, fail-open on a no-OpenSSL build) - the `#else` stub `init` at
server-oidc.cpp:715-721 early-returns `true` when `!configured(params)`. With introspection-only
config on a build without OpenSSL, `configured()` is false, so the stub returns TRUE and the server
boots with `g_introspect_enabled` set but `introspect()` permanently unable to run. Every opaque
token is then denied, so this is not an authentication bypass, but it IS a silent
misconfiguration that section 3.3's "step 2" does not actually implement, because step 2 sits in
the wrong compilation branch. BINDING: the `#else` block must contain
`if (!configured(params) && !introspection_configured(params)) { return true; }` followed by the
existing SRV_ERR + `return false`, and must also define no-OpenSSL stubs for
`server_oidc::introspect` (returns `ok=false`) and `server_oidc::introspection_configured` - or,
cleaner, define `introspection_configured` next to `configured` at server-oidc.cpp:26 OUTSIDE both
branches, since it is a pure params check like `configured` and `looks_like_jwt`.

R7 (blocker-adjacent, precedence) - the section-3.4 branch placement is wrong. See 8.5 (OQ-B1) for
the replacement precedence. Section 3.4's code block is SUPERSEDED.

R8 (should-fix, testability) - section 3.7 case 4 ("a negative result is cached only a few
seconds") and the positive-TTL criterion are not testable as designed: 5 s and 60 s are compiled-in
and the pytest harness cannot wait on them deterministically. Add test-only env overrides using the
exact pattern already in `server_oidc::init` (server-oidc.cpp:466-511: `std::stoi` in a try, ignore
malformed, keep default):
`LLAMA_OIDC_INTROSPECT_POS_TTL_SECONDS`, `LLAMA_OIDC_INTROSPECT_NEG_TTL_SECONDS`,
`LLAMA_OIDC_INTROSPECT_MAX_PER_SECOND`. Without these, three F010b acceptance criteria are
untestable and the coder will be tempted to `time.sleep(60)`.

R9 (should-fix, secret hygiene) - three concrete leak paths section 3.2 does not close:
- `common_http_client` (common/http.h:100) parses URL userinfo and calls
  `cli.set_basic_auth(parts.user, parts.password)` from it. If an operator writes
  `https://id:secret@idp/introspect`, that secret is in the URL - and `https_get` logs the raw URL
  on failure (server-oidc.cpp:127, :156, :177), which is the pattern the coder will copy. BINDING:
  `init` REJECTS an `--oidc-introspection-url` whose authority contains `@` (SRV_ERR: "userinfo in
  --oidc-introspection-url is not supported; use --oidc-client-id/--oidc-client-secret-file"), and
  `introspect_post` NEVER logs the URL - log a fixed string such as
  `"OIDC: introspection request failed (HTTP %d)"`.
- `set_basic_auth` builds `base64(client_id ":" secret)`. A `client_id` containing `:` silently
  corrupts the split at the IdP; a secret or id containing CR/LF/NUL is a malformed-header hazard.
  BINDING: `init` rejects a `client_id` or secret containing any byte outside printable ASCII
  0x21-0x7E, and rejects a `client_id` containing `:`.
- Secret file trimming: section 3.2 says "trim a single trailing newline". On Windows/CRLF that
  leaves a `\r` in the secret and every introspection silently 401s at the IdP. BINDING: read the
  file in BINARY mode and strip ALL trailing `\r` and `\n`; if what remains contains an interior
  newline, fail closed (that is the wrong file, e.g. a PEM).

R10 (should-fix, request forgery into the introspection POST) - the token goes into an
`application/x-www-form-urlencoded` body. It is fully attacker-controlled. Un-encoded, a token of
`x&token_type_hint=refresh_token&client_id=other` injects parameters into the request the server
makes with its OWN client credentials. Section 3.3 offers `httplib::detail::encode_query_param` as
one option; that symbol is NOT declared in `vendor/cpp-httplib/httplib.h` in this tree (verified by
grep) and is an internal detail namespace that upstream may move on any httplib bump. BINDING:
implement a 12-line file-static `form_urlencode` in server-oidc.cpp - pass `A-Za-z0-9-_.~` through,
percent-encode every other byte as `%XX` uppercase - and use it for the token value. This is not
hand-rolled crypto; it is RFC 3986 unreserved-set escaping, and it removes a vendored-internal-API
dependency that would break on rebase. Also encode `token_type_hint`'s value or emit it as the
literal `&token_type_hint=access_token` (it is a constant).

R11 (should-fix, audit) - section 3.4 sets `p.issuer = v.issuer` where `v.issuer` came from the
introspection response's `iss`. Two problems: (a) the design's own OQ-B4 rationale ("issuer
differentiates, audit still shows auth_method oidc") is false - `audit_emit` (server-auth.cpp:441-475)
writes `subject_hash`, `method`, `path`, `decision`, `required_perm`, `auth_method`, `peer_ip`,
`request_id` and NEVER writes `issuer`, so nothing in the audit log distinguishes an introspected
principal from a JWT one; (b) copying an IdP-controlled free-form string into a principal field is
gratuitous. BINDING: set `v.issuer` to `g_oidc_issuer` when it is non-empty, else the literal
constant `"oidc-introspection"`. Never copy the response `iss` into the principal (it is still
CHECKED against the configured issuer per B1, just not stored). If distinguishing the two OIDC
sub-methods in the audit log is wanted, that is a separate change to `audit_emit` and is NOT part
of F010b.

R12 (should-fix, half-applied enforcement flip - the S1 pattern) - the exact edits, at the real
anchors, all six of which are required. Missing any ONE of them is a silent
introspection-configured-but-not-enforcing or enforcing-but-not-working state:
1. server-auth.cpp:564, next to `has_oidc`: `bool has_introspect = server_oidc::introspection_configured(params);`
2. server-auth.cpp:692, the auth-disabled early return: add `&& !has_introspect`.
3. server-auth.cpp:704: `g_auth_enabled = has_policy || has_api_keys || has_trusted_proxies || has_mtls || has_oidc || has_introspect;`
4. server-auth.cpp:952: widen the gate to `if (has_oidc || has_introspect)`. Keep
   `server_oidc::set_require_typ(g_oidc_require_typ)` inside it (harmless when introspection-only).
   `g_oidc_enabled = true;` at :959 stays gated on `has_oidc` ALONE; add
   `if (has_introspect) g_introspect_enabled = true;`. Conflating them is a real hazard: with
   `g_oidc_enabled` wrongly true in introspection-only mode, a JWT-shaped Bearer enters the JWT
   block, `validate()` runs against an empty `g_oidc_algs`/unset issuer, fails, and returns
   anonymous at :1167 with no fall-through - a silent lockout that no test in section 3.7 catches.
5. server-auth.cpp:977, next to the two existing S1 invariants:
   `if (has_introspect && !g_auth_enabled) { SRV_ERR("OIDC introspection is enabled but auth enforcement is off; refusing to start\n"); return false; }`
6. NEW, and required by the precedence change in 8.5: after `default_role` is resolved
   (server-auth.cpp:889-905), `if (has_introspect && g_default_perms != 0) { SRV_ERR("policy default_role cannot be combined with --oidc-introspection-url; an unknown bearer would be authorized by the default role before introspection runs\n"); return false; }`.
   Without this, the API-key branch at server-auth.cpp:1191-1199 authenticates EVERY unknown bearer
   with `g_default_perms` and introspection is never reached - a total bypass of F010b.

R13 (consider) - introspection configured with no policy file means `g_oidc_role_map` is empty
(server-auth.cpp:834 clears it; :864-886 only populates it from `policy["oidc"]["role_map"]`), so
every introspected principal gets `perms = 0` and 403s everywhere. Fail-closed, but the operator
sees a server that authenticates and then denies everything. Emit `SRV_WRN` at init when
`has_introspect && g_oidc_role_map.empty()`. Do not make it fatal - that would change F009
behaviour for the JWT path too.

R14 (consider, rebase) - F010b adds no routes, so the `assert_routes_covered` guarantee
(server-auth.cpp:1334) is untouched and the "new upstream endpoint stays private after rebase"
property is unaffected by either sub-feature. The only rebase-fragile external couplings F010b
introduces are `common_http_client` (common/http.h, an upstream file whose
`set_follow_location(true)` default MUST keep being overridden - see section 3.3) and the httplib
`Client::set_basic_auth`/`set_payload_max_length` API (both public, verified present at
httplib.h:2754 and :2766). R10 removes the third and worst one.

### 8.5 ANSWERS to section 7 open questions (each is a decision, not a discussion)

ANSWER OQ-A1 (CRL_CHECK vs CRL_CHECK_ALL): KEEP BOTH FLAGS,
`X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL`. At the default `--mtls-verify-depth 1` with a
self-signed root, OpenSSL's `check_revocation()` skips the self-signed last chain element, so
CRL_CHECK_ALL is behaviourally IDENTICAL to CRL_CHECK there - one CRL from the client CA suffices
and there is no extra operational cost at the default. At depth > 1, leaf-only checking would
silently ignore a revoked INTERMEDIATE, which is precisely the failure a CRL exists to catch.
Apply R2: the help text and section 2.1 must stop claiming a self-signed root needs its own CRL.

ANSWER OQ-A2 (no runtime CRL reload): ACCEPTED for F010a, conditional on R1. Load-once is fine
only because startup now proves the CRL has a `nextUpdate` and that it is in the future; without R1
the no-reload decision converts a missing optional X.509 field into a permanent, silent revocation
freeze. Runtime reload (SIGHUP or mtime poll) is explicitly deferred to a NEW backlog feature -
suggested id F016, `todo`, not scheduled in PR5 - and the flag help must say a restart is required
to rotate.

ANSWER OQ-B1 (opaque-bearer fall-through): NEITHER of the two options offered. REORDER instead.
Move the introspection branch to AFTER the API-key branch. Final precedence in `resolve_principal`:
mTLS -> trusted-proxy -> OIDC JWT (only when `g_oidc_enabled` AND `looks_like_jwt`) -> API key
(local SHA-256 lookup) -> introspection (opaque Bearer) -> anonymous.
This dominates both alternatives the architect posed. Hard-401-no-fallthrough would BREAK the
common `Authorization: Bearer <api-key>` pattern - which this repo's own WebUI emits verbatim
(`getAuthHeaders()`, tools/ui/src/lib/utils/api-headers.ts) - the moment introspection is turned
on. Fall-through-after-introspection sends a network POST for every mistyped API key, feeding B2.
Checking the local hash FIRST costs nothing, never leaves the process for a valid key, keeps mixed
api-key + introspection deployments working unchanged, and leaves nothing to fall through TO
(anonymous is next), so the "inactive -> 401" property the architect wanted holds anyway.
Exact branch contract for the coder:
- Placement: between the API-key branch (ends server-auth.cpp:1201) and the final
  `return server_auth_principal{};` (server-auth.cpp:1204).
- Guard: `if (g_introspect_enabled)`; take the token from `req.authorization` ONLY, and ONLY when
  it starts with the literal `"Bearer "` (a raw `Authorization: <key>` or an `X-Api-Key` value must
  never trigger a network call). Empty after stripping -> skip.
- Reaching this point with a JWT-shaped token implies `g_oidc_enabled == false` (the JWT block at
  :1139-1170 returns in both of its outcomes), so introspect it unconditionally - in
  introspection-only mode a JWT-formatted opaque token MUST still be introspected, and section
  3.4's `!looks_like_jwt(token)` condition would wrongly skip it.
- On `v.ok`: build the principal exactly as in section 3.4 (AUTH_OIDC, `g_oidc_role_map`,
  `perms = 0` for unmapped roles) with R11's issuer rule, and return it.
- On failure: fall out of the branch to `return server_auth_principal{}` (anonymous -> 401).
- R12 item 6 (`default_role` + introspection = startup abort) is REQUIRED by this ordering.

ANSWER OQ-B2 (roles from an RFC 7662 `scope` string): SPLIT IT, narrowly. In `extract_oidc_roles`
(server-auth.cpp:1078-1081), when the terminal node is a STRING and the LAST dot-separated segment
of the configured claim path is exactly `scope` or `scp`, split the value on whitespace (space and
tab) and return each non-empty piece as a role; for every other claim name, keep today's behaviour
(the whole string is one role). Rationale: `scope` is space-delimited by RFC 6749/7662 and RFC 9068
alike, so this is correct for the JWT path too; not splitting leaves an operator who sets
`roles_claim: scope` trying to name a role `"openid profile llm.admin"`, which fails closed but is
a pure footgun. Scoping the change to the two claim names `scope`/`scp` means no existing F009
test (all of which use `realm_access.roles`) changes behaviour. Add one positive test
(`scope: "openid llm.admin"` maps to the `llm.admin` role) and one negative
(a non-`scope` string claim is still treated as a single role).

ANSWER OQ-B3 (negative-cache duration / no-cache-on-error): CONFIRMED as designed - 5 s negative
TTL, network/parse/HTTP errors NOT cached - but ONLY because B2's rate limit now bounds the retry
storm that "do not cache errors" would otherwise permit. Both TTLs and the rate limit become
env-overridable per R8. Additionally: a DENY produced by the B1 checks (audience mismatch, issuer
mismatch, expired, missing `sub`) is cached as a NEGATIVE result like `active:false` - it is a
property of the token, not a transient failure - whereas a rate-limit rejection is NOT cached
(it is transient by definition). The 60 s positive ceiling stands (PLAN 4.4); document that a
revoked token remains accepted for up to `min(exp - now, 60 s)`.

ANSWER OQ-B4 (AUTH_OIDC reuse): CONFIRMED - reuse `AUTH_OIDC`, add no enum value. But the stated
justification is wrong and must not be repeated in the code comment: `audit_emit` never writes
`issuer`, so an introspected principal is INDISTINGUISHABLE from a JWT one in the audit log (both
log `auth_method: "oidc"`). Accept that for F010b, apply R11, and note it as a known forensics gap
rather than pretending `issuer` differentiates.

ANSWER OQ-C1 (F010c deferral): NOT REVIEWED in this pass - explicitly out of scope. The section-4
DEFER recommendation stands unchallenged; the orchestrator decides.

ANSWER OQ-5 (out-of-scope pieces): CONFIRMED - `/cors-proxy` + `/tools` SSRF hardening and
Prometheus auth metrics stay OUT of PR5 and are cut as separate features F014 and F015. One
correction to section 5's framing: B2 shows F010b itself introduces a new outbound-request surface
reachable pre-authentication, so the SSRF-hardening feature (F014) is now MORE relevant, not less,
and its host-allowlist idea should be considered for the introspection URL as well when it is
designed. Also cut F016 (runtime CRL reload) per OQ-A2.

### 8.6 Test-plan corrections (for the test-planner)

- Section 2.5 case 4 (expired-CRL handshake test) is REPLACED by a STARTUP test under R1: a CRL
  whose `nextUpdate` is in the past -> server refuses to start; a CRL built WITHOUT `next_update`
  -> server refuses to start. Both are deterministic; the old handshake-timing variant was not.
- Section 2.5 case 1 must assert only that the connection PRESENTING the revoked cert fails
  (transport/SSL error). Per R4 it must NOT assert that the same client cannot connect anonymously
  in `optional` mode.
- Section 3.7 needs three NEW cases, all currently absent and all covering blocker-level behaviour:
  (a) B1 audience - introspection returns `active:true` with `aud` NOT containing the configured
  audience -> 401; and with `aud` absent entirely -> 401.
  (b) B1 issuer - with `--oidc-issuer` also configured, `active:true` with a mismatched `iss` -> 401.
  (c) OQ-B1 precedence - with BOTH `--api-key` and introspection configured, `Authorization: Bearer
  <valid-api-key>` still authenticates as `auth_method=api_key` and the mock introspection endpoint
  records ZERO hits.
  Plus (d) R12 item 6 - a policy with `default_role` set plus `--oidc-introspection-url` refuses to
  start.
- Section 3.7 case 4 (caching) requires the R8 env overrides to be deterministic. The existing mock
  IdP (tools/server/tests/unit/test_oidc.py: `_IdPHandler`, `MockIdP`, `jwks_hits`) is GET-only;
  the planner must add `do_POST` plus an `introspect_hits` counter and a configurable JSON body,
  mirroring `jwks_hits`. It must also assert the received `Authorization: Basic` header decodes to
  the configured client id and the secret read from the file - that is the only direct test that
  the secret plumbing works.
- The B2 rate limit is testable: set `LLAMA_OIDC_INTROSPECT_MAX_PER_SECOND=1`, fire two distinct
  opaque tokens in the same second, assert exactly one `introspect_hits` increment and a 401 for
  the second. The cache CAP is NOT practically testable through the pytest harness (4096 distinct
  tokens per test is too slow); state that explicitly rather than writing a flaky test - it is
  covered by code review.
- `ServerProcess` (tools/server/tests/utils.py) gains four fields, mirroring the existing
  `mtls_*`/`oidc_*` blocks at utils.py:107-119 and :280-305: `mtls_crl_file`,
  `oidc_introspection_url`, `oidc_client_id`, `oidc_client_secret_file`.

### 8.7 Confirmed correct - do NOT change

The F010a store choice and call ordering (R5). Reuse of `oidc_validation` and `AUTH_OIDC`
(OQ-B4). Reuse of `g_oidc_roles_claim` / `extract_oidc_roles` / `g_oidc_role_map` so introspected
and JWT principals map roles through one code path. Secret from FILE only, never argv, never env
VALUE, never logged (R9 hardens the leak paths, it does not change the model). https-only, no
redirects, short timeouts, 1 MiB body cap on the introspection POST, mirroring `https_get`
(server-oidc.cpp:125-180). Token HASH as the cache key, raw token never stored. `active` missing
treated as false. `active:true` without `sub` denied. Unmapped roles -> `perms = 0` -> 403, never a
default role. Keeping F013 (exp during long SSE streams) out of F010b. The three sub-features
remaining independent and shippable separately.
