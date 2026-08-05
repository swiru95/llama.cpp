# Implementation Plan: RBAC (admin/user) + OIDC + mTLS in `llama-server`

Repo state: `ggml-org/llama.cpp`, branch `master`, July 2026. Note: `tools/server/` was recently split into many files (`utils.hpp` no longer exists). The layout changes every few weeks - verify file names and line numbers before starting.

## 0. License - answer to the preliminary question

llama.cpp is MIT-licensed. You may fork it, modify it, keep your modifications closed, and distribute commercially; the only obligation is to preserve the copyright notice and the license text.

The practical consequence, more important than the license itself: upstream will most likely **not** accept these changes. The maintainers deliberately keep server-side auth at the level of "a single API key; everything else is the reverse proxy's job". This means you take on the perpetual cost of rebasing onto code that is refactored aggressively (see: the disappearance of `utils.hpp`, the split of `server.cpp` into 15 files).

## 1. Architectural decision - read this before writing a single line of C++

Before you touch the code: 90% of this task should stand **in front of** the server, not inside it.

| Variant | OIDC | mTLS | RBAC | Maintenance cost | Risk |
|---|---|---|---|---|---|
| A. Proxy (Envoy / oauth2-proxy / NGINX+njs / Kong) | proxy | proxy | proxy (ext_authz) | low | low |
| B. Hybrid (**recommended**) | proxy | proxy | in the server | medium | low |
| C. Everything in llama-server | jwt-cpp | cpp-httplib+OpenSSL | in the server | high | high |

Arguments against C that you must consciously reject if you choose it anyway:

* You are writing JWT validation and X.509 handling in C++, inside a process that simultaneously parses untrusted input (GGUF, multipart, Jinja) - you enlarge the attack surface in the worst possible place.
* JWKS = an HTTP client + cache + key rotation + resilience against DoS-ing your own IdP. This is non-trivial.
* No isolation: one process serves all tenants and shares the KV cache and the slot pool.
* A rebase onto upstream with every larger change to `server-http.cpp`.

When C is justified: air-gap, appliance/edge with a single binary, no sidecar/service mesh available, or a hard requirement that "security must not depend on the correct configuration of an external component".

Variant B in practice: the proxy terminates mTLS and verifies OIDC, then injects headers (`X-Auth-Subject`, `X-Auth-Roles`, `X-Forwarded-Client-Cert`), and llama-server:

* trusts those headers **only** when the connection came from an address on the `--auth-trusted-proxies` list,
* enforces RBAC at the route level (because only the server knows what `/slots/:id` does vs `/completions`).

The plan below describes variant C (the full build-out), with notes on what drops out under B.

## 2. Target architecture

Request processing chain (new elements marked [N]):

```
TLS handshake
  └─ [N] client certificate verification (mTLS)  -> principal.cert_dn / SAN
pre_routing_handler (server-http.cpp)
  ├─ CORS
  ├─ middleware_server_state (503 while the model is loading)
  ├─ [N] middleware_authn   -> principal { subject, roles[], method }
  │      order: mTLS -> OIDC Bearer -> API key (legacy)
  └─ [N] middleware_authz   -> route -> required permission; deny-by-default
handler (server-context.cpp / server-models.cpp / ...)
  └─ [N] access to the principal via thread_local (audit, /slots filtering)
```

### Permission model

Do not make a `bool is_admin`. Make **permissions**, with roles as named sets of them - adding a third role (`observer`, `service`) then requires no change in the policy code.

```
INFER        - /completions, /chat/completions, /embeddings, /rerank, /responses, /v1/messages,
               /infill, /tokenize, /detokenize, /apply-template, /audio/transcriptions
READ_STATE   - /props (GET), /slots (GET), /lora-adapters (GET)
METRICS      - /metrics
ADMIN_STATE  - /props (POST), /slots/:id (POST: save/restore/erase), /lora-adapters (POST)
ADMIN_MODELS - /models (POST/DELETE), /models/load, /models/unload, /models/sse
PROXY        - /cors-proxy, /tools   (SSRF! see section 8)

user  = { INFER }
admin = { INFER, READ_STATE, METRICS, ADMIN_STATE, ADMIN_MODELS }
```

Public without authentication (configurable, default matching today's behavior): `/health`, `/v1/health`, WebUI assets. `/models` and `/v1/models` are public today - that is a model-inventory leak. Change the default to require `READ_STATE`, with a compatibility flag.

## 3. File-by-file change map

| File | Kind | Scope |
|---|---|---|
| `tools/server/server-auth.h` | new | types: `server_auth_principal`, `server_auth_policy`, the `server_auth` interface |
| `tools/server/server-auth.cpp` | new | policy loading, claim/DN -> role mapping, authz decision, path normalization |
| `tools/server/server-oidc.h/.cpp` | new | discovery, JWKS cache, JWT verification (or RFC 7662 introspection) |
| `tools/server/server-mtls.h/.cpp` | new | `SSL_CTX` configuration, identity extraction from the certificate, CRL |
| `tools/server/server-http.h` | modified | `principal` field in `server_http_req` |
| `tools/server/server-http.cpp` | modified | SSLServer with client CA, new middleware, thread_local principal |
| `tools/server/server.cpp` | modified | route -> permission table, registration alongside routing |
| `tools/server/CMakeLists.txt` | modified | new sources, options `LLAMA_SERVER_OIDC`, `LLAMA_SERVER_MTLS` |
| `common/common.h` | modified | configuration fields in `common_params` |
| `common/arg.cpp` | modified | new CLI flags + environment variables |
| `tools/server/tests/utils.py` | modified | passing the new flags to `ServerProcess` |
| `tools/server/tests/unit/test_authz.py` | new | route x role matrix |
| `tools/server/tests/unit/test_oidc.py` | new | mock IdP + JWKS, negative cases |
| `tools/server/tests/unit/test_mtls.py` | new | CA/certs generated in a fixture |
| `tools/server/README.md` | modified | flag documentation |
| `tools/server/webui/` | modified (optional) | PKCE in the browser instead of the "API key" field |

## 4. Implementation details

### 4.1 `tools/server/server-auth.h` (new)

```cpp
#pragma once
#include <string>
#include <vector>
#include <cstdint>

enum server_auth_method { AUTH_NONE, AUTH_API_KEY, AUTH_MTLS, AUTH_OIDC };

enum server_perm : uint32_t {
    PERM_INFER        = 1u << 0,
    PERM_READ_STATE   = 1u << 1,
    PERM_METRICS      = 1u << 2,
    PERM_ADMIN_STATE  = 1u << 3,
    PERM_ADMIN_MODELS = 1u << 4,
    PERM_PROXY        = 1u << 5,
};

struct server_auth_principal {
    bool         authenticated = false;
    std::string  subject;        // sub (OIDC) or SHA256(DN) (mTLS) or API key hash
    std::string  issuer;
    std::vector<std::string> roles;
    uint32_t     perms  = 0;
    server_auth_method method = AUTH_NONE;
    int64_t      expires_at = 0; // exp from the token; 0 = no expiry
};

struct server_auth {
    static bool init(const common_params & params);          // loads policy, JWKS, mappings
    static server_auth_principal authenticate(              // does not throw
        const std::string & authorization_header,
        const std::string & x_api_key_header,
        const void * ssl /* SSL* or nullptr */,
        const std::string & peer_addr);
    static bool authorize(const server_auth_principal &, const std::string & normalized_path,
                          const std::string & method);
    static uint32_t required_perm(const std::string & normalized_path, const std::string & method);
};
```

Policy from a JSON file (`--auth-policy-file`), with a sensible compiled-in default:

```json
{
  "roles": { "admin": ["INFER","READ_STATE","METRICS","ADMIN_STATE","ADMIN_MODELS"],
             "user":  ["INFER"] },
  "oidc":  { "roles_claim": "realm_access.roles",
             "role_map": { "llm-admins": "admin", "llm-users": "user" } },
  "mtls":  { "identity_source": "san_uri",
             "role_map": { "spiffe://corp/ns/ml/sa/ops": "admin", "spiffe://corp/ns/*": "user" } },
  "public_endpoints": ["/health", "/v1/health"],
  "default_role": null
}
```

`default_role: null` = deny by default. Do **not** put a default value of "user" here.

### 4.2 `server-http.cpp` - the enforcement point

You replace the current `middleware_validate_api_key` (around line 208) with a chain. Three critical things:

**a) Path normalization before policy matching.** `req.path` in `pre_routing_handler` contains `params.api_prefix`. You must:

1. strip the prefix (and reject the request if the prefix is absent),
2. decode percent-encoding **once** and reject if, after decoding, `/`, `..`, or `%` appear,
3. collapse repeated `/`, remove the trailing `/`,
4. compare case-sensitively against the allowlist; deny-by-default for unknown paths.

This is the most common bug class in this kind of RBAC: `/Slots`, `/slots/`, `//slots`, `/v1/../slots` bypass naive string matching. Write unit tests for this **first**, before the policy.

**b) Passing the principal to the handlers.** `pre_routing_handler` and the handler execute on the same cpp-httplib thread within a single request, so:

```cpp
// server-http.cpp
thread_local server_auth_principal t_principal;
```

set in the middleware, copied into `server_http_req` in `get_params(...)`/request construction (lines ~583, ~630, ~647 - three places: `get`, `post`, `del`). Clear it **on entry to the middleware**, not on handler exit - if a handler returns early, the previous request's stale principal would linger on that thread. Note: `register_gcp_compat()` constructs a `server_http_req` internally (around line 802) - you must pass the principal there too, or block that path.

**c) Fail-closed.** If `server_auth::init()` fails (e.g. JWKS unreachable at startup) - the server does not start. Do not degrade to "let everything through".

### 4.3 mTLS - `server-mtls.cpp` + `server-http.cpp` (~line 107)

cpp-httplib supports this natively; constructor change:

```cpp
srv = std::make_unique<httplib::SSLServer>(
    params.ssl_file_cert.c_str(),
    params.ssl_file_key.c_str(),
    params.mtls_client_ca_file.empty() ? nullptr : params.mtls_client_ca_file.c_str(),
    params.mtls_client_ca_dir.empty()  ? nullptr : params.mtls_client_ca_dir.c_str());
```

Providing a client CA makes httplib set `SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT`. Then reach for `srv->ssl_context()` and tighten what httplib does not do:

* `SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)` (or TLS 1.3 only),
* `SSL_CTX_set_verify_depth(ctx, N)` - without this you accept arbitrarily long chains,
* cipher / group lists,
* CRL: `X509_STORE_load_locations` + `X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL)`,
* optionally a custom `verify_callback` for logging the rejection reason (bare `SSL_VERIFY_PEER` only gives you "handshake failed" in the client's log and nothing in the server's).

Identity: `httplib::Request` has an `ssl` field (with `CPPHTTPLIB_OPENSSL_SUPPORT`); from it, `SSL_get1_peer_certificate()` -> extract SAN URI / SAN DNS, **not** CN. CN is deprecated and collision-prone; if you must use it, compare the whole DN, not the CN alone.

Revocation is the hardest piece. CRL requires file distribution and refreshing; OCSP stapling is not exposed by httplib. The realistic recommendation: short-lived certificates (SPIFFE/SVID, 1-24 h) instead of CRL - this solves revocation via expiry.

Behind a TLS terminator (variant B): identity from the `X-Forwarded-Client-Cert` header, accepted only when `peer_addr` is in `--auth-trusted-proxies`, and **always stripped from the request on entry** so a client cannot forge it.

### 4.4 OIDC - `server-oidc.cpp`

Default: local JWT validation (access token), no callback and no sessions. llama-server is meant to be a resource server, not a relying party - do not implement the authorization code flow in C++.

Verification (the order matters):

1. Parse the header, extract `kid` and `alg`.
2. Algorithm whitelist from configuration (`RS256,ES256`). Reject `none`, and reject `HS*` whenever the key comes from JWKS - that is the classic algorithm confusion (a public key used as an HMAC secret).
3. Fetch the key by `kid` from the JWKS cache. Unknown `kid` -> a single refresh, rate-limited (e.g. max 1 per 5 min, with jitter) - otherwise you have a DoS amplifier pointed at your own IdP.
4. Verify the signature, then `iss` (exact match), `aud` (must contain the configured `--oidc-audience`), `exp`, `nbf`, `iat` with clock tolerance <= 60 s.
5. Optionally `typ == "at+jwt"` - protects against an ID token being substituted for an access token.
6. Map the roles claim -> local roles. No match -> denial, **not** a default role.

Dependencies: `jwt-cpp` (header-only, MIT, needs OpenSSL which you already use) in `vendor/jwt-cpp/`. Alternative - hand-rolled verification on `EVP_DigestVerify` (~300 LOC): less third-party code, but you will write base64url parsing and JWKS->EVP_PKEY yourself, i.e. more of your own cryptographic code. At this scale, pick jwt-cpp.

JWKS client: `common/http.h` + `httplib::SSLClient`, mandatory `enable_server_certificate_verification(true)` and an explicit CA bundle path (`--oidc-ca-file`) - otherwise in a scratch container you will silently fail to verify the IdP. Cache: TTL from `Cache-Control`, fallback 300 s, background refresh, last-known keys retained when the IdP is unavailable (fail-static, not fail-open for new `kid`s).

Opaque tokens -> RFC 7662 introspection mode: `--oidc-introspection-url` + client credentials, with results cached by token hash and TTL <= min(exp, 60 s). Never cache negative responses for longer than a few seconds.

### 4.5 `common/arg.cpp` + `common/common.h` - new flags

```
# RBAC
--auth-policy-file PATH            (env LLAMA_ARG_AUTH_POLICY_FILE)
--auth-mode {any|all}              default any; all = require mTLS AND OIDC
--auth-trusted-proxies CIDR,...
--auth-audit-log PATH

# OIDC
--oidc-issuer URL                  (env LLAMA_ARG_OIDC_ISSUER)
--oidc-audience STR[,STR]
--oidc-algs RS256,ES256
--oidc-jwks-url URL                overrides discovery
--oidc-ca-file PATH
--oidc-clock-skew SEC              default 60
--oidc-introspection-url URL
--oidc-client-id / --oidc-client-secret-file    (secret from a file, not from argv!)

# mTLS
--mtls-client-ca-file PATH
--mtls-client-ca-dir PATH
--mtls-crl-file PATH
--mtls-required {off|optional|required}
--mtls-verify-depth N
--tls-min-version {1.2|1.3}
```

Secrets exclusively from files or env, never as an `argv` value (visible in `ps`, in orchestrator logs, in core dumps).

### 4.6 `server.cpp` - route -> permission map

Keep it next to the route registrations (lines ~226-356), as a single table, so that adding an endpoint without a policy entry is visible in code review. Add a startup assertion: every path registered in `ctx_http.handlers` must have an entry in the permission table - otherwise the server does not start. This is the only mechanism that will save you from "a new upstream endpoint became public after a rebase".

## 5. Rollout order (PRs)

| # | Scope | Result |
|---|---|---|
| 1 | Path normalization + route->perm table + `server-auth.{h,cpp}` + RBAC on the existing API key (key->role from policy) | Working RBAC without new dependencies, testable |
| 2 | Principal in `server_http_req` + audit log + `--auth-trusted-proxies` (behind-proxy mode) | Variant B complete |
| 3 | mTLS: SSLServer with client CA, `SSL_CTX` hardening, SAN->role mapping | Machine authentication |
| 4 | OIDC: jwt-cpp, JWKS cache, validation, claim->role mapping | User authentication |
| 5 | CRL / introspection / WebUI PKCE | Optional, needs-dependent |

PRs 1+2 deliver most of the value at the least risk. If the budget runs out after them - you still have a sensible system, because a proxy covers OIDC and mTLS.

## 6. Tests

Directory `tools/server/tests/` (pytest, `utils.py::ServerProcess`).

* `test_authz.py` - a parameterized matrix of every route x every role x expected status code. The test must fail when a route appears in `server.cpp` without a policy entry.
* `test_path_normalization.py` - `/Slots`, `//slots`, `/slots/`, `/v1/%2e%2e/slots`, `/slots%00`, unicode, very long paths.
* `test_oidc.py` - a mock IdP (Flask/`http.server`) with JWKS. Negative cases matter more than positive ones: `alg:none`, HS256 signed with the public key from JWKS, wrong `aud`, wrong `iss`, `exp` in the past, `nbf` in the future, unknown `kid`, JWKS unavailable, key rotation.
* `test_mtls.py` - a fixture generating a CA + client cert + a cert from a different CA + an expired cert + a revoked cert (CRL). No cert with `required` = rejection at the handshake level.
* Fuzzing of the `Authorization` header (very long, binary, missing space, repeated header).

## 7. Observability

Audit log (separate stream, JSON lines): `ts, subject_hash, method, path, decision, required_perm, auth_method, peer_ip, request_id`.

Do **not** log: tokens, the `Authorization` header, prompts, the full DN (if it contains PII). Instead of `sub`, log `SHA256(sub + salt)` - correlation without PII.

Prometheus metrics in `/metrics` (itself protected by `PERM_METRICS`): `llamacpp_auth_failures_total{reason}`, `llamacpp_jwks_refresh_total{result}`, `llamacpp_authz_denied_total{path,role}`.

## 8. Pitfalls and residual risks - the most important section

1. **`/cors-proxy` and `/tools` are ready-made SSRF.** The server performs HTTP requests to a client-supplied address. In a cloud environment this is the road to the metadata service (169.254.169.254). Require `PERM_PROXY`, disable by default, add a host allowlist and a private-address block.
2. **IDOR on streams.** `/v1/stream`, `/v1/streams/lookup`, `DELETE /v1/stream` address streams by ID. If the ID is not bound to the principal, user A reads user B's response. This is a real multi-tenancy hole - bind the stream ID to `subject` and check ownership **in the handler**, not in the middleware. The same problem applies to `/slots/:id_slot`.
3. **Slot save/restore writes files to disk** (`--slot-save-path`). `ADMIN_STATE` is mandatory, plus filename validation (path traversal).
4. **Authorization is checked once, at the start of the request.** SSE streaming can outlast the token's `exp`. Decide consciously: either you cut the stream on expiry (requires a check in the generation loop in `server-context.cpp`), or you accept it and document it.
5. **Side channel via the shared KV cache.** Prompt-prefix reuse across slots (`--cache-reuse`) yields a measurable time-to-first-token difference depending on what another user processed earlier. This is a real, if narrow-band, cross-tenant leak. If tenants are mutually untrusted - separate processes, not separate roles.
6. **API key comparison is not constant-time** (`std::find` on strings). While you are at it, switch to `CRYPTO_memcmp` over hashes.
7. **`OPTIONS` bypasses authentication** (deliberately, for preflight). Make sure it returns nothing beyond CORS headers and that it cannot be used to probe for the existence of routes.
8. **Rate limiting does not exist in llama-server.** Authentication without per-principal limits is an open door to slot exhaustion by a single user (DoS). Consider a simple token bucket per `subject` in `middleware_authz`, or leave it to the proxy.
9. **Rebase.** Minimize changes in existing files: all logic in new files; leave only call sites in `server-http.cpp`. Keep the fork on a linear `rebase` onto `master` and run the full auth test suite in CI after every rebase.

## 9. What deliberately NOT to do

* Do not implement sessions and cookies in C++. WebUI: a PKCE public client in the browser (a change in `tools/server/webui/`) or oauth2-proxy in front of the server.
* Do not implement your own cryptographic JWT code - use jwt-cpp.
* Do not build per-user quotas, billing, or multi-tenancy into llama-server. That is a layer above.
* Do not trust identity headers without `--auth-trusted-proxies` - not even "just on dev".

## 10. Effort estimate

| Stage | Working days (1 engineer who knows C++ and the repo) |
|---|---|
| PR1 RBAC + normalization + tests | 4-6 |
| PR2 principal + audit + proxy mode | 2-3 |
| PR3 mTLS (without CRL) | 3-5 |
| PR4 OIDC + JWKS + negative tests | 5-8 |
| PR5 CRL / introspection / WebUI | 5-10 |
| **Total** | **19-32 days + the ongoing rebase cost** |

For comparison: variant B (proxy + PR1/PR2) is 6-9 days and significantly lower risk.
