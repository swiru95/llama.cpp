# PR1 design: RBAC core on the existing API key

Status: in_design
Features: F001 (path normalization), F002 (permission model + policy types),
F003 (route -> permission table + startup assertion), F004 (authn/authz middleware chain).

This document is the implementation contract for a Haiku-class coder. Every non-obvious
decision is settled here. Do not invent behavior that is not written down; if something is
missing, stop and ask the architect.

ASCII only in all code and docs (AGENTS.md): no em-dash, no unicode arrows, use `-` and `->`.

--------------------------------------------------------------------------------
## 0. Scope and non-goals

In scope for PR1:
- Deterministic path normalization before any policy match (F001).
- A permission bitmask, a principal type, and a policy loaded from an optional JSON file
  with a compiled-in default (F002).
- A route -> permission table plus a startup assertion that every registered handler path
  is classified (F003).
- Replacing `middleware_validate_api_key` with an authn+authz chain that maps the existing
  API key to a role/permission set and enforces it per route (F004).

Explicitly NOT in PR1 (do not implement, do not add fields for beyond what is noted):
- OIDC / JWT (PR4), mTLS (PR3).
- Principal propagation into handlers via `server_http_req` / thread_local (PR2, F005).
  PR1 makes the authz decision entirely inside the middleware; handlers never see a principal.
- Audit log (PR2, F006), trusted-proxy header trust (PR2, F007).
- Per-principal rate limiting, stream-ownership (IDOR) checks, SSRF allowlists (later PRs).

Hard rules (CLAUDE.md) honored by this design:
- Fail closed: any init/parse error aborts startup; unknown route or unmapped role denies.
- Deny-by-default route table enforced by a startup assertion.
- All auth logic lives in new files `server-auth.h` / `server-auth.cpp`; existing files get
  only call sites.
- Constant-time key comparison; no hand-rolled JWT/X.509/hash crypto.

--------------------------------------------------------------------------------
## 1. Discrepancies found between PLAN.md and the current code

Anchors were verified on branch `master` at the time of writing. Line numbers are current.

| PLAN.md claim | Reality | Impact |
|---|---|---|
| `middleware_validate_api_key` ~208 | server-http.cpp:208 (exact) | none |
| `pre_routing_handler` ~279 | server-http.cpp:279 (exact) | none |
| get/post/del req construction ~583/630/647 | server-http.cpp:583/630/647 (exact) | PR2 concern, not PR1 |
| `register_gcp_compat` internal req ~802 | server-http.cpp:802 (exact) | see 6.4 |
| SSLServer ctor ~107 | server-http.cpp:110 | PR3 concern |
| route -> perm table "next to registrations ~226-356" | server.cpp:233-356 | see 6.1: table lives in server-auth.cpp, not server.cpp |

Substantive discrepancies that change the design:

1. **httplib already percent-decodes `req.path` once.** `httplib.cpp:7591` sets
   `req.path = decode_path_component(target-before-'?')` at request-line parse time, and it
   does NOT collapse `..`. Therefore PLAN.md 4.2a step "decode percent-encoding once" is
   ALREADY DONE by the time any middleware runs. Our normalization must NOT decode a second
   time (that would be a double-decode bug); instead it inspects the already-once-decoded path
   and rejects any residual `%`, NUL, backslash, or `..`/`.` segment. See section 5.

2. **`ctx_http.handlers` is keyed by path only, without method, and stores UNPREFIXED
   patterns** (e.g. `"/slots/:id_slot"`), because `get/post/del` do `handlers.emplace(path, ...)`
   while registering `path_prefix + path` on httplib (server-http.cpp:581/598/645). A path that
   is registered for multiple methods (GET+POST `/props`, GET+POST `/cors-proxy`) appears once
   in `handlers`. Consequence: the startup assertion can only check path-pattern coverage, not
   per-method; per-method granularity lives in the table and is used at request time. This is
   sufficient and matches PLAN.md 4.6 intent ("every path registered in handlers must have an
   entry").

3. **`/models` and `/v1/models` stay PUBLIC in PR1 (deferred).** server-http.cpp:197-206 lists
   `/health`, `/v1/health`, `/models`, `/v1/models` plus UI assets as public, and
   `tools/server/tests/unit/test_security.py::test_access_public_endpoint` asserts
   `GET /models -> 200` with no key. PLAN.md 2 wants `/models` READ_STATE-protected, but flipping
   it in PR1 changes observable behavior and breaks an existing test for no security-critical
   reason at this stage. DECISION (challenger Q3): keep `/models` public in PR1 exactly as today;
   flip it in a later focused PR. There is NO `--auth-public-models` flag and NO test change in
   PR1.

4. **`register_gcp_compat` dispatches to handlers internally and this IS an authz-bypass
   surface.** It constructs its own `server_http_req` (server-http.cpp:802) and calls
   `handlers.at(dispatch_path)(internal_req)` directly for a CLIENT-SELECTED `@requestFormat`,
   bypassing `pre_routing_handler`. Correction to an earlier claim: the reachable sub-handlers
   are NOT all INFER-level. The alias map is built from ALL handlers, so a client can target
   `/props` (READ_STATE), `/slots` (READ_STATE), `/metrics` (METRICS), and in router mode
   `/models` (ADMIN_MODELS; router registration at server.cpp:226-230 precedes GET `/models` and
   `emplace` keeps the first handler). An INFER-only `/predict` principal would therefore escalate.
   Mitigation in PR1: restrict gcp dispatch to an INFER-only format allowlist (section 6.4). The
   `/predict` and gcp health routes are env-derived, so they are covered via
   `server_auth::register_route` (section 6.4), not the static table.

5. **No reusable SHA-256 exists in `common/`.** The only in-tree SHA-256 implementations are
   backend-private (ggml-opencl). OpenSSL is only linked when the server is built with SSL.
   This constrains the key-hashing story; see section 8 and open question Q1.

--------------------------------------------------------------------------------
## 2. File layout

New files (all PR1 auth logic):
- `tools/server/server-auth.h`  - public types and the `server_auth` static interface.
- `tools/server/server-auth.cpp` - policy load, normalization, route table, decision logic.
- a vendored public-domain SHA-256 source under `tools/server/vendor/` (section 8.1).

Modified files (call sites and config only):
- `tools/server/CMakeLists.txt` - add `server-auth.cpp` / `server-auth.h` and the vendored
  SHA-256 source to the `llama-server-impl` target (already contains server.cpp /
  server-http.cpp, CMakeLists.txt:40-46).
- `tools/server/server-http.h` - add the `registered_routes` (method, path) vector to
  `server_http_context` (section 6.5). Infrastructure, not auth logic.
- `tools/server/server-http.cpp` - replace the `middleware_validate_api_key` lambda body/usage
  with a call into `server_auth`; keep the OPTIONS short-circuit, `middleware_server_state`,
  and the embedded UI-asset public carve-out. Populate `registered_routes` in get/post/del.
  Add one `server_auth::register_route(...)` pair plus the `is_infer_only` guard inside
  `register_gcp_compat`.
- `tools/server/server.cpp` - two call sites only: `server_auth::init(params)` (fail-closed)
  and `server_auth::assert_routes_covered(ctx_http.registered_routes)` after all routes are
  registered.
- `common/common.h` - add one `auth_policy_file` field to `common_params` (section 10).
- `common/arg.cpp` - add the `--auth-policy-file` flag and its env var (section 10).
- `tools/server/tests/utils.py` - thread the new flag into `ServerProcess` (section 12).

New test files are owned by the test-planner (section 12); the coder does not write them.

--------------------------------------------------------------------------------
## 3. server-auth.h (full contract)

The coder implements exactly this interface. `error_type` comes from `server-common.h`.

```cpp
#pragma once

#include "server-common.h" // error_type, format_error_response

#include <cstdint>
#include <string>
#include <unordered_map>

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

// PR1 authentication method. Extended in PR3/PR4; do not add members now.
enum server_auth_method { AUTH_NONE, AUTH_API_KEY };

// The identity resolved for a request. In PR1 this stays inside the middleware
// (it is NOT copied into server_http_req; that is PR2/F005).
struct server_auth_principal {
    bool               authenticated = false;
    uint32_t           perms         = 0;
    server_auth_method method        = AUTH_NONE;
    std::string        role;   // resolved role name, "" if none; for future audit
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

    // Full per-request check: normalize, classify, authenticate the API key,
    // and authorize. Header values are passed raw (may be empty). Never throws.
    static server_auth_decision authorize_request(const std::string & method,
                                                  const std::string & raw_path,
                                                  const std::string & authorization_header,
                                                  const std::string & x_api_key_header);

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
};
```

Notes:
- `assert_routes_covered` now takes a `std::vector<std::pair<std::string,std::string>>`
  (method, path) instead of the `handlers` map, so `server-auth.h` does NOT need to include
  `server-http.h`. `<vector>`, `<utility>`, `<string>`, `<cstdint>` suffice.
- The header intentionally omits any OIDC/mTLS/ssl parameters. Do not add them in PR1.

--------------------------------------------------------------------------------
## 4. Policy model and modes

### 4.1 Policy JSON schema (`--auth-policy-file`)

```json
{
  "roles": {
    "admin": ["INFER","READ_STATE","METRICS","ADMIN_STATE","ADMIN_MODELS"],
    "user":  ["INFER"]
  },
  "api_keys": {
    "<sha256-hex-of-key>": "admin",
    "<sha256-hex-of-key>": "user"
  },
  "public_endpoints": ["/health", "/v1/health"],
  "default_role": null
}
```

- `roles`: object mapping a role name to a list of permission-name strings. Permission names
  are exactly: `INFER`, `READ_STATE`, `METRICS`, `ADMIN_STATE`, `ADMIN_MODELS`, `PROXY`.
  Any unknown permission name -> `init` fails (fail closed).
- `api_keys`: object mapping the lowercase hex SHA-256 of an API key to a role name. The role
  name must exist in `roles` (or the merged default roles) or `init` fails. Storing hashes,
  not plaintext, keeps secrets out of the policy file. The admin computes a hash offline, e.g.
  `printf %s "sk-mykey" | sha256sum`.
- `public_endpoints`: list of NORMALIZED paths (already prefix-stripped form, e.g. `/health`)
  that require no authentication. These MUST also be present as PERM_PUBLIC in the route table
  or covered by a handler; a `public_endpoints` entry that is not a registered route is ignored
  with a warning (it cannot make a non-existent route reachable).
- `default_role`: role name applied to an otherwise-valid but unmapped API key, or `null`
  (deny by default). PLAN.md 4.1: never default to `"user"`. For PR1 keep it simple: if
  `default_role` is `null`, an API key whose hash is not in `api_keys` is treated as an
  invalid credential (401). If `default_role` names a role, such a key authenticates with that
  role's perms.

### 4.2 Compiled-in default

When `--auth-policy-file` is NOT set, use this compiled-in default (do not read any file):

```
roles.admin = INFER|READ_STATE|METRICS|ADMIN_STATE|ADMIN_MODELS   (no PROXY, PLAN.md 2)
roles.user  = INFER
public_endpoints = { "/health", "/v1/health" }
default_role = null
api_keys = {}   (empty: no hash->role assignments)
```

When a policy file IS set, parse it and use it AS GIVEN for `roles`, `api_keys`,
`public_endpoints`, `default_role`. If the file omits `roles`, fall back to the compiled-in
default roles. If it omits `public_endpoints`, fall back to `{ "/health", "/v1/health" }`.
`api_keys` has no default (empty if omitted).

### 4.3 Operating modes (settled)

The mode is a function of `--auth-policy-file` and `params.api_keys`:

1. **Auth-disabled** (no policy file AND `params.api_keys` empty): today's default. Every
   request is allowed; `authorize_request` returns `allowed=true` for all API routes without
   inspecting headers. Route table + startup assertion still run (coverage guarantee). This
   preserves the current "no key => open server" behavior exactly.

2. **Legacy super-user** (no policy file AND `params.api_keys` non-empty): reproduce today's
   behavior with per-route classification layered on top. Build the key table by hashing each
   `params.api_keys` value (see section 8) and assigning `PERM_ALL` to it. A request with a
   valid key gets `PERM_ALL` (passes every route including PROXY, matching today). A request
   with a missing/invalid key gets 401 on any non-public route (matching today), and public
   routes (health, UI assets) are still allowed. Net effect vs today: identical, EXCEPT
   `/models` becomes non-public by default (section 4.4 / Q3).

3. **RBAC** (`--auth-policy-file` set): the policy is the SINGLE SOURCE OF TRUTH for keys.
   Build the key table from `policy.api_keys` (hash -> role -> perms). For `params.api_keys`
   (`--api-key` / `--api-key-file`): hash each value and require its hash to be present in
   `policy.api_keys`; if any configured `--api-key` is NOT listed in the policy, `init` FAILS
   with a clear message and the server aborts (challenger Q2 - no silent `default_role`
   assignment, no ambiguity about which keys are valid). `default_role` still governs the
   runtime case of a presented key whose hash is unknown: `null` -> 401, else that role's perms.

In all modes, `PERM_PUBLIC` routes never require a key, and the embedded UI-asset carve-out
(section 7.1) is applied before authz.

### 4.4 The `/models` default

`GET /models` and `GET /v1/models` stay PUBLIC in PR1, exactly as today (challenger Q3 -
deferred). No classification is flag-dependent in PR1; there is no `--auth-public-models` flag.
The READ_STATE flip is left to a later focused PR.

--------------------------------------------------------------------------------
## 5. Path normalization algorithm (F001)

Input: `raw_path` = httplib `req.path` (already single percent-decoded, `..` NOT collapsed),
and the configured `api_prefix` (stored in `init` from `params.api_prefix`, default "").
Output: `server_norm_status` and, on `NORM_OK`, `out_normalized`.

Write unit tests for this FIRST (F001), before wiring the middleware.

Steps, in order:

1. **Strip prefix.**
   - If `api_prefix` is non-empty:
     - If `raw_path == api_prefix`, set `work = "/"`.
     - Else if `raw_path` starts with `api_prefix + "/"`, set `work = raw_path.substr(len(api_prefix))`
       (this keeps the leading `/`).
     - Else return `NORM_UNMATCHED` (the request is outside the API namespace; it cannot reach
       a prefixed handler, so it is not a protected route). Do not reject; the caller treats
       UNMATCHED as "not an API route" and falls through (httplib will 404 or serve a static
       asset). This satisfies F001 "requests without the configured api_prefix are rejected"
       in effect: they can never match a protected route.
   - If `api_prefix` is empty, `work = raw_path`.

2. **Do NOT repair the path; reject anything non-canonical.** This is the fix for BLOCKER B1.
   A normalizer that silently collapses `//` or strips a trailing `/` DESYNCS from httplib's
   router: httplib matches `POST /slots/` against `/slots/:id_slot` (empty captured id) and runs
   the ADMIN_STATE slot handler, while a repaired-then-matched `/slots` looks like a GET-only
   route with a POST method mismatch (unclassified). To make desync impossible, `normalize_path`
   must REJECT any path that is not already in canonical form, and rejection short-circuits in
   `pre_routing_handler` (returns Handled) BEFORE httplib routes. Return `NORM_REJECT` if `work`:
   - contains a NUL byte (`'\0'`), or
   - contains a literal `'%'` (residue of a double-encoded sequence; httplib already decoded
     once, so a real request never needs a `%` in these routes), or
   - contains a backslash (`'\\'`), or
   - contains an EMPTY segment, i.e. two consecutive `'/'` (`//slots`, `/slots//0`), or
   - ends with a trailing `'/'` and is longer than 1 char (`/slots/`), or
   - after splitting on `'/'`, has any segment equal to `"."` or `".."`.
   `NORM_REJECT` maps to HTTP 400 (invalid_request) in the caller. There is NO collapsing and NO
   trailing-slash stripping step; the path is either already canonical or rejected.

3. **Ensure leading slash.** If `work` is empty or `work[0] != '/'`, return `NORM_REJECT`
   (should not happen after step 1, but fail closed).

4. Return `NORM_OK` with `out_normalized = work` unchanged. Comparison downstream is
   CASE-SENSITIVE (`/Slots` != `/slots`).

Worked outcomes (all with empty prefix) that the tests must lock:
- `/slots`      -> NORM_OK `/slots`
- `/Slots`      -> NORM_OK `/Slots` (then required_perm finds no match; with auth ENABLED this
  is DENIED per B2, see section 7.3, not silently allowed)
- `//slots`     -> NORM_REJECT (empty segment) -> 400
- `/slots/`     -> NORM_REJECT (trailing slash) -> 400  [B1: prevents the ADMIN_STATE desync]
- `/slots/0/`   -> NORM_REJECT (trailing slash) -> 400
- `/v1/%2e%2e/slots` (wire) -> httplib decodes to `/v1/../slots` -> segment `..` -> NORM_REJECT
- `/slots%00`   (wire) -> httplib decodes to `/slots\0` -> NUL -> NORM_REJECT
- `/slots%2f0`  (wire) -> httplib decodes to `/slots/0` -> NORM_OK `/slots/0` (matches
  `/slots/:id_slot` pattern -> ADMIN_STATE; correct, an encoded slash is a real slash)
- `/slots%2f`   (wire) -> httplib decodes to `/slots/` -> trailing slash -> NORM_REJECT
- `/foo%2e`     (wire, double) -> httplib decodes `%2e`->`.`; a whole `.` segment is rejected;
  a `.` inside a longer segment like `/v1.0` is allowed (only whole `.`/`..` segments reject)

### 5.1 Route matching against normalized path

`required_perm(normalized_path, method, matched)`:
- Split `normalized_path` and each table pattern into `'/'`-separated segments.
- A pattern segment beginning with `':'` matches exactly one non-empty concrete segment
  (mirrors httplib `PathParamsMatcher`). All other segments must be byte-equal.
- Segment counts must be equal.
- Among all entries whose pattern matches, select the one whose method equals `method`.
  - If a pattern matches but no entry has this method: set `matched=false`.
  - If no pattern matches: `matched=false`.
- On a match: `matched=true`, return that entry's perm (may be `PERM_PUBLIC`).

`matched=false` does NOT mean "allow". When auth is enabled the caller applies deny-by-default
(section 7.3, BLOCKER B2): an unclassified `(path, method)` requires a valid authenticated
principal (401 for anonymous), and only then falls through to httplib's own 404. Do NOT invent
a 405. This preserves today's behavior where any non-public path requires a key for ALL methods.

--------------------------------------------------------------------------------
## 6. Route -> permission table and startup assertion (F003)

### 6.1 Where the table lives (deviation from PLAN.md 4.6, deliberate)

PLAN.md 4.6 suggests putting the table next to the route registrations in `server.cpp`.
CLAUDE.md hard rule says all auth logic lives in `server-auth.*` and existing files get call
sites only. These conflict. Resolution: the canonical table is a static array in
`server-auth.cpp`. The coupling to `server.cpp` is preserved by the startup assertion: adding
a route in `server.cpp` without a matching table entry aborts startup with a message naming
the path, forcing the developer to edit `server-auth.cpp`. This satisfies both "new upstream
endpoint fails the assertion, not silently public" (PLAN.md hard rule) and "logic in new
files" (CLAUDE.md). Flagged for the challenger (Q4).

### 6.2 Table format

In `server-auth.cpp`, a file-scope static array:

```cpp
struct auth_route { const char * method; const char * pattern; uint32_t perm; };

static const auth_route k_routes[] = {
    // health (public)
    { "GET",  "/health",                        PERM_PUBLIC },
    { "GET",  "/v1/health",                     PERM_PUBLIC },

    // public (deferred: /models stays public in PR1, matching today; challenger Q3)
    { "GET",  "/models",                        PERM_PUBLIC },
    { "GET",  "/v1/models",                     PERM_PUBLIC },

    // read state
    { "GET",  "/props",                         PERM_READ_STATE },
    { "GET",  "/models/sse",                    PERM_READ_STATE },   // router mode
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
    { "DELETE","/models",                       PERM_ADMIN_MODELS },
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

    // resumable streaming (session-scoped inference; ownership check deferred to a later PR)
    { "GET",    "/v1/stream",                   PERM_INFER },
    { "POST",   "/v1/streams/lookup",           PERM_INFER },
    { "DELETE", "/v1/stream",                   PERM_INFER },

    // proxy / agent tools (SSRF surface: PERM_PROXY, absent from default admin role)
    { "GET",  "/cors-proxy",                    PERM_PROXY },
    { "POST", "/cors-proxy",                    PERM_PROXY },
    { "GET",  "/tools",                         PERM_PROXY },
    { "POST", "/tools",                         PERM_PROXY },
};
```

Rules encoded above:
- `/models` and `/v1/models` GET are PERM_PUBLIC in PR1 (unchanged from today; the
  READ_STATE flip is deferred to a later PR - challenger Q3). There is no runtime override and
  no `--auth-public-models` flag.
- `/cors-proxy` and `/tools` require `PERM_PROXY`, which no default role grants; in legacy
  super-user mode a valid key has `PERM_ALL` (includes PROXY), so today's behavior is
  preserved. In RBAC mode an operator must explicitly add `"PROXY"` to a role to enable them
  (document this in the `--auth-policy-file` flag help). These routes are additionally
  feature-gated by `res_403` in server.cpp when disabled (unchanged).
- The router-mode-only routes (`/models/*`, `/models/sse`) are always in the table; they are
  only registered as handlers in router mode, so the assertion only checks them when present.

The coder must keep this table in sync with server.cpp:233-356. The assertion is the safety net.

### 6.3 Runtime table build in `init`

`init` copies `k_routes` into a runtime structure suited for matching (e.g. a
`std::vector<auth_route_rt>` with pre-split segments) and records, per pattern, the set of
methods classified for it (for the method-aware assertion, section 6.5). Dynamic routes added
via `register_route` are appended.

### 6.4 gcp compat dynamic routes and the internal-dispatch bypass (SHOULD-FIX S1)

Inside `server_http_context::register_gcp_compat` (server-http.cpp), after computing
`gcp.path_predict` and `gcp.path_health`, and only when `gcp.enabled`, add two call sites so the
dynamic env-derived paths are classified and pass the assertion:

```cpp
server_auth::register_route("POST", gcp.path_predict, PERM_INFER);
if (!gcp.path_health.empty()) {
    server_auth::register_route("GET", gcp.path_health, PERM_PUBLIC);
}
```

These paths are registered via `post()`/`get()` and appear in `handlers`; the outer `/predict`
POST is authorized at INFER by the normal middleware. Place these calls at the top of
`register_gcp_compat` (the assertion runs from `main` after it returns).

**The bypass (S1).** The `/predict` handler dispatches `handlers.at(dispatch_path)(internal_req)`
(server-http.cpp:802-812) for a client-selected `@requestFormat`, and that internal request never
passes through `pre_routing_handler`. Reachable sub-handlers include non-INFER routes (`/props`
READ_STATE, `/slots` READ_STATE, `/metrics` METRICS, router-mode `/models` ADMIN_MODELS). Since
`/predict` only requires INFER, this is a privilege-escalation path.

Mitigation for PR1 (no principal propagation available yet): confine gcp dispatch to
INFER-only endpoints. Add a helper to `server_auth`:

```cpp
// true iff the path pattern is classified AND every classified method for it is exactly INFER
static bool is_infer_only(const std::string & normalized_path);
```

In the `/predict` dispatch lambda, immediately after resolving `dispatch_path` and before
calling the handler, reject non-inference targets:

```cpp
if (!server_auth::is_infer_only(dispatch_path)) {
    return build_error("requestFormat not permitted via predict route: " + format,
                       ERROR_TYPE_PERMISSION);
}
```

`is_infer_only` returns false for `/props`, `/slots`, `/metrics`, `/models`, etc. (they have a
non-INFER method entry), and true for `/completions`, `/chat/completions`, `/embeddings`,
`/rerank`, `/tokenize`, and the other pure-INFER routes. This closes the escalation without
needing the principal inside the handler; a full principal-carrying check is a PR2 concern.

### 6.5 Startup assertion (method-aware, SHOULD-FIX S2)

The existing `handlers` map is keyed by path only, so multi-method paths collapse and a new
method on an existing path would pass a path-only assertion silently. The assertion must be
method-aware. This needs a small, method-carrying registry of what was actually registered.

Change to `server_http_context` (server-http.h / server-http.cpp - infrastructure, not auth
logic): add a member that records the (method, path) of every registration:

```cpp
// server-http.h, in server_http_context
mutable std::vector<std::pair<std::string, std::string>> registered_routes; // (method, path)
```

Populate it in `get`/`post`/`del` (server-http.cpp:580/597/644) next to the existing
`handlers.emplace(path, handler)`:

```cpp
registered_routes.emplace_back("GET", path);    // in get()
registered_routes.emplace_back("POST", path);   // in post()
registered_routes.emplace_back("DELETE", path); // in del()
```

`assert_routes_covered` takes this registry (not the path-only map):

```cpp
static bool assert_routes_covered(
    const std::vector<std::pair<std::string, std::string>> & registered_routes);
```

Logic:
- For each `(method, path)` in `registered_routes`: look the pattern up in the table with an
  EXACT method match (pattern string equality against the table's `pattern`, plus method
  equality). If no table/dynamic entry has that exact `(method, pattern)`, log
  `SRV_ERR("route '%s %s' has no auth policy entry; refusing to start\n", method, path)` and
  return false.
- Return true only if every registered `(method, path)` is classified.

Call site in `server.cpp` (after `register_gcp_compat()` at server.cpp:294 and after the
cors-proxy/tools registration blocks, i.e. after server.cpp:357, before `ctx_http.start()`):

```cpp
if (!server_auth::assert_routes_covered(ctx_http.registered_routes)) {
    return 1; // fail closed
}
```

Note: the request-time deny-by-default (B2, section 7.3) is the primary runtime safety net for
an unclassified method; this startup assertion additionally makes a rebase that adds a new
upstream method/route fail LOUDLY at startup instead of silently.

--------------------------------------------------------------------------------
## 7. Middleware chain (F004): exact changes to server-http.cpp

Replace the `middleware_validate_api_key` lambda (server-http.cpp:208-253) and its use in the
pre-routing handler (server-http.cpp:305-307). Keep everything else in `pre_routing_handler`
(CORS block, OPTIONS short-circuit, `middleware_server_state`).

### 7.1 Keep

- The OPTIONS short-circuit (server-http.cpp:294-301) stays as-is. OPTIONS returns only CORS
  headers and never reaches authz (F004 acceptance: preflight reveals no route existence).
- `middleware_server_state` (503 while loading) stays and runs BEFORE authz.
- The frontend/UI public carve-out: reuse the existing `frontend_paths` set
  (server-http.cpp:188-194) which is `{"/"} + all embedded UI asset names`. A request whose
  `req.path` (after prefix handling) is in `frontend_paths` is a public UI asset and skips
  authz. IMPORTANT: `frontend_paths` entries are unprefixed (`"/"`, `"/index.html"`, ...),
  while `req.path` is prefixed; compare using the same prefix logic already used for asset
  registration (assets are served at `params.api_prefix + "/" + name`). Simplest: strip
  `params.api_prefix` from `req.path` first, then check membership in `frontend_paths`.

### 7.2 Replace: the new authz middleware

Define a replacement lambda (name it `middleware_authz`) that captures nothing but relies on
`server_auth` statics:

```cpp
auto middleware_authz = [](const httplib::Request & req, httplib::Response & res) {
    const server_auth_decision d = server_auth::authorize_request(
        req.method,
        req.path,
        req.get_header_value("Authorization"),
        req.get_header_value("X-Api-Key"));
    if (d.allowed) {
        return true;
    }
    res.status = d.status;
    res.set_content(
        safe_json_to_str(json {{"error", format_error_response(d.message, d.type)}}),
        "application/json; charset=utf-8");
    return false;
};
```

Wire it in `pre_routing_handler` in place of the old `middleware_validate_api_key` call:

```cpp
if (!middleware_server_state(req, res)) {
    return httplib::Server::HandlerResponse::Handled;
}
// UI-asset public carve-out (unchanged semantics): strip prefix, check frontend_paths
if (is_frontend_asset(req.path)) {
    return httplib::Server::HandlerResponse::Unhandled;
}
if (!middleware_authz(req, res)) {
    return httplib::Server::HandlerResponse::Handled;
}
return httplib::Server::HandlerResponse::Unhandled;
```

`is_frontend_asset` is a small local helper capturing `params.api_prefix` and `frontend_paths`.
The `pre_routing_handler` lambda already captures `&params`; adjust its capture list to also
capture `middleware_authz` and `middleware_server_state` (drop `middleware_validate_api_key`).

### 7.3 `authorize_request` decision logic (in server-auth.cpp)

This logic is deny-by-default when auth is enabled (BLOCKER B2). It must NOT allow-by-default
for unclassified `(path, method)` or for `NORM_UNMATCHED`, because today's
`middleware_validate_api_key` requires a valid key for ANY non-public path and ALL methods
(unknown path -> 401). Allowing-by-default would make a future `PUT /props`, or `--public-path`
static-mount files, reachable with no auth.

```
server_auth_decision authorize_request(method, raw_path, authz_hdr, x_api_key_hdr):
    // Auth-disabled mode (no policy file AND no api_keys): today's open server.
    if (auth_disabled):
        return allow()

    // --- auth is ENABLED below (legacy super-user or RBAC) ---

    std::string norm;
    switch (normalize_path(raw_path, norm)):
        case NORM_REJECT:
            return deny(400, ERROR_TYPE_INVALID_REQUEST, "invalid request path")
        case NORM_UNMATCHED:
            // outside api_prefix: cannot reach a prefixed handler. Deny-by-default:
            // require a valid principal, then fall through to httplib 404.
            // fallthrough to the shared authn+deny path below with need = <unclassified>
        case NORM_OK: break

    bool matched = false
    uint32_t need = (norm-was-UNMATCHED) ? 0 : required_perm(norm, method, matched)

    if (matched && need == PERM_PUBLIC):
        return allow()

    // Everything else that is auth-enabled requires authentication first.
    server_auth_principal p = authenticate_api_key(authz_hdr, x_api_key_hdr)
    if (!p.authenticated):
        return deny(401, ERROR_TYPE_AUTHENTICATION, "Invalid API Key")

    if (!matched):
        // Authenticated but this (path, method) is not a classified API route.
        // Let it fall through to httplib (which will 404). We ALLOW only because the
        // caller has already proven a valid credential; an anonymous caller was denied
        // 401 above. This matches today: valid key required, unknown path -> 404.
        return allow()

    if ((p.perms & need) == need):     // 'need' is a single bit in PR1, so this is an AND-mask
        return allow()

    return deny(403, ERROR_TYPE_PERMISSION, "insufficient permissions")
```

Key points:
- `auth_disabled` is the ONLY allow-by-default path. When any key or policy is configured, an
  anonymous request to an unclassified/unmatched path gets 401, not a silent pass.
- `NORM_UNMATCHED` (outside `api_prefix`) is treated like an unclassified route: authenticated
  callers fall through to httplib (404); anonymous callers get 401.
- `allow()` = `{allowed=true}`. `deny(status,type,msg)` = `{allowed=false, status, type, msg}`.
- Use `(p.perms & need) == need` so multi-bit requirements would also work if introduced.
- The embedded frontend-asset carve-out (section 7.1) runs in `pre_routing_handler` BEFORE
  this function, so UI assets never reach here. `--public-path` static-mount files are NOT in
  that carve-out and therefore require auth when auth is enabled (matches today; challenger Q5).

### 7.4 `authenticate_api_key` (in server-auth.cpp)

```
authenticate_api_key(authz_hdr, x_api_key_hdr):
    std::string key = authz_hdr
    if (key.empty()) key = x_api_key_hdr
    // strip "Bearer " prefix (case-sensitive, matching current code)
    static const std::string prefix = "Bearer "
    if (key.rfind(prefix, 0) == 0) key = key.substr(prefix.size())
    if (key.empty()) return {authenticated=false}

    std::string h = sha256_hex(key)                 // section 8
    auto it = key_perms.find(h)                      // unordered_map<string,uint32_t>
    // constant-time membership: iterate all entries, constant-time compare hashes
    // (section 8) to avoid leaking which key prefix matched via timing.
    ...
    if (found) return {authenticated=true, perms=<mapped>, method=AUTH_API_KEY, role=<name>}
    return {authenticated=false}
```

Header parsing mirrors the current code (server-http.cpp:220-230): `Authorization` first,
then `X-Api-Key`, then strip a leading `"Bearer "`.

--------------------------------------------------------------------------------
## 8. Key hashing and constant-time comparison

Requirements: constant-time comparison over hashes (CLAUDE.md), no hand-rolled crypto.

### 8.1 Hashing - vendor a standalone SHA-256 (challenger Q1)

`key_perms` maps `sha256_hex(key) -> perms`. The policy `api_keys` object stores hex digests;
`params.api_keys` values are hashed at `init` time. This requires a SHA-256 at runtime and it
must work on ALL builds (RBAC must not depend on an SSL-enabled build).

Decision: vendor a small, self-contained, public-domain SHA-256 implementation under
`tools/server/vendor/` (or reuse one already vendored in-tree if the coder finds a suitable
public-domain single-file impl; there is none in `common/` today). This is standard llama.cpp
vendoring, not "hand-rolled crypto" in the forbidden sense (which targets JWT/X.509/JWKS logic).
Add the source to the `llama-server-impl` target in CMakeLists.txt. Expose:

```cpp
static std::string sha256_hex(const std::string & in); // lowercase 64-char hex
```

RBAC works identically on SSL and non-SSL builds. There is NO OpenSSL gate and NO
`--auth-policy-file requires SSL` error.

### 8.2 Comparison

- **Hashed path (RBAC and, when hashing legacy keys too, legacy mode):** at request time,
  compute `sha256_hex(presented_key)` and do a plain `unordered_map` lookup on the hex digest.
  Because the lookup key is a one-way SHA-256 digest, a hash-table lookup leaks nothing
  invertible about the configured keys, so a constant-time scan over all entries is NOT required
  here (challenger C2). Store `key_perms` as `std::unordered_map<std::string /*hex*/, key_entry>`
  where `key_entry` holds `perms` and the role name.
- **Legacy non-hashed fallback (optional):** if the coder chooses to compare raw legacy keys
  instead of hashing them, use the portable, length-safe, constant-time equality below and
  iterate all configured keys so timing does not reveal which key matched. Prefer the hashed
  path for uniformity; keep `consttime_equal` only for a raw-key comparison if used.

```cpp
// portable, length-safe, constant-time byte-string equality
static bool consttime_equal(const std::string & a, const std::string & b) {
    unsigned char diff = (unsigned char)(a.size() ^ b.size());
    const size_t n = a.size() > b.size() ? a.size() : b.size();
    for (size_t i = 0; i < n; i++) {
        unsigned char ca = i < a.size() ? (unsigned char)a[i] : 0;
        unsigned char cb = i < b.size() ? (unsigned char)b[i] : 0;
        diff |= (unsigned char)(ca ^ cb);
    }
    return diff == 0;
}
```

Recommended: hash every configured key (legacy and RBAC) to a hex digest and use the
`unordered_map` lookup uniformly. This satisfies PLAN.md 4.1 and pitfall #6 on all builds.

--------------------------------------------------------------------------------
## 9. Error handling and status codes

Use the existing helper `format_error_response(message, error_type)` (server-common.h:93,
implemented server-common.cpp:17) which sets the numeric `code` in the JSON body and whose
mapping is:

| error_type | HTTP | JSON type |
|---|---|---|
| ERROR_TYPE_AUTHENTICATION | 401 | authentication_error |
| ERROR_TYPE_PERMISSION | 403 | permission_error |
| ERROR_TYPE_INVALID_REQUEST | 400 | invalid_request_error |

Conventions (settled):
- Missing or invalid credential on a protected route -> **401** `ERROR_TYPE_AUTHENTICATION`,
  message `"Invalid API Key"` (matches the current message exactly, so existing
  `test_security.py::test_incorrect_api_key` assertions on `type == authentication_error`
  keep passing).
- Authenticated principal lacking the required permission -> **403** `ERROR_TYPE_PERMISSION`,
  message `"insufficient permissions"`.
- Malformed/hostile path (`NORM_REJECT`) -> **400** `ERROR_TYPE_INVALID_REQUEST`, message
  `"invalid request path"`.
- The middleware sets `res.status` from the decision AND relies on `format_error_response`
  putting the same code in the body (both must agree; set `res.status = d.status` and pass
  `d.type` whose code equals `d.status`). The coder must keep `d.status` consistent with the
  `error_type` mapping above.
- Never log the key, the `Authorization` header, or the `X-Api-Key` header. A denial may log at
  most `SRV_WRN` with a static string (as the current code does at server-http.cpp:250). Do not
  log the presented key or its hash in PR1.

--------------------------------------------------------------------------------
## 10. CLI flag and common_params (F002)

`common/common.h`, in the server params block near `api_keys` (common.h:645) and `api_prefix`
(common.h:627) - a single new field:

```cpp
std::string auth_policy_file = "";   // --auth-policy-file; empty = legacy/compiled-in default
```

`common/arg.cpp`, following the `--api-key-file` pattern (arg.cpp:3357-3373), add ONE flag:

```cpp
add_opt(common_arg(
    {"--auth-policy-file"}, "PATH",
    "path to a JSON RBAC policy file (roles, api_keys sha256->role, public_endpoints, "
    "default_role). When unset, a valid API key grants full access (legacy behavior). "
    "In RBAC mode, endpoints needing PROXY (/cors-proxy, /tools) require a role that "
    "explicitly lists \"PROXY\".",
    [](common_params & params, const std::string & value) {
        params.auth_policy_file = value;
    }
).set_examples({LLAMA_EXAMPLE_SERVER}).set_env("LLAMA_ARG_AUTH_POLICY_FILE"));
```

No secret is passed on argv: `--auth-policy-file` is a path; key hashes live in the file.
`--api-key` remains as-is (its argv exposure is pre-existing and out of scope for PR1). There is
NO `--auth-public-models` flag (challenger Q3: `/models` stays public in PR1).

--------------------------------------------------------------------------------
## 11. Startup / init flow and ordering

In `server.cpp main()` (current flow: `ctx_http.init` at server.cpp:172, route registration
233-356, `register_gcp_compat` at 294, `ctx_http.start` at 407/436):

1. `ctx_http.init(params)` (unchanged; wires the new `middleware_authz` which only references
   `server_auth` statics, so it does not need the policy to be loaded yet).
2. Call `server_auth::init(params)` as early as possible AFTER params are finalized and BEFORE
   any request can be served. Place it immediately after `ctx_http.init` succeeds
   (around server.cpp:172-175). On failure: `SRV_ERR` and `return 1` (fail closed).
3. Register all routes (existing block, unchanged) including `register_gcp_compat()` which now
   also calls `server_auth::register_route` for its dynamic paths.
4. After the cors-proxy/tools registration (after server.cpp:357), call
   `server_auth::assert_routes_covered(ctx_http.registered_routes)`; on false `return 1`.
5. `ctx_http.start()` (unchanged).

Ordering rationale: the middleware calls `server_auth` statics only at request time, which is
after `start()`, so step 2 before step 5 guarantees the policy is ready. `register_route` in
step 3 must precede `assert_routes_covered` in step 4 (it does).

Router mode: the same steps apply; the router registers `/models*` handlers (server.cpp:226-230)
which are covered by the static table. `server_auth::init` and `assert_routes_covered` run in
both modes.

--------------------------------------------------------------------------------
## 12. Tests and harness threading (for the test-planner; the coder threads the flag only)

`tools/server/tests/utils.py::ServerProcess`: add one field and flag threading following the
existing `api_key` pattern (utils.py:91, 234-235):

```python
auth_policy_file: str | None = None
...
if self.auth_policy_file:
    server_args.extend(["--auth-policy-file", self.auth_policy_file])
```

Test files (owned by test-planner, listed here so the coder does not duplicate):
- `unit/test_path_normalization.py` (F001): the normalization matrix from section 5, including
  `/Slots`, `//slots` (expect 400), `/slots/` (expect 400), `/v1/%2e%2e/slots` (400),
  `/slots%00` (400), encoded-slash, long paths. Black-box (HTTP-level) since the server applies
  normalization in the middleware. Run these with a key configured (auth enabled) so the
  deny-by-default B2 behavior is exercised; with no key configured, auth-disabled mode allows.
- `unit/test_authz.py` (F003, F004): route x role x method matrix -> expected 200/401/403,
  using a policy file with `admin`/`user` keys; include B2 negative cases (anonymous request to
  an unclassified path/method -> 401, not a pass) and a startup-abort check for an uncovered
  route (test-planner decides the mechanism).

NO existing-test changes are required in PR1. Because `/models` stays public (challenger Q3),
`unit/test_security.py::test_access_public_endpoint` keeps passing unchanged.

--------------------------------------------------------------------------------
## 13. Feature mapping

- F001 Path normalization (reject double-slash / trailing-slash, B1) -> section 5 (+ 5.1
  matching). Files: server-auth.h/.cpp.
- F002 Permission model + policy types + vendored SHA-256 -> sections 3, 4, 8, 10. Files:
  server-auth.h/.cpp, vendored sha256 source, common/common.h, common/arg.cpp,
  tools/server/CMakeLists.txt.
- F003 Route table + method-aware assertion (S2) + gcp INFER-only guard (S1) -> section 6
  (+ 6.4 gcp, 6.5 assertion, 11 wiring). Files: server-auth.cpp/.h, server.cpp (assert call
  site), server-http.h (registered_routes), server-http.cpp (register_route + is_infer_only in
  gcp compat, populate registered_routes).
- F004 Authn/authz middleware, deny-by-default when auth enabled (B2) -> sections 7, 8, 9.
  Files: server-http.cpp (call site), server-auth.cpp (authorize_request, authenticate_api_key).

Suggested implementation order for the coder: F001 (+ its tests) -> F002 -> F003 -> F004,
matching `depends_on` in features.json.

--------------------------------------------------------------------------------
## 14. Challenger review outcomes (resolved)

The challenger (Fable) reviewed the first draft and found two auth-bypass BLOCKERS and two
should-fix issues. All are now resolved in this document:

- **B1 (trailing-slash / double-slash matcher desync -> admin bypass).** RESOLVED in section 5:
  `normalize_path` no longer collapses `//` or strips a trailing `/`. It REJECTS (400) any empty
  segment or trailing slash, and rejection short-circuits in `pre_routing_handler` before
  httplib routes, so httplib can never dispatch an admin handler that authz classified as a
  different route. F001 acceptance updated: `//slots` and `/slots/` are 400, not silent repairs.

- **B2 (allow-by-default inverted today's deny-by-default -> fail-open).** RESOLVED in
  section 7.3: only the auth-disabled mode allows-by-default. When auth is enabled, an
  unclassified `(path, method)` or a `NORM_UNMATCHED` path requires a valid principal (401 for
  anonymous), then authenticated callers fall through to httplib 404. `--public-path` mount
  files therefore require auth (matches today). F004 acceptance updated.

- **S1 (gcp internal dispatch bypasses authz -> INFER escalates to READ_STATE/METRICS/
  ADMIN_MODELS).** RESOLVED in section 6.4 and discrepancy #4: the earlier "sub-handlers are all
  INFER-level" claim was false and is struck. gcp `/predict` dispatch is now confined to an
  INFER-only format allowlist via `server_auth::is_infer_only(dispatch_path)`.

- **S2 (method-blind startup assertion).** RESOLVED in section 6.5: a method-aware
  `registered_routes` (method, path) registry is populated at get/post/del registration, and
  `assert_routes_covered` checks exact `(method, pattern)` coverage, so a new upstream method on
  an existing path fails loudly at startup.

Q-answers applied:
- Q1 -> vendor a small public-domain SHA-256; RBAC works on all builds, no SSL gate (section 8).
- Q2 -> in RBAC mode, a `--api-key` whose hash is absent from `policy.api_keys` is a STARTUP
  ERROR; the policy is the single source of truth (section 4.3 mode 3).
- Q3 -> DEFER the `/models` flip; `/models` stays public in PR1; no `--auth-public-models` flag,
  no runtime override, no test change (sections 4.4, 6.2, 10, 12; discrepancy #3).
- Q5 -> covered by B2; no static-path enumeration; mount files require auth when auth enabled.
- Q6 -> `PERM_PROXY` absent from the default admin role is correct (SSRF-conservative); RBAC
  operators must grant `"PROXY"` explicitly. Documented in the `--auth-policy-file` flag help.
  Legacy super-user deployments (`--ui-mcp-proxy`/`--tools` + `--api-key`) are unaffected
  (PERM_ALL includes PROXY).
- C2 -> hashed-key lookup uses a plain `unordered_map` on the hex digest (no invertible leak);
  `consttime_equal` retained only for an optional raw-key legacy path (section 8.2).

No open questions remain for PR1. Any residual multi-tenancy concerns (stream IDOR, slot
ownership, KV-cache side channel) are out of PR1 scope and tracked for later PRs.
