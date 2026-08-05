# PR2 design: principal propagation, audit log, trusted-proxy mode

Status: in_design
Features: F005 (principal propagation to handlers), F006 (audit log),
F007 (trusted-proxy mode / variant B).

This document is the implementation contract for a Haiku-class coder. Every non-obvious
decision is settled here. Do not invent behavior that is not written down; if something is
missing, stop and ask the architect.

ASCII only in all code and docs (AGENTS.md): no em-dash, no unicode arrows, use `-` and `->`.

PR2 builds directly on the merged PR1 (docs/design/pr1-rbac-core.md). It reuses PR1 conventions:
all auth logic stays in server-auth.{h,cpp}; existing files get call sites / plumbing only;
fail closed; deny-by-default; no hand-rolled crypto (reuse the vendored SHA-256).

--------------------------------------------------------------------------------
## 0. Scope and non-goals

In scope for PR2:
- F005: build a full `server_auth_principal` during authorization and make it visible to
  handlers via a value stored on `server_http_req`, transported from the middleware through a
  thread_local that is cleared on middleware entry (PLAN.md 4.2b). Includes the gcp
  internal-dispatch path.
- F006: an optional JSON-lines audit stream (`--auth-audit-log PATH`), one line per
  authn/authz decision (allow and deny), with only non-sensitive fields (PLAN.md 7).
- F007: trusted-proxy mode (`--auth-trusted-proxies CIDR,...`): accept identity from
  `X-Auth-Subject` / `X-Auth-Roles` ONLY when the TCP peer is inside a configured CIDR;
  always strip those headers (and `X-Forwarded-Client-Cert`) before handler dispatch.

Explicitly NOT in PR2 (do not implement, do not add fields beyond what is noted):
- mTLS certificate parsing / `X-Forwarded-Client-Cert` consumption (PR3). PR2 only STRIPS
  `X-Forwarded-Client-Cert`; it never reads it.
- OIDC / JWT validation, `expires_at` enforcement, JWKS (PR4). `expires_at` is added to the
  principal struct now (value always 0 in PR2) so PR3/PR4 need no struct change.
- Audit-log rotation, async/background audit writer, per-principal rate limiting, stream/slot
  ownership (IDOR) checks (later PRs). PR2 audit is a synchronous, mutex-guarded append.
- Prometheus auth metrics (PR5).

Hard rules (CLAUDE.md) honored:
- Fail closed: any init error (bad CIDR, unopenable audit file) aborts startup.
- Identity headers are honored ONLY from a trusted peer and are ALWAYS stripped from the
  handler-visible request, trusted or not (identity flows only through `req.principal`).
- All new logic in server-auth.cpp; server-http.cpp gets the strip + peer-addr plumbing and the
  principal-copy call sites; server.cpp is unchanged (init already wires everything).
- No secrets on argv, in logs, or in the audit stream.

--------------------------------------------------------------------------------
## 1. Discrepancies between PLAN.md and the current (post-PR1) code

Anchors verified on branch `master` after PR1 merged.

| PLAN.md / task claim | Reality | Impact |
|---|---|---|
| "authorize_request does not expose the principal" | Correct: server-auth.cpp:433 resolves a local `perms` and never builds a `server_auth_principal`; the struct's `role` field is written nowhere | F005 must build and surface it |
| `server_http_req` needs a `principal` field | server-http.h:49-65; it is an aggregate with a reference member `should_stop` | add a value member with an in-class default (section 4.1) |
| get/post/del req construction "~583/630/647" | actual: get 562-570, post 610-618, del 628-636 | 3 copy sites |
| gcp internal req "~802" | actual: `const server_http_req internal_req {...}` at server-http.cpp:795-803, built on a `std::async(std::launch::async,...)` worker thread (line 760) | CRITICAL: the async worker does NOT inherit the request thread_local; the gcp path MUST copy from `req.principal`, not from the thread_local (section 4.3) |
| `registered_routes` (method,path) to be added in PR1 | already present: server-http.h:77, populated in get/post/del | reuse as-is |
| `req.remote_addr` availability in middleware | set in `process_request` (httplib.cpp:8472/8532-8534) BEFORE `routing()`/`pre_routing_handler_` (8175-8177) | peer addr is available in the middleware |
| peer addr trustworthiness | llama-server does NOT call `set_trusted_proxies`; httplib `trusted_proxies_` is empty, so `req.remote_addr` is the real TCP peer, never a client-supplied `X-Forwarded-For` | F007 may trust `req.remote_addr`; see open question Q3 for the rebase risk |

No discrepancy blocks the design. The one substantive correction to the task's framing: the gcp
internal dispatch runs on a `std::async` worker thread, so principal transport for that path is
by explicit value copy from the outer `req.principal`, not via the thread_local (section 4.3).

--------------------------------------------------------------------------------
## 2. server-auth.h changes (full contract)

### 2.1 Extended principal struct (F005)

Replace the PR1 `server_auth_principal` (which had a single `role` string) with:

```cpp
// Extended in PR3 (AUTH_MTLS) and PR4 (AUTH_OIDC); AUTH_TRUSTED_PROXY added in PR2.
enum server_auth_method { AUTH_NONE, AUTH_API_KEY, AUTH_TRUSTED_PROXY };

// The identity resolved for a request. In PR2 this is copied onto server_http_req so
// handlers can read req.principal (audit, future slot/stream ownership checks).
struct server_auth_principal {
    bool                     authenticated = false;
    std::string              subject;    // stable non-reversible id (never the raw key)
    std::string              issuer;     // "" (api key) or "trusted-proxy"; OIDC iss / mTLS CA later
    std::vector<std::string> roles;      // resolved role names (may be empty)
    uint32_t                 perms       = 0;
    server_auth_method       method      = AUTH_NONE;
    int64_t                  expires_at  = 0; // 0 = no expiry; populated by OIDC in PR4
};
```

Add `#include <vector>` to server-auth.h (PR1 used `std::vector` in the assert signature only
via a transitive include; make it explicit now that the struct itself uses it).

No handler or PR1 test reads the old `.role` field (grep clean), so replacing it with `roles`
is safe.

### 2.2 Auth request DTO (inputs)

Bundle the per-request inputs into one struct so the signature is stable as PR3/PR4 add fields
(this replaces the four scalar parameters of the PR1 `authorize_request`):

```cpp
struct server_auth_request {
    std::string method;          // req.method
    std::string raw_path;        // req.path (already single-decoded by httplib)
    std::string authorization;   // Authorization header (raw, may be empty)
    std::string x_api_key;       // X-Api-Key header (raw, may be empty)
    std::string peer_addr;       // req.remote_addr (actual TCP peer)
    std::string x_auth_subject;  // X-Auth-Subject header (honored only if peer trusted)
    std::string x_auth_roles;    // X-Auth-Roles header, comma-separated (honored only if trusted)
    // X-Forwarded-Client-Cert is consumed in PR3; PR2 only strips it, never reads it here.
};
```

### 2.3 server_auth interface changes

```cpp
struct server_auth {
    static bool init(const common_params & params);   // unchanged name; extended body (section 5)

    static server_norm_status normalize_path(const std::string & raw_path,
                                              std::string & out_normalized); // unchanged

    static uint32_t required_perm(const std::string & normalized_path,
                                  const std::string & method,
                                  bool & matched);      // unchanged

    // CHANGED signature: takes the DTO. Resolves the principal (trusted-proxy -> API key),
    // stores it in the request-scoped thread_local, writes one audit line, and returns the
    // authz decision. Never throws.
    static server_auth_decision authorize_request(const server_auth_request & req);

    // NEW (F005): request-scoped principal transport.
    // reset_principal() clears the thread_local; call it at middleware ENTRY (PLAN.md 4.2b)
    // so a prior request's principal cannot leak on a reused worker thread.
    static void reset_principal();
    // principal_at_construction() returns the thread_local resolved by the most recent
    // authorize_request on THIS thread. It is VALID ONLY synchronously at server_http_req
    // construction time (get/post/del), on the same worker thread that ran the middleware.
    // Handlers MUST read req.principal, never this: reading it lazily during streaming, from
    // on_complete, or from a gcp std::async worker returns a stale or foreign identity (1c).
    static const server_auth_principal & principal_at_construction();

    static void register_route(const std::string & method,
                               const std::string & path_pattern,
                               uint32_t perm);          // unchanged
    static bool is_infer_only(const std::string & normalized_path);          // unchanged
    static bool assert_routes_covered(
        const std::vector<std::pair<std::string, std::string>> & registered_routes); // unchanged
};
```

`server_auth_decision`, `server_perm`, `PERM_ALL`, `server_norm_status` are unchanged from PR1.

--------------------------------------------------------------------------------
## 3. F005: principal propagation - data flow

The principal is produced once, inside `authorize_request`, and travels to the handler by two
different mechanisms depending on the code path:

```
pre_routing_handler (server-http.cpp, one worker thread per request)
  |  reset_principal()                 <- FIRST line, unconditional (clear-on-entry)
  |  CORS / OPTIONS short-circuit / middleware_server_state / frontend-asset carve-out
  |  middleware_authz:
  |     authorize_request(dto)         <- resolves principal, sets thread_local t_principal,
  |                                        writes audit line, returns decision
  |
  v  (same thread continues into the matched handler)
get()/post()/del() handler lambda
  |  build server_http_req { ...existing... }
  |  request->principal = server_auth::principal_at_construction(); <- copy thread_local -> req
  |  handler(*request)   -> handler reads req.principal (never the accessor)
  |
  '- gcp /predict handler (post): its own req.principal is set as above (INFER principal).
        For each instance it spawns std::async(std::launch::async, ...) on a DIFFERENT thread,
        so the thread_local is NOT valid there. The internal_req copies req.principal by VALUE:
            internal_req.principal = req.principal;   (already resolved, thread-safe read)
```

### 3.1 Why both a thread_local AND a field

- The thread_local (`t_principal` in server-auth.cpp) is the transport across the
  pre_routing/handler boundary: httplib runs `pre_routing_handler_` and then the matched
  handler sequentially on the SAME worker thread, so a thread_local set in the middleware is
  readable at handler-construction time without threading it through httplib's `Request`.
- The field `server_http_req::principal` is the stable, thread-independent copy handlers read.
  Copying into the field decouples handler code from thread_local lifetime and makes the gcp
  async path correct (it copies the field, not the thread_local).

The handler contract is therefore: **read `req.principal` only**. `principal_at_construction()`
exists solely for the get/post/del copy step and is valid only synchronously on the worker
thread at construction time. A handler that calls it lazily during streaming, from
`on_complete`, or from a gcp `std::async` worker would observe a stale or foreign identity (1c).
No PR2 handler does this; the accessor name and this contract exist to keep PR3+ from being
tempted.

### 3.2 The lifetime rule (PLAN.md 4.2b) - clear on ENTRY, not on exit

`reset_principal()` MUST be the first statement of the `pre_routing_handler` lambda, before
CORS, before the OPTIONS short-circuit, before `middleware_server_state`, and before the
frontend-asset carve-out. Reason: paths that skip `middleware_authz` (frontend assets, OPTIONS,
503-while-loading) never call `authorize_request`, so if the thread_local were only cleared
inside `authorize_request`, a previous authenticated request on the same thread would leave a
stale principal that a later early-returning request could observe. Clearing at entry makes the
worst case an EMPTY (unauthenticated) principal, never a foreign one.

Note: only `get()/post()/del()` construct a `server_http_req`. Static UI assets are served by
`srv->Get(...)` directly (server-http.cpp:376/393) and never build a `server_http_req`, so they
never copy a principal. Every route that DOES build a `server_http_req` has already passed
`authorize_request` (it is not a frontend asset and not OPTIONS), so
`principal_at_construction()` at construction time is exactly this request's resolved principal.

### 3.3 Subject derivation for the API-key method

The subject MUST be stable and non-reversible; never the raw key (CLAUDE.md, PLAN.md 7).
Reuse the SHA-256 already computed for the key lookup:

```
h       = sha256_hex(key)              // 64 lowercase hex chars, already computed for lookup
subject = "apikey:" + h.substr(0, 12)  // e.g. "apikey:9f86d081884c"
```

- Same derivation for legacy super-user keys and RBAC keys.
- `roles` for an API-key principal = the single resolved role name from the key table
  (`{"legacy"}` in legacy super-user mode; the policy role name in RBAC mode).
- `issuer` = "" for API keys. `method` = AUTH_API_KEY. `expires_at` = 0.
- Anonymous / unauthenticated request: `authenticated=false`, `subject=""`, `roles={}`,
  `perms=0`, `method=AUTH_NONE`.

--------------------------------------------------------------------------------
## 4. F005: exact code changes

### 4.1 server-http.h - add the principal field

Add `#include "server-auth.h"` at the top of server-http.h (server-auth.h is the natural owner
of `server_auth_principal`; server-http.cpp already includes it). Add ONE member to
`server_http_req`, as the LAST member with an in-class default so the existing aggregate
initializers that omit it still compile:

```cpp
struct server_http_req {
    std::map<std::string, std::string> params;
    std::map<std::string, std::string> headers;
    std::string path;
    std::string query_string;
    std::string body;
    std::map<std::string, uploaded_file> files;
    const std::function<bool()> & should_stop;

    server_auth_principal principal;   // PR2/F005: resolved identity for this request

    std::string get_param(...) const { ... }  // unchanged
};
```

Rationale for a default member initializer: `server_http_req` stays an aggregate (C++14+ allows
aggregates with default member initializers), so the three `server_http_req{...}` brace
initializers in get/post/del may omit the trailing `principal` and it is value-initialized. The
handler code then assigns the real value (section 4.2). This avoids editing the positional
aggregate initializers (fragile) at the get/post/del sites.

### 4.2 server-http.cpp - copy the principal at construction sites

In `get()` (after line 570), `post()` (after line 618), and `del()` (after line 636), after the
`std::make_unique<server_http_req>(...)` call and before `handler(*request)`, add ONE line:

```cpp
request->principal = server_auth::principal_at_construction();
```

For the gcp internal dispatch (server-http.cpp:795-803), the request is a `const` stack object
on a `std::async` worker thread; append `req.principal` as the last aggregate element (the field
has an in-class default, so appending it is valid and keeps it `const`):

```cpp
const server_http_req internal_req {
    req.params,
    req.headers,
    path_prefix + dispatch_path,
    req.query_string,
    payload.dump(),
    {},
    req.should_stop,
    req.principal,          // PR2/F005: carry the outer principal onto the async path
};
```

This is the whole gcp change for F005; the S1 `is_infer_only` guard from PR1 stays as-is.

### 4.3 server-http.cpp - clear on entry

In the `pre_routing_handler` lambda (server-http.cpp:253), make the FIRST statement:

```cpp
server_auth::reset_principal();
```

before the CORS block. No other middleware ordering changes.

### 4.4 server-auth.cpp - thread_local and accessors

```cpp
namespace {
    thread_local server_auth_principal t_principal;
}

void server_auth::reset_principal() { t_principal = server_auth_principal{}; }
const server_auth_principal & server_auth::principal_at_construction() { return t_principal; }
```

`authorize_request` assigns `t_principal = <resolved principal>` exactly once, immediately after
resolving it (section 6). On the `NORM_REJECT` early return it leaves `t_principal` as the
entry-cleared empty principal.

--------------------------------------------------------------------------------
## 5. F006 + F007: init changes (server-auth.cpp) and config

### 5.1 New common_params fields (common/common.h)

Next to `auth_policy_file` (common.h:646), add two fields:

```cpp
std::string auth_audit_log      = "";  // --auth-audit-log; empty = disabled
std::string auth_trusted_proxies = ""; // --auth-trusted-proxies; comma-separated CIDRs
```

### 5.2 New CLI flags (common/arg.cpp)

Following the `--auth-policy-file` pattern (arg.cpp:3374-3383), add two flags scoped to
`LLAMA_EXAMPLE_SERVER`:

```cpp
add_opt(common_arg(
    {"--auth-audit-log"}, "PATH",
    "append one JSON line per auth decision to PATH (ts, subject_hash, method, path, "
    "decision, required_perm, auth_method, peer_ip, request_id). No tokens, headers, keys, "
    "or prompts are ever written.",
    [](common_params & params, const std::string & value) {
        params.auth_audit_log = value;
    }
).set_examples({LLAMA_EXAMPLE_SERVER}).set_env("LLAMA_ARG_AUTH_AUDIT_LOG"));

add_opt(common_arg(
    {"--auth-trusted-proxies"}, "CIDR[,CIDR...]",
    "comma-separated IPv4/IPv6 CIDRs of the fronting proxy whose requests may carry identity "
    "via X-Auth-Subject / X-Auth-Roles. These headers are honored only from a listed peer and "
    "are always stripped before handler dispatch. Setting this ENABLES auth enforcement "
    "(deny-by-default) even with no --api-key/--auth-policy-file, so direct non-proxy clients "
    "then get 401 on protected routes. Use the proxy's own address (host /32 or /128, or its "
    "subnet), never 0.0.0.0/0 or ::/0. 127.0.0.1 and ::1 are different families - list both if "
    "the proxy may use either. Unset = never trust identity headers.",
    [](common_params & params, const std::string & value) {
        params.auth_trusted_proxies = value;
    }
).set_examples({LLAMA_EXAMPLE_SERVER}).set_env("LLAMA_ARG_AUTH_TRUSTED_PROXIES"));
```

Salt for the audit subject_hash is NOT a CLI flag (no argv secret). See section 7.4.

Q5 doc callout (also for README): `--auth-trusted-proxies` flips a previously-open
(keyless/policyless) server to deny-by-default; document this behavior change prominently.
`--auth-audit-log` does NOT flip enforcement - it opens the stream independently of
`g_auth_enabled` (section 5.3 step 4) and keeps that separation.

### 5.3 init: enabling auth, persisting role_perms, parsing proxies, opening audit

PR1's `init` builds a local `role_perms` map and discards it. PR2 must PERSIST it so
trusted-proxy role mapping works at request time. Add file-scope state and extend `init`:

```cpp
namespace {
    // existing PR1 state: g_route_table, g_key_perms, g_api_prefix, g_auth_enabled,
    //                     g_default_perms
    std::unordered_map<std::string, uint32_t> g_role_perms;   // role name -> perms (NEW)

    struct cidr {
        int      family;       // AF_INET or AF_INET6
        uint8_t  net[16];      // network bytes (4 used for v4, 16 for v6)
        int      bits;         // prefix length
    };
    std::vector<cidr> g_trusted_proxies;                       // NEW (F007)

    std::ofstream g_audit_ofs;                                 // NEW (F006)
    std::mutex    g_audit_mtx;                                 // NEW (F006)
    bool          g_audit_enabled = false;                     // NEW (F006)
    std::string   g_audit_salt;                                // NEW (F006)
}
```

Changes inside `init`, in order:

0. **FIX 4b (correctness trap - highest priority).** PR1 has an early return that fires BEFORE
   the role map is built:

   ```cpp
   // server-auth.cpp:301-304 (PR1)
   } else if (!has_api_keys) {
       g_auth_enabled = false;
       return true;          // <- returns before role_perms is built (~314-349)
   }
   ```

   In trusted-proxy-ONLY mode (no `--api-key`, no `--auth-policy-file`, only
   `--auth-trusted-proxies`), this early return fires, so `g_role_perms` is never populated and
   `g_auth_enabled` stays false. Result: X-Auth-Roles maps to nothing, enforcement is off, and
   every trusted-proxy caller authenticates to perms=0 while direct callers are allowed - a
   silent failure of the whole feature. The design REQUIRES this change:

   ```cpp
   } else if (!has_api_keys && !has_trusted_proxies) {
       g_auth_enabled = false;   // truly no auth configured
       // still open the audit log if requested (audit is independent, see step 4), then:
       return true;
   }
   ```

   With `has_trusted_proxies` true, control must FALL THROUGH to the role-building block so the
   compiled-in `admin`/`user` roles exist and `g_role_perms` is populated, and
   `g_auth_enabled` must end up true (step 1).

1. `has_trusted_proxies = !params.auth_trusted_proxies.empty();`
   `g_auth_enabled = has_policy_file || has_api_keys || has_trusted_proxies;`
   (Configuring trusted proxies alone now ENABLES auth; without it, trusted-proxy principals
   would be pointless because auth-disabled allows everything. See Q5 doc callout.)

2. When building the role map (PR1 already builds default or policy roles), also store it:
   `g_role_perms = role_perms;` after validation. Because of the step-0 fix this now runs on
   ALL enabled modes (legacy super-user, trusted-proxy-only, RBAC), so the compiled-in default
   roles (`admin`, `user`) are available for X-Auth-Roles mapping even without a policy file.
   Verify with a trusted-proxy-only smoke: no keys, no policy, `--auth-trusted-proxies
   127.0.0.0/8`, then a loopback `X-Auth-Roles: admin` must map to the admin perm set.

3. Parse `params.auth_trusted_proxies` into `g_trusted_proxies` (section 8.1). Any malformed
   CIDR, or a `/0` (all-peers) entry, -> `SRV_ERR` and return false (fail closed; see 2c).

4. If `params.auth_audit_log` is non-empty, open the audit file (section 7.1). Open failure ->
   `SRV_ERR` and return false (an operator who asked for an audit trail must get one). Open the
   audit file REGARDLESS of `g_auth_enabled` and BEFORE the step-0 auth-disabled early return,
   so `--auth-audit-log` works even on an otherwise-open server. Audit alone must NOT flip
   `g_auth_enabled` (audit is observability, not enforcement).

--------------------------------------------------------------------------------
## 6. authorize_request - new decision + resolve flow (server-auth.cpp)

`authorize_request` is rewritten to (a) build the DTO-driven principal, (b) stash it in the
thread_local, (c) run the PR1 authz logic against the resolved principal, and (d) emit one audit
line. Pseudocode (deny-by-default preserved from PR1 B2):

```
server_auth_decision authorize_request(const server_auth_request & r):
    std::string request_id = "req-" + random_string()

    // 1. Normalize (input validation, runs unconditionally, before any allow short-circuit)
    std::string norm
    server_norm_status ns = normalize_path(r.raw_path, norm)
    if ns == NORM_REJECT:
        t_principal = {}                                  // stays cleared
        d = deny(400, ERROR_TYPE_INVALID_REQUEST, "invalid request path")
        audit(r, /*norm*/ r.raw_path, /*need*/ 0, /*matched*/ false, t_principal, d, request_id)
        return d

    // 2. Resolve the principal: trusted-proxy first, then API key. Always set the thread_local.
    server_auth_principal p = resolve_principal(r)
    t_principal = p

    // 3. Auth-disabled mode: allow (principal may be unauthenticated). Still audit.
    if !g_auth_enabled:
        d = allow()
        audit(r, norm-or-unmatched, 0, false, p, d, request_id)
        return d

    // 4. NORM_UNMATCHED (outside api_prefix): deny-by-default, require an authenticated principal
    if ns == NORM_UNMATCHED:
        if !p.authenticated:
            d = deny(401, ERROR_TYPE_AUTHENTICATION, "Invalid API Key")
        else:
            d = allow()                                   // fall through to httplib 404
        audit(r, r.raw_path, 0, false, p, d, request_id)
        return d

    // 5. NORM_OK: classify + authorize
    bool matched = false
    uint32_t need = required_perm(norm, r.method, matched)

    if matched && need == PERM_PUBLIC:
        // 3c: public routes (/health, /v1/health, /models GET) are NOT audited. They are the
        // high-frequency poller paths; auditing them would put a mutex+write on every health
        // check. Return WITHOUT calling audit.
        return allow()

    if !p.authenticated:
        d = deny(401, ERROR_TYPE_AUTHENTICATION, "Invalid API Key")
    else if !matched:
        d = allow()                                       // authenticated; unknown route -> 404
    else if (p.perms & need) == need:
        d = allow()
    else:
        d = deny(403, ERROR_TYPE_PERMISSION, "insufficient permissions")

    audit(r, norm, need, matched, p, d, request_id)
    return d
```

Audit-emission sites: the `NORM_REJECT` (400), auth-disabled allow, `NORM_UNMATCHED`, and the
final NORM_OK block all audit. The ONLY non-audited path is a matched `PERM_PUBLIC` allow (3c).
OPTIONS, 503-while-loading, and frontend assets never reach `authorize_request` and are likewise
not audited.

This preserves every PR1 behavior (auth-disabled allows; anonymous on a protected/unclassified/
unmatched path gets 401; authenticated-but-underprivileged gets 403; malformed path 400) while
routing the credential resolution through `resolve_principal` and emitting audit.

### 6.1 resolve_principal (server-auth.cpp, new static helper)

```
server_auth_principal resolve_principal(const server_auth_request & r):
    // Precedence (PR2 subset of PLAN's mTLS -> OIDC -> proxy-headers -> API key):
    //   trusted-proxy headers (only from a trusted peer) -> API key -> anonymous
    if peer_is_trusted(r.peer_addr) && !r.x_auth_subject.empty():
        server_auth_principal p
        p.authenticated = true
        p.method        = AUTH_TRUSTED_PROXY
        p.issuer        = "trusted-proxy"
        p.subject       = r.x_auth_subject          // opaque id from the proxy (hashed for audit)
        p.roles         = split_csv(r.x_auth_roles) // e.g. "admin,user"
        p.perms         = 0
        for role in p.roles:
            auto it = g_role_perms.find(role)
            if it != end: p.perms |= it->second     // unknown roles contribute nothing (fail-closed)
        // p.roles retains only the names as sent; perms reflect only known roles
        return p

    // API key (mirrors PR1 header parsing exactly)
    std::string key = r.authorization
    if key.empty(): key = r.x_api_key
    if key.rfind("Bearer ", 0) == 0: key = key.substr(7)
    if !key.empty():
        std::string h = sha256_hex(key)
        auto it = g_key_perms.find(h)
        uint32_t perms = 0; std::string role
        if it != g_key_perms.end():
            perms = it->second.perms; role = it->second.role
        else if g_default_perms != 0:
            perms = g_default_perms; role = ""      // default_role case
        else:
            return {}                                // unknown key -> anonymous (caller -> 401)
        server_auth_principal p
        p.authenticated = true
        p.method        = AUTH_API_KEY
        p.subject       = "apikey:" + h.substr(0, 12)
        if !role.empty(): p.roles = { role }
        p.perms         = perms
        return p

    return {}                                        // anonymous
```

Notes:
- A trusted-proxy principal with zero known roles is `authenticated=true, perms=0`: it passes
  authentication but is denied (403) on any protected route - fail closed, matching PLAN's
  "unmapped role -> deny, not a default role" (Q4: confirmed - keep perms=0, not a hard 401).
- **Roles vs perms (Q4).** `p.roles` retains the RAW client-sent role names (all of them, known
  or not) purely for audit and future use. Authorization is done ONLY on `p.perms`, which is the
  OR of the perms of the KNOWN roles (unknown roles contribute nothing). Enforce a hard rule for
  all current and future code: NO handler and no authz path may branch on role NAMES; perms are
  the only authorization currency. This keeps an attacker who guesses a role string from gaining
  anything unless that string is a configured role with real perms.
- The API-key branch is unchanged in behavior from PR1 (same header order, same Bearer strip,
  same default_role semantics), only refactored to yield a principal.
- If the peer is trusted but `X-Auth-Subject` is empty, we fall through to API-key auth (a
  trusted proxy may forward a Bearer/API key instead of identity headers).

### 6.2 split_csv

`split_csv(s)` trims whitespace around each comma-separated token and drops empty tokens.
Used for `X-Auth-Roles`.

--------------------------------------------------------------------------------
## 7. F006: audit log details

### 7.1 Opening the file

```cpp
g_audit_ofs.open(params.auth_audit_log, std::ios::out | std::ios::app);
if (!g_audit_ofs.is_open()) {
    SRV_ERR("failed to open audit log: %s\n", params.auth_audit_log.c_str());
    return false;      // fail closed
}
g_audit_enabled = true;
g_audit_salt    = audit_salt();   // section 7.4
```

Append mode; the file is created if absent. No rotation in PR2 (documented limitation). The
`std::ofstream` static destructor flushes/closes at process exit.

### 7.2 Where the write happens

A single helper `audit_emit(...)` is called from `authorize_request` at every return site
EXCEPT the matched-`PERM_PUBLIC` allow (3c). So one line is written per non-public decision that
reaches the middleware. Frontend assets, OPTIONS, 503-while-loading, and public routes
(`/health`, `/v1/health`, `/models` GET) are NOT audited (they carry no identity and no
enforced policy decision, and are the high-frequency poller paths).

### 7.3 Line format, thread-safety, and DoS posture (3c)

Build with `nlohmann::ordered_json` and append under the mutex:

```cpp
void audit_emit(const server_auth_request & r, const std::string & norm_path,
                uint32_t need, bool matched, const server_auth_principal & p,
                const server_auth_decision & d, const std::string & request_id) {
    if (!g_audit_enabled) return;
    json line = {
        {"ts",            iso8601_utc_now()},
        {"subject_hash",  p.authenticated ? sha256_hex(p.subject + g_audit_salt) : "anonymous"},
        {"method",        r.method},
        {"path",          norm_path},                       // normalized (or raw on 400)
        {"decision",      d.allowed ? "allow" : "deny"},
        {"required_perm", matched ? perm_to_string(need) : ""},
        {"auth_method",   auth_method_to_string(p.method)}, // "none"/"api_key"/"trusted_proxy"
        {"peer_ip",       r.peer_addr},
        {"request_id",    request_id},
    };
    // json::dump() escapes control characters, so a %0A-decoded newline in norm_path becomes a
    // literal "\n" inside the JSON string - it can never split or inject a second log line.
    std::lock_guard<std::mutex> lk(g_audit_mtx);
    g_audit_ofs << line.dump() << "\n";
}
```

DoS posture (3c): there is NO unconditional per-line `flush()`. Public poller paths are excluded
(section 7.2), and the remaining audited lines rely on `ofstream`'s own buffering; the buffer is
flushed by the static destructor at process exit. This removes the "every `/health` poll takes
the audit mutex and fsync-less flush" hazard. The mutex still guarantees whole-line integrity
under concurrency. Documented throughput caveat: a flood of AUTHENTICATED requests still
serializes on the mutex + buffered write; a bounded async writer is deferred (Q3). Audit is
strictly fail-OPEN: if the stream enters a fail state (disk full), lines are silently dropped
and the request is NEVER failed - audit is observability, not an auth gate.

Note for tests: because there is no explicit flush, a pytest that reads the audit file WHILE the
server runs may not see the most recent line until enough is buffered or the server stops. The
F006 tests therefore assert on the audit file AFTER `server.stop()` (or read with a
retry/sleep), not immediately after each request.

- `perm_to_string(uint32_t)`: "PUBLIC" for 0-when-matched, else the single bit name
  ("INFER","READ_STATE","METRICS","ADMIN_STATE","ADMIN_MODELS","PROXY"); "" when unmatched.
- `auth_method_to_string`: AUTH_NONE->"none", AUTH_API_KEY->"api_key",
  AUTH_TRUSTED_PROXY->"trusted_proxy".
- `iso8601_utc_now()`: `time()` + `gmtime_r` + `strftime("%Y-%m-%dT%H:%M:%SZ")` (seconds
  precision; ASCII, locale-independent). On Windows use `gmtime_s`.
- MUST NOT appear anywhere in the object: the key, the Authorization/X-Api-Key values, the
  X-Auth-Subject raw value (only its salted hash), the request body/prompt, or any DN. The
  field set above is exhaustive; do not add the raw subject, headers, or body.

### 7.4 Salt source

```
audit_salt():
    const char * env = std::getenv("LLAMA_AUTH_AUDIT_SALT")
    if env && env[0]: return std::string(env)     // configurable, stable across restarts
    return random_string()                          // per-process random (default)
```

Default is a per-process random salt: subject hashes correlate within one server lifetime but
not across restarts, and are not reversible to the subject. An operator who needs cross-restart
correlation sets `LLAMA_AUTH_AUDIT_SALT` (env, not argv). Document that the salt itself is never
logged.

--------------------------------------------------------------------------------
## 8. F007: trusted-proxy mode details

### 8.1 CIDR parsing (init)

For each comma-separated token in `params.auth_trusted_proxies`:
- Split on the last `/` into `addr` and optional `bits`. Bare address -> bits = 32 (v4) / 128 (v6).
- Try `inet_pton(AF_INET, addr, buf4)`; on success family=AF_INET, copy 4 bytes, require
  0 < bits <= 32.
- Else try `inet_pton(AF_INET6, addr, buf16)`; on success family=AF_INET6, copy 16 bytes,
  require 0 < bits <= 128.
- Else -> malformed: `SRV_ERR("invalid --auth-trusted-proxies entry: %s\n", token)` and
  `return false` (fail closed).

**FIX 2c (all-peers footgun).** A `/0` prefix (`0.0.0.0/0` or `::/0`, or any `bits == 0`) trusts
EVERY peer, which lets any direct client assert `X-Auth-Subject: admin` and fully defeats the
mechanism. Reject it at init: `bits == 0` -> `SRV_ERR("--auth-trusted-proxies entry '%s' trusts
all peers; specify the proxy's own address\n", token)` and `return false`. Hence the `0 < bits`
bounds above. Document in the flag help and README that `--auth-trusted-proxies` must be the
proxy's own address (a host `/32` or `/128`, or the proxy subnet), never a default route.

Includes: guard like httplib does -
```cpp
#ifdef _WIN32
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#endif
```

### 8.2 peer_is_trusted(peer_addr)

**INVARIANT (Q2/2a) - document this comment directly above `peer_is_trusted`.** `r.peer_addr`
is `req.remote_addr`, which is the genuine TCP peer ONLY because llama-server never calls
httplib's `set_trusted_proxies`. If it ever did, httplib would rewrite `req.remote_addr` from a
client-supplied `X-Forwarded-For` header (httplib.cpp:8522-8535), and a direct attacker could
spoof the peer to land inside a trusted CIDR and forge identity. `trusted_proxies_` is private
with no getter, so a compile-time assert is infeasible. The guard is therefore a REQUIRED pytest
rebase-tripwire (F007 acceptance): from a non-listed peer, send
`X-Forwarded-For: <listed-proxy-ip>` plus `X-Auth-Roles: admin` and assert 401/403 on a
protected route. If a future rebase turns on httplib X-Forwarded-For handling, that test flips to
green-for-attacker and fails, catching the regression. Do NOT mark F007 done without it.

```
peer_is_trusted(peer):
    if g_trusted_proxies.empty(): return false      // no config -> never trust (F007 criterion)
    // Normalize an IPv4-mapped IPv6 peer ("::ffff:a.b.c.d") to its IPv4 form before matching.
    std::string a = strip_v4mapped_prefix(peer)     // section 8.3
    parse a with inet_pton for AF_INET then AF_INET6 into pbytes/pfamily
    if parse failed: return false                   // unix socket / empty / hostname -> not trusted
    for each c in g_trusted_proxies:
        if c.family == pfamily && prefix_match(pbytes, c.net, c.bits): return true
    return false

prefix_match(a, b, bits):
    full = bits / 8; rem = bits % 8
    if memcmp(a, b, full) != 0: return false
    if rem:
        uint8_t mask = 0xFF << (8 - rem)
        if (a[full] & mask) != (b[full] & mask): return false
    return true
```

### 8.3 IPv4-mapped and edge inputs

- `strip_v4mapped_prefix`: if `peer` starts with "::ffff:" and the remainder parses as IPv4,
  treat it as that IPv4 (so a v4 CIDR matches a v4-mapped peer). Otherwise leave unchanged.
- Empty peer, a `.sock` unix-socket peer, or a hostname never parse to an address -> not trusted
  -> identity headers ignored (fail closed). Consequence: trusted-proxy mode is UNUSABLE over a
  unix-socket listener (the peer has no IP); document this - a proxy fronting llama-server must
  use a TCP loopback/link, not the unix socket, if it needs to assert identity.
- `::1` (IPv6 loopback) and `127.0.0.1` (IPv4 loopback) are DISTINCT addresses in different
  families; a `127.0.0.0/8` CIDR does not match a `::1` peer and vice versa. If the fronting
  proxy may connect over either family, list both (e.g. `127.0.0.0/8,::1/128`). Document in the
  flag help.

### 8.4 Header stripping (server-http.cpp) - the hard rule

Identity headers must NEVER be visible to handlers, whether or not the peer is trusted (the
trust decision is already captured in `req.principal`). Strip them at the point where handler
headers are materialized: `get_headers(const httplib::Request & req)` (server-http.cpp:496-502).
Add a case-insensitive skip set:

```cpp
static std::map<std::string, std::string> get_headers(const httplib::Request & req) {
    static const std::unordered_set<std::string> stripped = {
        "x-auth-subject", "x-auth-roles", "x-forwarded-client-cert",
    };
    std::map<std::string, std::string> headers;
    for (const auto & [key, value] : req.headers) {
        std::string lk = key; // lowercase
        std::transform(lk.begin(), lk.end(), lk.begin(),
                       [](unsigned char c){ return std::tolower(c); });
        if (stripped.count(lk)) continue;   // never forward identity headers to handlers/MCP
        headers[key] = value;
    }
    return headers;
}
```

Consequences:
- A direct (untrusted) client that sends `X-Auth-Subject` cannot reach a handler with it (the
  middleware ignores it because the peer is untrusted, and `get_headers` removes it) - no
  injection.
- The MCP proxy (which forwards `server_http_req::headers`) never re-emits identity headers
  upstream.
- The middleware itself reads the raw `X-Auth-*` values via `req.get_header_value(...)` in
  server-http.cpp BEFORE this copy; that is trusted gating code and is the only reader.
- With no `--auth-trusted-proxies`, `peer_is_trusted` is always false, so the headers are both
  ignored by the middleware and stripped here: "always stripped/ignored" criterion met.

### 8.5 Middleware wiring (server-http.cpp)

Replace the four-arg `authorize_request` call in `middleware_authz` (server-http.cpp:213-227)
with a DTO built from the request, including peer and identity headers:

```cpp
auto middleware_authz = [](const httplib::Request & req, httplib::Response & res) {
    server_auth_request ar;
    ar.method        = req.method;
    ar.raw_path      = req.path;
    ar.authorization = req.get_header_value("Authorization");
    ar.x_api_key     = req.get_header_value("X-Api-Key");
    ar.peer_addr     = req.remote_addr;
    ar.x_auth_subject= req.get_header_value("X-Auth-Subject");
    ar.x_auth_roles  = req.get_header_value("X-Auth-Roles");
    const server_auth_decision d = server_auth::authorize_request(ar);
    if (d.allowed) return true;
    res.status = d.status;
    res.set_content(
        safe_json_to_str(json {{"error", format_error_response(d.message, d.type)}}),
        "application/json; charset=utf-8");
    return false;
};
```

--------------------------------------------------------------------------------
## 9. Fail-closed behavior summary

| Condition | Behavior |
|---|---|
| Malformed or all-peers (`/0`) `--auth-trusted-proxies` CIDR | `init` returns false; server aborts (2c) |
| `--auth-audit-log` path unopenable | `init` returns false; server aborts |
| Trusted-proxy-only mode (no keys/policy) | 4b fix: role map + `g_role_perms` still built; `g_auth_enabled` true |
| Peer not in trusted CIDR (or no CIDR configured) | X-Auth-* ignored by middleware, stripped from handler view; API-key auth applies |
| Trusted peer, X-Auth-Roles with only unknown roles | principal authenticated, perms=0 -> 403 on any protected route |
| Trusted peer, X-Auth-Subject empty | fall through to API-key auth |
| Stale thread_local from a prior request | impossible: cleared at pre_routing entry; worst case is empty/unauthenticated |
| gcp async worker (no thread_local) | principal copied by value from `req.principal`; INFER-only guard (PR1 S1) still applies |
| Audit write fails mid-run (disk full) | ofstream enters fail state; lines silently dropped (3c); request is NOT failed (audit is observability, not a gate) - documented tradeoff |

--------------------------------------------------------------------------------
## 10. Acceptance criteria (testable with tools/server/tests pytest harness)

Thread the two new flags into `tools/server/tests/utils.py::ServerProcess` (following the
`auth_policy_file` pattern already added in PR1): `auth_audit_log: str | None` and
`auth_trusted_proxies: str | None`, each appended to `server_args` when set.

### F005 (principal propagation)
- A handler-observable surface confirms the principal: for the test harness, the simplest probe
  is behavioral - with a valid `user` key, `POST /completions` succeeds (INFER) and the audit
  line (if enabled) shows `auth_method=api_key` and a non-anonymous `subject_hash`; with no key
  in auth-disabled mode the same request shows `auth_method=none`. (No new debug endpoint is
  added in PR2; principal visibility is asserted via the audit stream, which reads
  `req`-resolved fields, plus the gcp test below.)
- No stale-principal leak across requests on a reused worker thread: on a single-threaded
  server (`--threads-http 1`), run an authenticated (admin key) request, then an ANONYMOUS
  request to a PROTECTED route (`GET /slots`). The `/slots` audit line shows
  `subject_hash=anonymous` and the response is 401, proving the thread_local was cleared on
  ENTRY (not carried over from the prior admin request). (Public routes are not audited under
  3c, so the probe uses a protected route, not `/health`.)
- gcp path (AIP_MODE=PREDICTION): a `/predict` request authorized at INFER produces internal
  dispatch whose principal equals the outer request's principal (the request succeeds; a
  non-INFER `@requestFormat` is still rejected by the PR1 S1 guard).

### F006 (audit log)
Tests read the audit file AFTER `server.stop()` (there is no per-line flush under 3c; see
section 7.3).
- Every NON-PUBLIC authn/authz decision emits exactly one JSON line with all nine fields
  (ts, subject_hash, method, path, decision, required_perm, auth_method, peer_ip, request_id).
- Both an allow and a deny are logged (e.g. `user` key to `/slots` -> one `deny` line with
  `decision=deny`, `required_perm=READ_STATE`; `admin` key to `/slots` -> one `allow` line).
- A 400 (malformed path, e.g. `//slots`) emits a `deny` line.
- Public routes are NOT audited (3c): a burst of `GET /health` and `GET /v1/health` produces
  zero audit lines.
- Log-injection safety: a request whose path contains `%0A` (decodes to a literal newline) still
  produces a SINGLE JSON line - `json::dump()` escapes the newline as `\n` inside the string
  (parse each audit line as JSON and assert one object per physical line).
- `grep` of the audit file for a configured API key, its Bearer header value, an X-Auth-Subject
  raw value, and any request-body substring returns nothing (no secret/PII leakage).
- `subject_hash` is stable for the same key within one process run and differs from the raw
  subject; with `LLAMA_AUTH_AUDIT_SALT` set, it is stable across restarts.
- Path is the NORMALIZED path (e.g. `/slots`, not a prefixed or encoded form) on non-400 lines.
- `--auth-audit-log` alone (no key, no policy, no proxies) still writes lines and does NOT turn
  on enforcement (an unprotected server still logs decisions; direct requests are allowed).
- An unopenable `--auth-audit-log` path aborts startup.

### F007 (trusted-proxy mode)
- Identity headers from a NON-listed peer are ignored and stripped: a request from 127.0.0.1
  with `X-Auth-Subject: alice`, `X-Auth-Roles: admin` while `--auth-trusted-proxies 10.0.0.0/8`
  is set gets NO admin access (falls back to API-key auth; `POST /slots` -> 401/403), and the
  header never reaches a handler (verified via an echo route / MCP path if available, else via
  the audit `auth_method` not being `trusted_proxy`).
- Identity headers from a LISTED peer produce an authenticated principal with mapped roles:
  with `--auth-trusted-proxies 127.0.0.0/8`, a request from loopback with
  `X-Auth-Subject: ops`, `X-Auth-Roles: admin` can `POST /slots/0` (ADMIN_STATE) with no API
  key; audit shows `auth_method=trusted_proxy`, non-anonymous `subject_hash`.
- `X-Auth-Roles` with an unknown role only -> authenticated but 403 on a protected route.
- With NO `--auth-trusted-proxies` configured, identity headers are always ignored/stripped
  (loopback client with `X-Auth-Roles: admin` still gets 401/403 on `/slots`).
- IPv6 CIDR: a `::1/128` trusted-proxies value trusts an IPv6 loopback peer; a v4-mapped peer
  `::ffff:127.0.0.1` matches a `127.0.0.0/8` v4 CIDR.
- Startup aborts on a malformed CIDR (`--auth-trusted-proxies not-a-cidr`) and on an all-peers
  entry (`--auth-trusted-proxies 0.0.0.0/0` or `::/0`) (2c).
- REBASE TRIPWIRE (Q2/2a, REQUIRED - do not mark F007 done without it): start with
  `--auth-trusted-proxies <IP-of-a-different-host>` (not the test client's IP); from the test
  client (a non-listed peer) send `X-Forwarded-For: <that listed IP>` together with
  `X-Auth-Subject: attacker`, `X-Auth-Roles: admin`; assert the protected route (`POST /slots/0`)
  returns 401/403 and audit `auth_method` is not `trusted_proxy`. This fails if a future rebase
  lets httplib rewrite `req.remote_addr` from `X-Forwarded-For` (section 8.2 invariant).
- Trusted-proxy mode over a unix-socket listener: a proxy cannot assert identity (peer has no
  IP); a request with identity headers over the unix socket gets no trusted-proxy principal.

--------------------------------------------------------------------------------
## 11. Files touched

New logic (server-auth.*), plumbing/call sites elsewhere:

- `tools/server/server-auth.h` - extend `server_auth_principal` (subject/issuer/roles/
  expires_at), add `AUTH_TRUSTED_PROXY`, add `server_auth_request`, change `authorize_request`
  signature to take the DTO, add `reset_principal`/`principal_at_construction`. Add
  `#include <vector>`.
- `tools/server/server-auth.cpp` - thread_local + accessors; persist `g_role_perms`; parse
  `g_trusted_proxies`; open audit stream + salt; rewrite `authorize_request`; add
  `resolve_principal`, `peer_is_trusted`, CIDR match, `split_csv`, `audit_emit`,
  `perm_to_string`, `auth_method_to_string`, `iso8601_utc_now`, `audit_salt`.
- `tools/server/server-http.h` - `#include "server-auth.h"`; add `server_auth_principal
  principal;` field to `server_http_req`.
- `tools/server/server-http.cpp` - `reset_principal()` at pre_routing entry; build the DTO in
  `middleware_authz`; strip identity headers in `get_headers`; copy
  `principal_at_construction()` into
  the req at get/post/del; carry `req.principal` into the gcp internal req.
- `common/common.h` - `auth_audit_log`, `auth_trusted_proxies` fields.
- `common/arg.cpp` - `--auth-audit-log`, `--auth-trusted-proxies` flags + env vars.
- `tools/server/tests/utils.py` - thread the two flags (coder threads only; tests owned by
  test-planner).

No change to server.cpp (init/assert call sites from PR1 are sufficient). No new source files,
no new CMake entries (SHA-256 already vendored in PR1).

--------------------------------------------------------------------------------
## 12. Suggested implementation order (per feature)

1. F005 first (principal struct + thread_local + field + copy sites + gcp carry): it is the
   substrate F006/F007 populate. Ship with the existing API-key subject derivation.
2. F006 (audit): add flags/fields, open stream, `audit_emit` at all `authorize_request` return
   sites. Independent of F007.
3. F007 (trusted proxy): flags/fields, CIDR parse + match, `resolve_principal` trusted-proxy
   branch, `get_headers` strip, DTO wiring. Depends on F005 (needs the principal) and reuses
   F006's `auth_method` in audit.

`depends_on`: F005 -> F004 (PR1). F006 -> F005. F007 -> F005.

--------------------------------------------------------------------------------
## 13. Challenger review outcomes (resolved)

The challenger (Fable) reviewed the first draft: no architectural blocker, design sound. Four
bounded MUST-FIXes and several callouts were folded in. Status stays in_design for F005-F007.

MUST-FIX applied:
- **4b (correctness trap, highest priority).** RESOLVED in section 5.3 step 0: PR1's
  `else if (!has_api_keys) { g_auth_enabled=false; return true; }` (server-auth.cpp:301-304)
  early-returned before the role map was built, so trusted-proxy-only mode never populated
  `g_role_perms` and left `g_auth_enabled` false. Changed to
  `else if (!has_api_keys && !has_trusted_proxies)`; control falls through to build the default
  roles and `g_role_perms`, and `g_auth_enabled` ends true when proxies are configured. Added a
  trusted-proxy-only smoke to F005/F007 acceptance.
- **Q2/2a (rebase tripwire).** RESOLVED: the `req.remote_addr`-is-genuine-peer invariant is
  documented directly above `peer_is_trusted` (section 8.2), and a REQUIRED pytest tripwire
  (non-listed peer + spoofed `X-Forwarded-For` -> still 401/403) is in F007 acceptance. F007 may
  not be marked done without it.
- **3c (audit DoS).** RESOLVED in sections 6/7.2/7.3: matched-`PERM_PUBLIC` allows (the
  `/health` poller paths) are NOT audited, and the unconditional per-line `flush()` is removed
  (rely on ofstream buffering, flushed at exit). Mutex retained for line integrity. Audit stays
  fail-OPEN. Tests read the file after `server.stop()`.
- **2c (CIDR footgun).** RESOLVED in section 8.1: a `/0` (all-peers) trusted-proxy entry is
  rejected at init (`0 < bits`), startup aborts; flag help/README say to use the proxy's own
  address.

Callouts applied:
- **1c (accessor foot-gun).** `current_principal()` renamed to `principal_at_construction()`
  with a doc contract: handlers read `req.principal` only; the accessor is valid solely at
  construction time (sections 2.3, 3.1, 4).
- **Q4 (roles vs perms).** Kept unknown-role -> perms=0 (authenticated, 403). Added the hard
  rule (section 6.1): `p.roles` retains raw client role names for audit/future only;
  authorization is ONLY on `p.perms`; no code may branch on role names.
- **Q5 (enforcement flip).** Documented in the `--auth-trusted-proxies` flag help (section 5.2)
  and flagged for README; `--auth-audit-log` remains independent of enforcement.
- **Family/socket notes.** `127.0.0.1` vs `::1` are distinct families (list both); a unix-socket
  peer never parses, so trusted-proxy mode is unusable over a unix socket (sections 8.3, 5.2).

Confirmed CLEAN by the challenger (no change needed): the gcp `std::async` worker cannot leak a
foreign identity (fresh thread, empty t_principal; by-value `req.principal` copy is correct);
clear-on-entry closes OPTIONS/503/frontend early returns; identity headers are stripped on every
handler-visible path incl. gcp internal req, cors-proxy, and MCP; `json::dump()` escapes newlines
so a `%0A` path cannot inject a second log line (acceptance test added); no secret/PII in the
log; the `authorize_request` rewrite preserves every PR1 outcome (401/403/400, B1, B2) provided
the branch order is mirrored exactly (section 6).

Remaining (deferred, not blockers): a bounded async audit writer (Q3) and enforcing token
`expires_at` on long-lived SSE streams are PR4+ concerns. Subject-hash uses a full SHA-256 of
`subject+salt` in the log regardless of the 12-hex in-memory subject prefix.
