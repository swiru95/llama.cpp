# PR7 design: additional hardening (SSRF proxy allowlist, auth metrics, runtime CRL reload)

Status: in_design
Features: F014 (/cors-proxy SSRF hardening), F015 (Prometheus auth metrics), F016 (runtime CRL reload).

This document is the implementation contract for a Haiku-class coder. Every non-obvious decision
is settled here. Do not invent behavior that is not written down; if something is missing, stop
and ask the architect.

ASCII only in all code and docs (AGENTS.md): no em-dash, no unicode arrows, use `-` and `->`.

The three features are INDEPENDENT. Any subset can ship, in any order, without the others (same
pattern as PR5's F010a/b/c). Sections 3, 4 and 5 are self-contained: a challenger or coder can
review or implement one without reading the other two. Sections 1 and 2 apply to all three and
should be read first.

PR7 builds on merged PR1-PR6. It reuses those conventions verbatim: all new logic in new files;
existing files get call sites only; fail closed; deny-by-default; no hand-rolled crypto.

--------------------------------------------------------------------------------
## 0. Scope and per-feature recommendation (read this first)

| Feature | Piece | Effort | Recommendation | One-line reason |
|---|---|---|---|---|
| F014 | /cors-proxy SSRF allowlist | M | DO-NOW if `--ui-mcp-proxy` is ever enabled; NO-OP otherwise | The route is already `PERM_PROXY`-gated, but an authorized caller can reach 169.254.169.254 and every loopback service on the box. This is the single largest remaining hole in the fork. |
| F015 | Prometheus auth metrics | S-M | DO-NOW | Purely additive, small, and it is the only way to see brute-force / misconfigured-role_map patterns without shipping the audit log off-box. |
| F016 | Runtime CRL reload | M | DO-NOW only if you run mTLS with a real CRL distribution point; otherwise DEFER in favour of short-lived certs | Closes F010a's OQ-A2. The OpenSSL mechanics are the hard part, not the reload loop. |

Effort: S = <1 day, M = 1-3 days incl. tests.

--------------------------------------------------------------------------------
## 1. Verified anchors

Every anchor below was re-read on the working tree at design time. The line numbers in the
features.json F014/F015/F016 descriptions and in PLAN.md are stale and were NOT trusted.

| What | File:line (verified) | Note |
|---|---|---|
| `/cors-proxy` route registration | `tools/server/server.cpp:330-337` | Registered only when `params.ui_mcp_proxy`; otherwise a 403 stub is registered for both methods. |
| `/tools` route registration | `tools/server/server.cpp:346-364` | Registered only when `--server-tools` or MCP servers are configured; otherwise a 403 stub. |
| Actual `/cors-proxy` outbound code | `tools/server/server-cors-proxy.h:22-75` (`proxy_request`) | Header-only static helper. Parses `?url=`, builds a `server_http_proxy`. THIS is the SSRF enforcement point, not `server.cpp`. |
| Outbound HTTP client construction | `tools/server/server-models.cpp:2036-2199` (`server_http_proxy::server_http_proxy`) | `httplib::ClientImpl(host, port)` at :2050, replaced by `httplib::SSLClient` at :2055 for https. `set_follow_location(true)` at :2062. Blocks for the response headers at :2185-2198, so `status`/`content_type` are valid when the ctor returns. |
| `server_http_proxy` is SHARED with router mode | `tools/server/server-models.cpp:1192` and `:1826`, both with `CHILD_ADDR` = `"127.0.0.1"` (`server-models.cpp:49`) | CRITICAL: an SSRF check placed inside `server_http_proxy` would break every router-mode request. The check MUST live in `server-cors-proxy.h`. |
| httplib pin-to-IP support | `vendor/cpp-httplib/httplib.h:2341` (`ClientImpl::set_hostname_addr_map`), consumed at `httplib.cpp:8911-8920`, numeric resolve at `httplib.cpp:2174-2178` (`AI_NUMERICHOST`) | With an addr_map entry, httplib connects to the supplied literal IP and does NOT re-resolve; `host_` still drives the Host header, SNI and certificate verification. This is the TOCTOU fix. |
| httplib redirect handling | `vendor/cpp-httplib/httplib.cpp:9580-9627` (`ClientImpl::redirect`), `:9630-9710` (`create_redirect_client`, `setup_redirect_client`) | A cross-host redirect builds a FRESH client and `setup_redirect_client` does NOT copy `addr_map_`. With `set_follow_location(true)` the pin is bypassable by a 302. |
| `PERM_PROXY` route table entries | `tools/server/server-auth.cpp:253-257` | `/cors-proxy` and `/tools`, GET+POST. Unchanged by PR7. |
| `/metrics` route registration | `tools/server/server.cpp:242` | `ctx_http.get("/metrics", ex_wrapper(routes.get_metrics))`. In router mode `routes.get_metrics` was already reassigned to `models_routes->proxy_get` at `server.cpp:205`, i.e. line 242 wraps whichever handler is live. |
| Existing Prometheus text generation | `tools/server/server-context.cpp:4399-4502` (`get_metrics`) | Builds a `json` metric definition then a `std::stringstream`; emits `llamacpp:<name>` with NO label support. Gated on `params.endpoint_metrics` (`--metrics`), else 501-style error. |
| `server-context` static lib boundary | `tools/server/CMakeLists.txt:5-26` vs `:38-54`; `tests/CMakeLists.txt:163` | `server-context.cpp` is in the `server-context` lib, which does NOT contain `server-auth.cpp` and is linked standalone by `test-chat`. F013's S3 finding still holds: `server-context.cpp` must contain ZERO `server_auth::` references. |
| Audit emit call sites | `tools/server/server-auth.cpp:1315, 1340, 1353, 1371, 1378, 1389` | Six sites inside `authorize_request` (`:1302-1391`). F015 counters go beside these and nowhere else. |
| `audit_emit` definition | `tools/server/server-auth.cpp:449-483` | Already applies the no-secrets rule (salted subject hash, no headers, no token). |
| Principal resolution branches | `tools/server/server-auth.cpp:1150-1300` (`resolve_principal`) | mTLS -> trusted-proxy -> OIDC JWT -> API key -> introspection -> anonymous. The failure reason is known here and lost by the time `authorize_request` sees `authenticated == false`. |
| JWKS refresh | `tools/server/server-oidc.cpp:250-280` (`refresh_jwks`) | One success return (`:275`) and two failure returns (`:257`, `:278`). |
| OIDC short error strings | `tools/server/server-oidc.cpp:823, 833, 839, 846, 850, 857, 882, 899, 906, 913, 920, 933, 1124` | Bounded set, already documented as "for audit/metrics" in `server-oidc.h:9-17`. |
| F010a CRL load | `tools/server/server-mtls.cpp:92-150` (`load_crl_file`) | `SSL_CTX_get_cert_store` -> `PEM_read_bio_X509_CRL` loop -> R1 nextUpdate checks -> `X509_STORE_add_crl` -> `X509_STORE_set_flags(CRL_CHECK|CRL_CHECK_ALL)`; requires count >= 1. |
| F010a hardening entry point | `tools/server/server-mtls.cpp:153-194` (`harden_context`), called from `tools/server/server-http.cpp:154` | The CRL block is at `server-mtls.cpp:179-184`, inside `if (cfg.enabled)`. |
| `server_http_context::stop()` | `tools/server/server-http.cpp:515-519` | The single place both the router and non-router shutdown paths converge on for HTTP teardown. |
| mTLS config struct | `tools/server/server-mtls.h:8-17` (`server_mtls_config`) | Gains one field in F016. |
| Existing CIDR parsing pattern | `tools/server/server-auth.cpp:44-49` (`struct cidr`), `:310-325` (`prefix_match`), `:296-308` (`strip_v4mapped_prefix`), `:579-646` (`--auth-trusted-proxies` parse loop) | All file-static inside `server-auth.cpp`. Not currently reusable from another translation unit. |
| Flag registration pattern | `common/arg.cpp:3455-3551` | `add_opt(common_arg({...}, "META", "help", lambda).set_examples({LLAMA_EXAMPLE_SERVER}).set_env("LLAMA_ARG_..."))`. |
| Params block | `common/common.h:645-670` | Auth/mTLS/OIDC fields live together, each tagged with its feature id. |
| Test harness flag threading | `tools/server/tests/utils.py:102-134` (fields), `:282-299` (arg emission), `:154`/`:348-349` (`ui_mcp_proxy`) | Every new server flag needs a field and an emission line. |
| YAML config bridge | `common/config.h:14-18` (`common_config_to_args`) | Generic: it looks up `--<key>` in the registered arg table. NEW FLAGS ARE AUTOMATICALLY USABLE IN YAML with no `common/config.cpp` change. |
| Existing proxy tests | `tools/server/tests/unit/test_proxy.py:13-41`, `tools/server/tests/unit/test_security.py:175-214` | THREE existing tests proxy to a target that F014 would block by default. See section 3.8. |

--------------------------------------------------------------------------------
## 2. Contradictions between PLAN.md / the feature descriptions and the current code

These are flagged rather than silently designed around, per the architect brief.

| Claim | Reality (verified) | Resolution |
|---|---|---|
| PLAN.md 8.1 and the F014 description: "`/cors-proxy` **and `/tools`** are ready-made SSRF". | `/tools` makes NO client-controlled outbound HTTP request. The built-in tools are `read_file`, `file_glob_search`, `grep_search`, `exec_shell_command`, `write_file`, `edit_file`, `get_datetime` (`server-tools.cpp:268-1031`). MCP tools run over a **stdio subprocess** transport (`server-mcp.h:94-125`, `server-mcp.cpp:462-655`), with the command/args supplied by the OPERATOR's config file, never by the request. `grep -n "httplib::Client" tools/server/server-tools.cpp tools/server/server-mcp.cpp` returns nothing. | **F014 is scoped to `/cors-proxy` only.** `/tools` gets NO SSRF change. See section 3.9 for the separate, larger `/tools` risk that this leaves open and that the orchestrator should file as its own feature. |
| The F014 description: "the actual outbound-request code likely lives in a dedicated proxy source file". | It lives in a header-only helper, `tools/server/server-cors-proxy.h`, and the HTTP client itself is constructed in `server-models.cpp`'s `server_http_proxy` ctor, which is **shared with router-mode child forwarding to 127.0.0.1**. | The guard goes in `server-cors-proxy.h`. `server_http_proxy` gains an OPTIONAL, defaulted options struct so router-mode call sites are byte-identical. See section 3.5. |
| The F015 description: metric names `llamacpp_auth_failures_total`. | The existing exposition uses a COLON: `llamacpp:prompt_tokens_total` (`server-context.cpp:4491-4493`). A colon in an exported metric name is reserved for recording rules and is a long-standing upstream non-conformance. | Use the UNDERSCORE form (`llamacpp_auth_failures_total`). Deliberately inconsistent with the neighbouring `llamacpp:` names; propagating a known-wrong convention into new metrics is worse. Flagged as OQ-B1. |
| The F015 description: "counters live alongside `g_audit_*` globals in server-auth.cpp ... wire into the existing /metrics handler". | The existing `/metrics` handler is `server-context.cpp:4399`, inside the `server-context` static lib, which does not link `server-auth.cpp` and is linked standalone by `test-chat` (`tests/CMakeLists.txt:163`). A `server_auth::` call from `server-context.cpp` breaks the `test-chat` link. This is exactly F013's S3 constraint. | The counters live in `server-auth.cpp` as specified, but they are appended to the `/metrics` body by a **response wrapper** registered at `server.cpp:242`, defined in a new header-only file `tools/server/server-metrics.h`. `server-context.cpp` is NOT modified. See section 4.4. |
| The F015 description: `llamacpp_auth_failures_total` labelled with reason `unmapped_role`. | An unmapped role produces `authenticated == true, perms == 0` and a **403**, not a 401. Counting it as an authentication failure double-counts it against `llamacpp_auth_authz_denied_total`. | `unmapped_role` becomes a `reason` label on the **authz** counter, not the authn counter. The two counter families are made disjoint by HTTP status. See section 4.2 and OQ-B2. |
| The F016 task framing: "SIGHUP ... requires no extra thread". | False. A signal handler may not call `malloc`, `fopen`, `BIO_new_file`, `PEM_read_bio_X509_CRL`, or lock a `std::mutex`. Any correct SIGHUP implementation sets a `sig_atomic_t` flag and needs some other thread to service it. | Since a worker thread is unavoidable either way, the trigger choice is decided on other grounds. **Recommendation: periodic re-stat-and-reload poll.** Full justification in section 5.2. |
| The F016 task framing: "atomically swapping a pointer the SSL_CTX consults". | OpenSSL gives NO such guarantee. `SSL_CTX_set_cert_store` frees the old store and does a plain non-atomic pointer write; an in-flight `X509_STORE_CTX` holds a raw, non-up-reffed pointer to the old store (set by `X509_STORE_CTX_init`), so freeing it is a use-after-free. `SSL_CTX` setters are documented as "call before creating SSL objects". | Do NOT swap the store. Install a `X509_STORE_set_lookup_crls` callback ONCE at startup and swap only OUR OWN snapshot, under our own mutex. Rationale and the two rejected alternatives are in section 5.3. |
| `--mtls-crl-file` help text (`common/arg.cpp:3545`): "A CRL is loaded once at startup; rotating the CRL requires restarting the server." | Correct today. | F016 must update this sentence. It is an acceptance criterion, not an optional nicety - a stale help text was the exact defect the F010a reviewer had to fix by hand. |

--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
# 3. F014 - /cors-proxy SSRF hardening

security_sensitive: true. depends_on: F002, F003.

## 3.1 Threat and scope

`PERM_PROXY` (F002/F003) answers WHO may call `/cors-proxy`. Nothing answers WHERE they may
proxy to. Today an authorized caller can issue:

```
GET /cors-proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
GET /cors-proxy?url=http://127.0.0.1:6379/
GET /cors-proxy?url=http://10.0.0.5:8500/v1/kv/?recurse
```

and the server performs the request from inside the trust boundary and relays the body back.
Cloud instance credentials, unauthenticated sidecars, and internal service discovery are all
reachable. The caller can also inject arbitrary request headers via the
`x-llama-server-proxy-header-*` prefix (`server-cors-proxy.h:45-58`), so this is a full
server-side request forgery primitive, not a read-only fetch.

IN SCOPE: `GET`/`POST /cors-proxy`.
OUT OF SCOPE: `/tools` (see section 2 and section 3.9), router-mode child forwarding, the OIDC
JWKS/introspection clients (those target operator-configured, https-pinned URLs, not
request-supplied ones).

## 3.2 Default-policy decision (the question the brief asks to answer)

**Recommendation: allowlist-required, i.e. deny-by-default. With `/cors-proxy` enabled and
`--proxy-allowed-hosts` unset, EVERY proxy request is denied with 403.** The private-address
block is retained as a SECOND filter layered on top of the allowlist, not as the primary
control.

Reasoning:

1. "Block private by default" is an ALLOW-by-default policy for the entire public internet. It
   does not stop exfiltration to an attacker-controlled public endpoint, and it does not stop a
   public host that 302-redirects inward. It mitigates one SSRF target class and leaves the
   primitive intact. The fork's hard rules are "deny by default" and "never a default role";
   a default of "any public host" is the network-layer analogue of a default role.
2. The blast radius of the strict default is bounded and visible. `/cors-proxy` is opt-in
   (`--ui-mcp-proxy`), already labelled EXPERIMENTAL in `server.cpp:324`, already printed in the
   "do not expose the server to untrusted environments" warning block (`server.cpp:371-379`),
   and in this fork it is already `PERM_PROXY`-gated. Anyone reaching it has consciously turned
   on three things.
3. Recovery is one flag with an error message that names it. The common local-MCP case is
   restored by `--proxy-allowed-hosts 127.0.0.1/32`; a remote MCP server by
   `--proxy-allowed-hosts mcp.corp.example`.
4. It is honest about the residual risk. Block-private-by-default reads as "SSRF is fixed" while
   leaving redirect-based and public-target SSRF live. The allowlist makes the operator state the
   reachable set, which is the only statement that actually bounds the primitive.

Accepted cost: this is a BREAKING change for existing `--ui-mcp-proxy` users, including three
tests in this repo (section 3.8). That cost is stated up front, not discovered later.

The private-address block is kept because an allowlist ENTRY can still be a hostname whose DNS
answer moves inward (`mcp.corp.example` repointed at 127.0.0.1). Layering is defined in 3.4.

## 3.3 Files

| File | Kind | Change |
|---|---|---|
| `tools/server/server-ssrf.h` | NEW | Types + the `server_ssrf` interface. No httplib, no OpenSSL types. |
| `tools/server/server-ssrf.cpp` | NEW | Allowlist parsing, blocked-range table, DNS resolution, decision. All logic. |
| `tools/server/server-cors-proxy.h` | modified | ~12 lines: one guard block in `proxy_request`, and pass the pin + no-redirect options to `server_http_proxy`. |
| `tools/server/server-models.h` | modified | +1 struct (`server_http_proxy_opts`), +1 defaulted ctor parameter. |
| `tools/server/server-models.cpp` | modified | 3 lines inside the `server_http_proxy` ctor. No change at the two router call sites. |
| `tools/server/server.cpp` | modified | 1 call site: `server_ssrf::configure(params)` next to `server_auth::init`. |
| `tools/server/CMakeLists.txt` | modified | `server-ssrf.cpp` / `server-ssrf.h` added to `llama-server-impl`. |
| `common/common.h` | modified | +1 field. |
| `common/arg.cpp` | modified | +1 flag. |
| `tools/server/tests/utils.py` | modified | +1 field, +1 emission line. |
| `tools/server/tests/unit/test_proxy.py` | modified | Update 3 existing tests, add the new negative cases. |

`common/config.cpp` is NOT modified: the YAML bridge resolves flags generically
(`common/config.h:14-18`), so `proxy_allowed_hosts: "127.0.0.1/32"` works for free.

## 3.4 Interface and decision procedure (binding)

```cpp
// tools/server/server-ssrf.h
#pragma once

#include <string>

struct common_params;

// A proxy target that passed every check. `pinned_ip` is the numeric address the connection
// MUST use; re-resolving `host` at connect time would reopen the DNS-rebinding window.
struct server_ssrf_target {
    std::string host;       // hostname or IP literal exactly as parsed from the URL
    int         port = 0;
    std::string pinned_ip;  // numeric IPv4 or IPv6 literal (no brackets)
};

struct server_ssrf {
    // Parse --proxy-allowed-hosts into the allowlist. Returns false (and logs SRV_ERR) on any
    // malformed entry; the caller MUST abort startup. Safe to call once, before any request.
    // Never throws.
    static bool configure(const common_params & params);

    // True iff at least one allowlist entry was configured.
    static bool enabled();

    // Decide whether `host`:`port` may be proxied to, and if so which IP to pin.
    // Returns true and fills `out` on allow. Returns false on deny and writes a SHORT,
    // non-sensitive diagnostic into `out_log_reason` for the SERVER LOG ONLY - it is never
    // returned to the client (see 3.6). Never throws.
    static bool check_target(const std::string & host,
                             int port,
                             server_ssrf_target & out,
                             std::string & out_log_reason);
};
```

`check_target` evaluates the following steps IN ORDER. The first failing step denies.

- **S1 - allowlist non-empty.** `enabled() == false` -> deny, reason `"no allowlist configured"`.
- **S2 - port sanity.** `port < 1 || port > 65535` -> deny, reason `"bad port"`.
- **S3 - hostname sanity.** After ASCII-lowercasing and stripping at most one trailing `.`:
  reject if empty, longer than 253 bytes, or containing any byte outside
  `[0-9a-z.:%_-]` plus `A-F`/`a-f` hex for IPv6 literals. Concretely: reject any byte with the
  high bit set (no IDNA/punycode handling - fail closed), any control byte, whitespace, `/`,
  `@`, `\`, `?`, `#`, `[`, `]`. Reason `"bad hostname"`.
- **S4 - resolve.** `getaddrinfo(host, nullptr, {ai_family=AF_UNSPEC, ai_socktype=SOCK_STREAM}, &res)`.
  Zero results or a non-zero return -> deny, reason `"resolve failed"`. Collect at most the
  first 32 results. IPv4-mapped IPv6 results (`::ffff:a.b.c.d`) are UNWRAPPED to their IPv4 form
  before any check, so `::ffff:127.0.0.1` is evaluated as `127.0.0.1`.
- **S5 - every resolved address must be permitted.** For EACH collected address `A`:
  - `A` is permitted if it falls inside at least one CIDR/IP-literal entry of the allowlist; OR
  - `A` is permitted if the request hostname exactly matched a hostname entry of the allowlist
    AND `A` is not inside the blocked-range table (3.7).
  - If any single `A` is not permitted -> deny the whole request, reason
    `"address not permitted"`. Not "any address passes" - a mixed A/AAAA answer must not let a
    caller gamble on ordering.
- **S6 - pin.** `out.pinned_ip` = the textual form of the FIRST collected address.
  `out.host` = the ORIGINAL (pre-lowercase) host string, so SNI/Host/cert verification are
  unchanged. `out.port` = `port`.

Allowlist entry kinds, decided at `configure()` time, no runtime ambiguity:

- If the text before an optional `/bits` parses with `inet_pton(AF_INET, ...)` or
  `inet_pton(AF_INET6, ...)`, it is a **CIDR entry**. Missing `/bits` defaults to `/32` (v4) or
  `/128` (v6). `/0` is REJECTED at configure time (fail closed, mirrors the
  `--auth-trusted-proxies` all-peers footgun rejection at `server-auth.cpp:603-608`). `bits`
  greater than the family width is rejected.
- Otherwise it is a **hostname entry**: matched by exact, ASCII-case-insensitive equality after
  stripping one trailing dot. NO wildcards, NO suffix matching. A hostname entry that itself
  parses as neither and contains a byte failing the S3 charset is rejected at configure time.

Consequence, stated so it is not a surprise: a hostname entry can only reach PUBLIC addresses.
Reaching a private address requires the operator to spell out the CIDR. `--proxy-allowed-hosts
localhost` therefore does NOT work; `--proxy-allowed-hosts 127.0.0.1/32` does.

## 3.5 Pin-through and redirect suppression (binding)

Validating the IP and then letting httplib re-resolve at connect time is the classic TOCTOU and
would make S4-S6 decorative. Two changes carry the decision into the socket.

`tools/server/server-models.h`, immediately above `struct server_http_proxy`:

```cpp
// Optional per-proxy overrides. Defaulted so the router call sites (server-models.cpp:1192,
// :1826) are unchanged. Used by /cors-proxy (F014) to connect only to the IP the SSRF guard
// validated and to refuse redirects.
struct server_http_proxy_opts {
    std::string pinned_ip;             // "" = resolve `host` normally
    bool        follow_location = true;
};
```

and the ctor gains a trailing `const server_http_proxy_opts & opts = {}`.

`tools/server/server-models.cpp`, inside the ctor, AFTER the `cli.reset(new httplib::SSLClient(...))`
block (i.e. replacing the current unconditional `cli->set_follow_location(true);` at :2062):

```cpp
cli->set_follow_location(opts.follow_location);
if (!opts.pinned_ip.empty()) {
    // connect to the address the caller already validated; httplib resolves an addr_map
    // entry with AI_NUMERICHOST and keeps host_ for Host/SNI/cert verification
    cli->set_hostname_addr_map({{host, opts.pinned_ip}});
}
```

Why `follow_location = false` for `/cors-proxy`: `ClientImpl::redirect` (`httplib.cpp:9580`)
sends a cross-host redirect to `create_redirect_client`, which builds a fresh client and calls
`setup_redirect_client` (`:9701`) - and that function does not copy `addr_map_`. A 302 from an
allowlisted public host to `http://169.254.169.254/` would therefore be followed, unvalidated,
to the pinned-around address. Re-validating each hop is the alternative; it is more code, more
state, and more to get wrong. Refusing redirects is the fail-closed choice and the WebUI's MCP
use case does not need them. The relayed 3xx status and `Location` header still reach the
client, so a caller that genuinely needs the hop can re-issue it through the guard.

`tools/server/server-cors-proxy.h`, in `proxy_request`, immediately AFTER the existing scheme
check (currently lines 38-40) and BEFORE the `SRV_INF` at line 42:

```cpp
server_ssrf_target tgt;
std::string ssrf_reason;
if (!server_ssrf::check_target(parsed_url.host, parsed_url.port, tgt, ssrf_reason)) {
    SRV_WRN("cors-proxy: target denied (%s)\n", ssrf_reason.c_str());
    auto res = std::make_unique<server_http_res>();
    res->status = 403;
    res->data = safe_json_to_str({
        {"error", {
            {"message", "proxy target not allowed"},
            {"type", "proxy_target_denied"},
        }}
    });
    return res;
}
```

and the `server_http_proxy` construction passes `tgt.host`, `tgt.port` and a trailing
`server_http_proxy_opts{tgt.pinned_ip, false}`.

`proxy_request` returns a 403 response object rather than throwing: `ex_wrapper`
(`server.cpp:55-87`) maps `std::invalid_argument` to 400 and everything else to 500, so there is
no exception type that yields 403.

## 3.6 Error-response policy

The client-visible body is ALWAYS the same for every denial: `403` with
`{"error":{"message":"proxy target not allowed","type":"proxy_target_denied"}}`.

It must NOT distinguish "not in the allowlist" from "resolved to a blocked range" from "DNS
resolution failed". Distinguishing them turns `/cors-proxy` into an internal-network scanner and
a DNS-existence oracle for an authenticated-but-untrusted caller - which is most of the SSRF
value back again. The distinguishing detail goes to `SRV_WRN` in the server log only.

The log line contains the short reason and, at most, the requested host and port. It never
contains a resolved internal IP (that would put scan results in the log for anyone who can read
it) - the resolved address is deliberately omitted from the log message.

## 3.7 Blocked-range table (binding)

Compiled-in, file-static in `server-ssrf.cpp`. Applies to S5's hostname-entry branch only.

IPv4:

| CIDR | Why |
|---|---|
| `0.0.0.0/8` | "this network" / unspecified |
| `10.0.0.0/8` | RFC1918 |
| `100.64.0.0/10` | CGNAT (RFC6598) |
| `127.0.0.0/8` | loopback |
| `169.254.0.0/16` | link-local; includes the cloud metadata endpoint 169.254.169.254 |
| `172.16.0.0/12` | RFC1918 |
| `192.0.0.0/24` | IETF protocol assignments |
| `192.0.2.0/24` | TEST-NET-1 |
| `192.168.0.0/16` | RFC1918 |
| `198.18.0.0/15` | benchmarking |
| `198.51.100.0/24` | TEST-NET-2 |
| `203.0.113.0/24` | TEST-NET-3 |
| `224.0.0.0/4` | multicast |
| `240.0.0.0/4` | reserved, includes 255.255.255.255 |

IPv6:

| CIDR | Why |
|---|---|
| `::/128` | unspecified |
| `::1/128` | loopback |
| `64:ff9b::/96` | NAT64 (would translate to an arbitrary v4 target) |
| `100::/64` | discard-only |
| `2001:db8::/32` | documentation |
| `fc00::/7` | unique-local |
| `fe80::/10` | link-local |
| `ff00::/8` | multicast |

`::ffff:0:0/96` is absent on purpose: v4-mapped addresses are unwrapped in S4 and evaluated
against the IPv4 table, so a mapped `::ffff:169.254.169.254` is caught by `169.254.0.0/16`
rather than by a blanket mapped-range block that would also hide the reason.

The CIDR matcher is a local copy of the `prefix_match` shape at `server-auth.cpp:310-325`, not a
shared helper. `server-auth.cpp`'s version is file-static and its parse loop is wired to
`--auth-trusted-proxies`-specific error strings; exporting it would put networking types into
`server-auth.h`, which currently has none. This is an ACCEPTED ~40-line duplication, called out
here so the reviewer does not flag it as accidental. See OQ-A4.

## 3.8 Existing tests that this breaks (must be updated, not deleted)

| Test | Target | Fix |
|---|---|---|
| `test_proxy.py::test_mcp_proxy` | `http://example.com` | Add `server.proxy_allowed_hosts = "example.com"`. |
| `test_proxy.py::test_mcp_proxy_custom_port` | `http://<server_host>:<server_port>/models` (loopback) | Add `server.proxy_allowed_hosts = "127.0.0.1/32"`. |
| `test_security.py` header-forwarding test (`:175-214`) | `http://127.0.0.1:<port>/capture` | Add `server.proxy_allowed_hosts = "127.0.0.1/32"`. |
| `test_proxy.py::test_mcp_no_proxy` | n/a (`--ui-mcp-proxy` off) | Unchanged; still 403 from the disabled-feature stub. |

That three of four existing proxy tests aim at a private address is itself evidence for how
routine the private-target use case is, and is the honest counterweight to 3.2. It does not
change the recommendation: the tests declare their intent with one flag, which is exactly what
an operator should have to do.

## 3.9 Deliberately NOT fixed here

`/tools` shares `PERM_PROXY` with `/cors-proxy` (`server-auth.cpp:253-257`) but its risk is not
SSRF - it is local file read (`read_file`, `grep_search`, `file_glob_search`), local file WRITE
(`write_file`, `edit_file`), and arbitrary command execution (`exec_shell_command`,
`server-tools.cpp:581`). A caller holding `PERM_PROXY` today gets shell on the server host when
`--server-tools` includes it. That is a strictly larger problem than SSRF and it needs its own
design (at minimum: a separate permission bit, since bundling RCE with "may fetch a URL" is a
permission-model error). It is OUT OF SCOPE for F014 and should be filed as its own feature.
Flagged as OQ-A5.

## 3.10 Open questions for the challenger (F014)

- **OQ-A1.** Is deny-by-default (3.2) the right call, or does the operational breakage argue for
  block-private-by-default with an opt-in strict mode? Attack the claim that
  "block-private-by-default leaves the primitive intact" - is exfiltration-to-public-host really
  in the threat model for a caller who already holds `PERM_PROXY`?
- **OQ-A2.** Redirect suppression (3.5): is refusing all redirects too blunt? Would per-hop
  re-validation via a `set_follow_location(false)` + manual loop be worth the extra state, given
  that MCP-over-HTTP servers sometimes redirect `/mcp` to `/mcp/`?
- **OQ-A3.** S5 requires ALL resolved addresses to pass while S6 pins only the first. Is
  "all must pass" the right strictness, or does it create a denial-of-service where one bad AAAA
  record in a legitimate host's DNS blocks the whole target? Consider the alternative: filter to
  the permitted subset and pin the first survivor.
- **OQ-A4.** The ~40-line CIDR-parser duplication (3.7). Accept, or export a shared helper from
  `server-auth.h` and take the networking-types-in-the-header cost?
- **OQ-A5.** `/tools` under `PERM_PROXY` grants `exec_shell_command` (3.9). Confirm this is a
  separate feature and not something F014 must at least warn about at startup.
- **OQ-A6.** `getaddrinfo` blocks with no timeout, on an httplib worker thread. Today's code
  already resolves at connect time so this is not a NEW DoS, but F014 moves the resolution
  earlier and adds a second one at connect (the numeric one, which is cheap). Is a
  hostile-DNS hold-open worth bounding here, or is that the reverse proxy's job?
- **OQ-A7.** The guard runs per request, so a long-lived proxy connection is validated once.
  Since redirects are refused and the IP is pinned, is there any remaining path by which a
  single accepted connection reaches a second address?

--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
# 4. F015 - Prometheus auth metrics

security_sensitive: false (no auth-decision logic changes). depends_on: F006.

## 4.1 Goal and constraints

Expose auth failure/denial counts through the EXISTING `/metrics` endpoint. Hard constraints:

- No parallel metrics system, no new route, no new dependency.
- Counters increment ONLY at the six `audit_emit` call sites in
  `server_auth::authorize_request` (`server-auth.cpp:1315, 1340, 1353, 1371, 1378, 1389`) plus
  the JWKS refresh sites. No authz logic is duplicated or moved.
- Every label value comes from a COMPILE-TIME table of string literals. No label value is ever
  derived from a request path, subject, key, token, DN, header, or peer address. Cardinality is
  bounded by construction, not by convention.
- `server-context.cpp` gains ZERO `server_auth::` references (static-lib boundary, section 2).

## 4.2 Metric families (binding)

Three families. They are DISJOINT, partitioned by the HTTP status of the decision, so no event
increments two of them.

### `llamacpp_auth_failures_total` - authentication failures (status 400 and 401)

Labels: `auth_method`, `reason`.

`auth_method` is the existing `auth_method_to_string()` output (`server-auth.cpp:397-405`):
`none`, `api_key`, `trusted_proxy`, `mtls`, `oidc`.

`reason` is a fixed enum:

| `reason` | Set when |
|---|---|
| `malformed_path` | `normalize_path` returned `NORM_REJECT` (status 400, site `:1315`). `auth_method` is always `none` here. |
| `no_credential` | No `Authorization` and no `X-Api-Key` header was presented. |
| `invalid_key` | An API key was presented and did not match any configured key, with no default role. |
| `malformed` | A JWT-shaped token failed structurally: parse, missing `alg`/`kid`, disallowed `alg`, unknown `kid`, `typ` mismatch, missing `sub`, missing `exp`, signature verification failure. |
| `expired` | A JWT failed specifically on `exp`/`nbf` outside the clock skew. |
| `aud_mismatch` | A JWT failed `aud` or `iss` matching. |
| `introspect_denied` | RFC-7662 introspection returned `active:false`, or the introspection call itself failed. |
| `mtls_reject` | A client cert was presented but yielded no usable SAN identity (empty or ambiguous per F008c's C1 rule). |

Nine values x five methods = 45 possible series, all compile-time.

### `llamacpp_auth_authz_denied_total` - authorization denials (status 403)

Labels: `auth_method`, `required_perm`, `reason`.

`required_perm` is the existing `perm_to_string()` output (`server-auth.cpp:383-395`):
`PUBLIC`, `INFER`, `READ_STATE`, `METRICS`, `ADMIN_STATE`, `ADMIN_MODELS`, `PROXY`.

`reason` is two values:

| `reason` | Set when |
|---|---|
| `unmapped_role` | `principal.perms == 0` - the caller authenticated but no role mapped. Almost always a `role_map` misconfiguration, which is why it is worth separating. |
| `insufficient_perm` | `principal.perms != 0` but does not include `need`. A genuine, correctly-configured denial. |

Five methods x seven perms x two reasons = 70 possible series, all compile-time.

### `llamacpp_auth_jwks_refresh_total` - JWKS refresh outcomes

Label: `result` in {`success`, `failure`}. Exactly two series.

Increment sites, all in `server-oidc.cpp`'s `refresh_jwks` (`:250-280`): `success` on the
`return true` at `:275`; `failure` on the `return false` at `:257` (fetch failed) and at `:278`
(parse exception).

No other metric families in F015. Introspection call outcomes, token-cache hit rates, and
per-route request counts are explicitly out of scope.

## 4.3 Storage and increment sites (binding)

In `server-auth.cpp`'s anonymous namespace, beside the existing `g_audit_*` state
(`server-auth.cpp:61-66`):

```cpp
// F015: fixed-shape counters. Indexed by enum, never by a string key, so label cardinality is
// a compile-time property. Relaxed ordering: these are monotonic observability counters, never
// read to make a decision.
std::atomic<uint64_t> g_authn_fail[AUTH_METHOD_COUNT][AUTH_FAIL_COUNT];
std::atomic<uint64_t> g_authz_deny[AUTH_METHOD_COUNT][PERM_INDEX_COUNT][AUTHZ_DENY_COUNT];
```

`server-auth.h` gains the enums (`server_auth_fail_reason`, `server_authz_deny_reason`, and the
`AUTH_METHOD_COUNT` / `PERM_INDEX_COUNT` bounds) plus:

```cpp
// F015: Prometheus text for the auth counters, appended to the /metrics body by
// server_metrics_wrap (server-metrics.h). Returns "" when auth is disabled, so /metrics output
// is byte-identical to pre-F015 in that mode. Never throws.
static std::string metrics_prometheus();
```

`server-oidc.h` gains:

```cpp
// F015: JWKS refresh counters (success, failure). Zero-filled when OIDC is not configured.
static void jwks_refresh_counts(uint64_t & out_success, uint64_t & out_failure);
```

Carrying the authn reason from `resolve_principal` to the audit site: `resolve_principal`
(`:1150-1300`) knows WHY authentication failed; `authorize_request` only sees
`authenticated == false`. Add a file-static `thread_local server_auth_fail_reason t_fail_reason;`
beside the existing `thread_local server_auth_principal t_principal` (`:59`). It is set on every
failing branch of `resolve_principal` and reset to `AUTH_FAIL_NONE` at the top of
`resolve_principal` (NOT in the middleware - the reset must be adjacent to the writes so a new
branch cannot forget it). `authorize_request` reads it at the 401 site. This mirrors the existing
`t_principal` mechanism exactly; no signature churn, no new DTO field copied into every request.

Increment placement: exactly one `counter_bump(...)` line IMMEDIATELY BEFORE each of the six
`audit_emit` calls, guarded by the same condition that produced the decision. The decision is
already computed at that point; the increment never branches on anything the audit line does not
already branch on, so it adds no timing signal beyond `audit_emit`'s existing one.

| Site | Decision | Action |
|---|---|---|
| `:1315` | 400 NORM_REJECT | `g_authn_fail[none][malformed_path]++` |
| `:1340` | allow (auth disabled) | none |
| `:1353` | 401 or allow (NORM_UNMATCHED) | on 401 only: `g_authn_fail[method][t_fail_reason]++` |
| `:1371` | 401 | `g_authn_fail[method][t_fail_reason]++` |
| `:1378` | allow (unclassified route) | none |
| `:1389` | allow or 403 | on 403 only: `g_authz_deny[method][perm_index(need)][perms==0 ? unmapped_role : insufficient_perm]++` |

`t_fail_reason` defaults to `no_credential` so a branch that forgets to set it reports the least
alarming, least specific value rather than a wrong specific one.

## 4.4 Wiring into `/metrics` (binding)

New header-only file `tools/server/server-metrics.h`, following the `server-cors-proxy.h`
precedent (a header-only handler helper in `tools/server/`, not added to `CMakeLists.txt`):

```cpp
#pragma once

#include "server-auth.h"
#include "server-http.h"

// F015: append the auth counters to whatever the real /metrics handler produced. Registered at
// the single /metrics call site in server.cpp, so it wraps the single-server handler AND the
// router-mode proxy handler with one line.
static server_http_context::handler_t server_metrics_wrap(server_http_context::handler_t inner);
```

Behaviour, in order:

1. `auto res = inner(req);`
2. If `res->status != 200` -> return `res` untouched. (`get_metrics` returns a JSON error when
   `--metrics` is off; a router-mode proxy returns the child's status. Never append to those.)
3. If `res->content_type` does not start with `"text/plain"` -> return `res` untouched. This is
   the same prefix-match guard shape F013 used for `text/event-stream`
   (`server-http.cpp:618-619`) and it is what keeps Prometheus text out of a JSON body.
4. If `server_auth::metrics_prometheus()` is empty -> return `res` untouched.
5. If `!res->is_stream()` -> `res->data += server_auth::metrics_prometheus(); return res;`
6. Otherwise (router mode: `server_http_proxy` always sets `next()`), wrap the pump:

```cpp
auto inner_next = std::move(res->next);
res->next = [inner_next](std::string & out) -> bool {
    const bool has_next = inner_next(out);
    if (!has_next) {
        out += server_auth::metrics_prometheus();  // final chunk, then sink.done()
    }
    return has_next;
};
```

This is safe because `process_handler_response` (`server-http.cpp:634-651`) writes the chunk
BEFORE acting on a `false` return, so appending on the last call delivers the text and then
terminates normally. `server_http_proxy`'s ctor blocks for the response headers
(`server-models.cpp:2185-2198`), so `status` and `content_type` are already correct at step 2/3.

`server.cpp:242` becomes:

```cpp
ctx_http.get ("/metrics",                  ex_wrapper(server_metrics_wrap(routes.get_metrics)));
```

plus one `#include "server-metrics.h"` next to the existing `#include "server-cors-proxy.h"`
(`server.cpp:5`). That is the whole footprint in existing files.

## 4.5 Exposition format (binding)

`metrics_prometheus()` returns `""` when `g_auth_enabled == false`. Otherwise it emits, in this
exact order, with `\n` line endings and no trailing blank line:

```
# HELP llamacpp_auth_failures_total Authentication failures by method and reason.
# TYPE llamacpp_auth_failures_total counter
llamacpp_auth_failures_total{auth_method="api_key",reason="invalid_key"} 3
# HELP llamacpp_auth_authz_denied_total Authorization denials for an authenticated principal.
# TYPE llamacpp_auth_authz_denied_total counter
llamacpp_auth_authz_denied_total{auth_method="oidc",required_perm="ADMIN_STATE",reason="insufficient_perm"} 1
# HELP llamacpp_auth_jwks_refresh_total JWKS refresh attempts by result.
# TYPE llamacpp_auth_jwks_refresh_total counter
llamacpp_auth_jwks_refresh_total{result="success"} 4
llamacpp_auth_jwks_refresh_total{result="failure"} 0
```

Rules:

- The `# HELP` / `# TYPE` pair for each family is emitted whenever the family is emitted at all.
- For the two label-set families, ONLY series with a value > 0 are emitted. Emitting all 115
  zero series on every scrape is a large constant payload for no operational value; a counter
  appearing on first increment is standard for label-set counters.
- `llamacpp_auth_jwks_refresh_total` emits BOTH series unconditionally (including zeros) when
  OIDC is configured, and neither when it is not, so `rate()` on the failure series works from
  the first scrape.
- Label order within a metric is fixed and alphabetical, exactly as shown.
- No label value requires escaping, because every one of them is a literal from the tables in
  4.2. The coder MUST NOT introduce a `std::string` label value from any other source; that is
  the single rule that keeps this feature non-security-sensitive.
- The name prefix is `llamacpp_` with an UNDERSCORE, deliberately unlike the neighbouring
  `llamacpp:` names. See section 2 and OQ-B1.

Note for operators, to be added to the flag/README documentation: these counters are only visible
when `--metrics` is on and the caller holds `PERM_METRICS`.

## 4.6 Open questions for the challenger (F015)

- **OQ-B1.** `llamacpp_auth_*` (underscore) next to `llamacpp:prompt_tokens_total` (colon) in the
  same payload. Correct-but-inconsistent, or should new metrics match the existing broken
  convention for scrape-config uniformity?
- **OQ-B2.** Making the two counter families disjoint by HTTP status (4.2) moves `unmapped_role`
  off the failures counter and onto the denials counter, deviating from the F015 description
  text. Is that the right partition, or do operators actually want "all auth rejections" in one
  series?
- **OQ-B3.** The router-mode append (4.4 step 6) inserts our text into a body proxied from a
  CHILD server. The child also emits `llamacpp:*` metrics, so the scrape mixes router-level auth
  counters with child-level inference counters and no label distinguishes them. Is that
  acceptable, or should router mode omit the append and expose the counters some other way?
- **OQ-B4.** `t_fail_reason` as a `thread_local` (4.3). It mirrors `t_principal`, but it is a
  second piece of implicit per-thread state that a future refactor could desynchronise from the
  principal. Worth the avoided signature churn?
- **OQ-B5.** Is `no_credential` as the default for an unset `t_fail_reason` right, or should an
  unset value be its own `unknown` label so a forgotten branch is VISIBLE rather than blended
  into the most common bucket?
- **OQ-B6.** Emitting only non-zero series (4.5) means a security team cannot distinguish "no
  failures yet" from "the metric was never wired up". Is the payload saving worth that?

--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
# 5. F016 - Runtime CRL reload

security_sensitive: true. depends_on: F010a.

## 5.1 Goal and fail-closed contract

Pick up a rotated `--mtls-crl-file` without restarting the server, with no impact on established
connections, and with no path by which a bad file write silently disables revocation checking.

Fail-closed rules:

- Startup behaviour is UNCHANGED from F010a when reload is off. All of F010a's abort conditions
  (missing file, unparseable, zero CRLs, absent `nextUpdate`, `nextUpdate` in the past, CRL file
  set with mTLS off) still abort startup.
- A reload attempt that fails validation NEVER weakens enforcement: the previous CRL set stays
  active. See 5.4 for the justification.
- A build that cannot support reload (5.5) does not silently ignore the flag; it aborts startup.
- If the active CRL's `nextUpdate` passes with no successful reload, OpenSSL returns
  `X509_V_ERR_CRL_HAS_EXPIRED` and every mTLS handshake fails. That is already the F010a
  behaviour and it is the correct fail-closed outcome; F016 adds loud warnings before it happens
  (5.6) but does not change it.

## 5.2 Trigger mechanism: recommendation and justification

**Recommendation: periodic re-stat-and-reload poll, behind a new
`--mtls-crl-reload-interval SECONDS` flag, default 0 (disabled).**

The brief's premise that SIGHUP "requires no extra thread" is incorrect: a signal handler cannot
open a file, allocate, call into OpenSSL, or take a mutex. Every correct SIGHUP design here is
"handler sets a `sig_atomic_t`, a worker thread does the work". Once the worker thread is
unavoidable, SIGHUP's advantages collapse and its costs remain:

| | Poll (recommended) | SIGHUP | inotify / FS watch |
|---|---|---|---|
| Needs a worker thread | yes | yes (see above) | yes |
| Changes to existing files | 1 line in `server-http.cpp::stop()` | `server.cpp:485-490` sigaction block + the shared `shutdown_handler`/`signal_handler` pair at `:26-38` | 1 line, same as poll |
| Windows | works | no SIGHUP | different API (`ReadDirectoryChangesW`) |
| Works when llama-server is a library entry (`llama_server(params, argc, argv)`) | yes | installing a process-wide signal handler from a library entry point is intrusive | yes |
| Works with an automated CRL distribution cron | yes, nothing to notify | operator/cron must remember to signal | yes |
| Rebase exposure | none | `server.cpp`'s signal setup is upstream code that moves | none |
| Handles atomic-rename and in-place rewrite | yes (retries next tick) | in-place rewrite can be signalled too early | rename vs write events differ per platform, easy to get wrong |

`server.cpp`'s signal path is a single `std::function<void(int)> shutdown_handler` invoked by one
`signal_handler` for both SIGINT and SIGTERM (`server.cpp:26-38, 485-490`), and it is assigned in
two different places for router and non-router mode (`:426`, `:475`). Threading a second,
non-shutdown signal through that is precisely the kind of change to an existing, upstream-owned
file that the fork's rebase rule exists to avoid.

The design keeps the door open: the actual work is `crl_reload_once()`, a plain function. Adding
a SIGHUP trigger later is setting a flag the same thread already checks - a three-line change,
not a redesign.

Interval validation: `0` disables. A value in `1..4` is REJECTED at startup (a hot `stat` loop on
a shared filesystem is a self-inflicted problem); the minimum is 5. Negative is rejected.
Non-zero with an empty `--mtls-crl-file` is rejected. All are `SRV_ERR` + abort.

## 5.3 The OpenSSL mechanism (the load-bearing part)

Three candidate mechanisms were considered. Two are unsafe.

**Rejected - swap the store (`SSL_CTX_set_cert_store`).** The setter frees the old store and
performs a plain, non-atomic pointer write to `ctx->cert_store`. An in-flight handshake reads
that pointer at verify time and `X509_STORE_CTX_init` stores it WITHOUT taking a reference, so
freeing the old store is a use-after-free against any concurrent verification. Keeping the old
store alive with an extra `X509_STORE_up_ref` removes the UAF but leaves a formally-racy pointer
write that OpenSSL explicitly does not support (`SSL_CTX` setters are documented as
"call before any SSL objects are created"). There is no OpenSSL guarantee to lean on here; the
brief's instruction to verify rather than assume resolves AGAINST this approach.

**Rejected - keep adding to the existing store (`X509_STORE_add_crl` on each reload).**
`X509_STORE_add_crl` is lock-protected and therefore safe to call concurrently, but there is no
public API to REMOVE a CRL. Stale CRLs accumulate forever, and OpenSSL's `get_crl_sk` picks the
first CRL that reaches the best score - among two CRLs from the same issuer that are BOTH inside
their validity window, the older one can win. A certificate revoked only by the newer CRL would
then not be caught. That is a fail-OPEN outcome and disqualifies the approach.

**Chosen - replace the CRL lookup, not the store.** `X509_STORE_set_lookup_crls(store, cb)` is
called ONCE at startup, before any connection exists, so the store is never mutated afterwards.
`X509_STORE_CTX_init` copies the store's `lookup_crls` pointer into the per-verification context,
and `get_crl_delta` calls it to obtain candidate CRLs for an issuer name. The callback returns a
FRESH `STACK_OF(X509_CRL)` that the caller owns and frees, so there is no cross-thread lifetime
question at all: it up-refs the CRLs it returns.

```cpp
// server-mtls.cpp, file-scope
struct crl_snapshot {
    STACK_OF(X509_CRL) * crls = nullptr;      // owned; freed with sk_X509_CRL_pop_free
    int64_t earliest_next_update = 0;         // unix seconds, for the expiry warnings in 5.6
    int     count = 0;
    ~crl_snapshot();
};

// Leaked on purpose: the reload thread is DETACHED (5.7) and must not race static destruction
// at process exit. Access via the accessors only.
static std::mutex & crl_mtx();                                  // returns *new std::mutex, once
static std::shared_ptr<const crl_snapshot> crl_get();           // copy under crl_mtx
static void crl_set(std::shared_ptr<const crl_snapshot>);       // swap under crl_mtx
```

The callback:

```cpp
static STACK_OF(X509_CRL) * crl_lookup_cb(const X509_STORE_CTX *, const X509_NAME * nm);
```

- Take a `shared_ptr` copy of the snapshot (lock held only for the pointer copy, never during
  verification).
- Allocate a new `sk_X509_CRL_new_null()`.
- For each CRL in the snapshot with `X509_NAME_cmp(X509_CRL_get_issuer(crl), nm) == 0`:
  `X509_CRL_up_ref(crl)` then `sk_X509_CRL_push`.
- Return the stack. If the snapshot is null or nothing matches, return the EMPTY stack (not
  `nullptr`). OpenSSL then reports `X509_V_ERR_UNABLE_TO_GET_CRL` and the handshake fails -
  fail-closed.
- The function must never throw and never log (it runs inside a TLS handshake).

Const-qualification of the two callback parameters differs between OpenSSL 3.x
(`const X509_STORE_CTX *`, `const X509_NAME *`, confirmed at
`openssl/x509_vfy.h:271-273` on this machine) and OpenSSL 1.1.x (both non-const). This is handled
by the build gate in 5.5 rather than by macro gymnastics.

**Safety net (important).** The startup path KEEPS F010a's `X509_STORE_add_crl` calls exactly as
they are, in addition to installing the callback. If the callback were somehow not consulted -
the one assumption in this design that rests on OpenSSL internals rather than on documented API
contract - the store-resident CRLs still enforce, so the degenerate failure mode is "reload is a
no-op", never "revocation silently stops". The acceptance test in 5.8 proves the callback IS
consulted by revoking a certificate ONLY in the reloaded file.

## 5.4 Bad-reload policy: recommendation and justification

**Recommendation: keep the last-known-good CRL enforced, log `SRV_ERR`, do not abort.**

- A running server that kills itself because a cron job wrote a truncated file is a self-inflicted
  denial of service, and it is trivially triggerable by anyone who can write that file - which is
  a strictly WEAKER attacker than one who can replace it with a valid-but-empty CRL.
- Keeping the old CRL is not fail-open: the old CRL still revokes everything it revoked before.
  The only thing lost is revocations added since. Compared with aborting, the exposure is bounded
  by the reload interval plus operator response time; compared with accepting the bad file, it is
  strictly safer.
- The condition is not silent. Every failed attempt logs `SRV_ERR` with the reason, and the
  operator's own CRL freshness alarm (5.6) fires as `nextUpdate` approaches.
- The genuinely dangerous case - a CRL that is valid but stale - is already handled: F010a's R1
  rules mean a CRL whose `nextUpdate` has passed is rejected at parse time and therefore never
  becomes the active snapshot, and if the ACTIVE snapshot expires, OpenSSL fails every handshake.

The alternative (abort on bad reload) is rejected but explicitly flagged for the challenger as
OQ-C1, because it is a defensible position for a high-assurance deployment where "stop serving"
beats "serve with a slightly stale revocation list".

## 5.5 Build gating

```c
#if defined(CPPHTTPLIB_OPENSSL_SUPPORT) && \
    !defined(OPENSSL_IS_BORINGSSL) && !defined(LIBRESSL_VERSION_NUMBER) && \
    OPENSSL_VERSION_NUMBER >= 0x30000000L
#define SERVER_MTLS_CRL_RELOAD_SUPPORTED 1
#endif
```

The repo can build against BoringSSL or LibreSSL (`vendor/cpp-httplib/CMakeLists.txt:40, 83`),
whose `X509_STORE_CTX_lookup_crls_fn` signatures differ. Rather than guess, the feature compiles
only for OpenSSL 3.0+.

On an unsupported build, `--mtls-crl-reload-interval > 0` produces
`SRV_ERR("--mtls-crl-reload-interval requires an OpenSSL 3.0+ build\n")` and aborts startup. It
is NOT silently ignored - a silently-ignored reload flag is an operator believing revocation is
fresh when it is frozen.

## 5.6 Control flow

`server_mtls_config` (`server-mtls.h:8-17`) gains:

```cpp
int crl_reload_interval = 0;   // F016: seconds between CRL re-stat checks; 0 = no reload
```

`server_mtls::configure` (`server-mtls.cpp:21-87`) gains the three validations from 5.2, placed
next to the existing `--mtls-crl-file`-with-mTLS-off check at `:51-55`.

`load_crl_file` (`:93-149`) is REFACTORED, not rewritten, so validation exists once:

```cpp
// Parse + validate a PEM CRL bundle. Applies F010a's R1 rules (nextUpdate present, not in the
// past) to EVERY CRL and requires count >= 1. Returns nullptr on any failure, having logged
// SRV_ERR. Does not touch any SSL_CTX or X509_STORE.
static std::shared_ptr<const crl_snapshot> crl_parse_file(const std::string & path);

// F010a, unchanged contract: parse via crl_parse_file, X509_STORE_add_crl each entry, then
// X509_STORE_set_flags(CRL_CHECK | CRL_CHECK_ALL). Returns false on any failure.
static bool load_crl_file(SSL_CTX * c, const std::string & crl_file);
```

`harden_context`'s CRL block (`:179-184`) becomes:

1. `load_crl_file(c, cfg.crl_file)` - unchanged, still the abort-on-failure gate.
2. If `cfg.crl_reload_interval > 0`:
   a. `#ifndef SERVER_MTLS_CRL_RELOAD_SUPPORTED` -> `SRV_ERR` + `return false`.
   b. `crl_set(crl_parse_file(cfg.crl_file))` - the initial snapshot. A second parse of a file
      that just parsed; the cost is microseconds at startup and the clarity is worth it.
   c. `X509_STORE_set_lookup_crls(SSL_CTX_get_cert_store(c), crl_lookup_cb)`.
   d. `crl_reload_start(cfg.crl_file, cfg.crl_reload_interval)`.

The reload thread body:

```
loop:
  wait on a condition_variable for `interval` seconds, or until the stop flag is set
  if stop -> return
  st = stat(path)
  if stat failed -> SRV_ERR (rate-limited, see below); continue
  if (st.mtime, st.size) == last_attempted -> goto expiry check
  last_attempted = (st.mtime, st.size)
  snap = crl_parse_file(path)
  if (!snap) -> SRV_ERR("mTLS: CRL reload failed, keeping the previous CRL"); continue
  crl_set(snap); SRV_INF("mTLS: reloaded N CRL(s) from <path>")
expiry check:
  now = time(nullptr); nu = crl_get()->earliest_next_update
  if nu <= now      -> SRV_ERR (at most once per hour) "active CRL has expired; all mTLS handshakes will fail"
  else if nu-now < 86400 -> SRV_WRN (at most once per hour) "active CRL expires in <h> hours"
```

Notes the coder must not deviate from:

- The `(mtime, size)` pair, not mtime alone: a same-second rewrite of a different length is
  caught.
- `last_attempted` is updated on FAILURE too, so a persistently-bad file logs once per distinct
  `(mtime, size)` rather than every tick. The accepted residual: a truncated write later completed
  to the exact same mtime AND size would not be retried. Size equality makes this essentially
  impossible and the operator sees the `SRV_ERR`.
- The expiry check runs every tick regardless of whether the file changed. This is what closes
  F010a's noted "no warning before the CRL expires" gap.
- The thread NEVER touches an `SSL_CTX`, `X509_STORE`, or any httplib object after startup. It
  only parses a file and swaps our own `shared_ptr`. That is what makes its lifetime independent
  of the HTTP server's.

## 5.7 Thread lifetime

The thread is DETACHED and is stopped cooperatively:

```cpp
// server-mtls.h
static void crl_reload_stop();   // idempotent; sets the stop flag and wakes the thread
```

called from `server_http_context::stop()` (`server-http.cpp:515-519`) - one line, and the single
point both the router (`server.cpp:432`) and non-router (`:441`) shutdown paths reach.

`crl_reload_stop()` does NOT join. `stop()` can be reached from `shutdown_handler` on the signal
delivery path (`server.cpp:29-38`), and `pthread_join` is not async-signal-safe. The thread wakes
within milliseconds and exits; it holds only its own copies plus file-scope statics with
intentionally-leaked storage (5.3), so nothing it touches can be destroyed underneath it.

In-flight connections: a reload changes nothing that an established connection consults.
Certificate verification happens once, during the handshake. Only handshakes that start after the
swap see the new CRL set. No socket is closed, no `SSL_CTX` is touched, no session is
invalidated. A handshake in progress across the swap sees either the old or the new snapshot -
both are valid, self-consistent CRL sets.

## 5.8 Test obligations

Extend `tools/server/tests/unit/test_mtls.py`. The load-bearing test is the one that proves the
lookup callback is actually consulted:

1. Start with CRL v1, which revokes NOTHING. Client cert C connects successfully.
2. Write CRL v2, which revokes C, over the same path. Wait `interval + slack`.
3. C's handshake now FAILS. (If the callback were not consulted, C would still succeed, because
   the store still holds only v1.)
4. A different, unrevoked cert D from the same CA still succeeds.
5. Overwrite the file with garbage. Wait `interval + slack`. C is STILL rejected (last-known-good
   held) and D still succeeds, and the server is still running.
6. `--mtls-crl-reload-interval` with no `--mtls-crl-file`, with a value of 1..4, and with a
   negative value each abort startup.

## 5.9 Documentation obligation

`common/arg.cpp:3545` currently reads "A CRL is loaded once at startup; rotating the CRL requires
restarting the server." That sentence must be replaced when F016 lands, and the new
`--mtls-crl-reload-interval` help must state the last-known-good-on-failure policy explicitly.
This is an acceptance criterion: the F010a review found and had to fix exactly this class of
stale help text.

## 5.10 Open questions for the challenger (F016)

- **OQ-C1.** The bad-reload policy (5.4): last-known-good + `SRV_ERR`, versus aborting. Attack
  the DoS argument - is "the CRL file writer can kill the server" actually a meaningful
  escalation over "the CRL file writer can install an empty CRL"?
- **OQ-C2.** Poll over SIGHUP (5.2). The strongest counter-argument is operator expectation:
  every other server in the stack reloads on SIGHUP, and an ops team may simply not look for a
  polling flag. Is the ~15-line `server.cpp` signal change worth buying that convention?
- **OQ-C3.** The `X509_STORE_set_lookup_crls` mechanism (5.3) rests on the claim that
  `X509_STORE_CTX_init` propagates the store's `lookup_crls` into the per-verification context
  and that `get_crl_delta` consults it in preference to the store. The safety net makes a wrong
  claim degrade to "reload is a no-op", and test 5.8/3 detects it - but confirm that reasoning,
  and confirm there is no path where the store-resident v1 CRL is preferred over the callback's
  v2 CRL (which would be a fail-open).
- **OQ-C4.** Should a successful reload be audited (an `audit_emit`-style line) rather than only
  logged? A CRL swap is a security-control change and arguably belongs in the audit stream, but
  F006's schema is per-request and has no event-type field.
- **OQ-C5.** OpenSSL-3.0+-only gating (5.5). Is aborting startup on a BoringSSL/LibreSSL build
  the right call, or should the flag degrade to a warning plus F010a's load-once behaviour?
- **OQ-C6.** The detached, never-joined thread with intentionally-leaked statics (5.7). Is this
  the right trade against a joinable thread that risks a `pthread_join` on the signal path?
- **OQ-C7.** F016 does not reload `--mtls-client-ca-file`. An operator who rotates the CA still
  restarts. Is a CRL-only reload a coherent half-measure, or does it create a false expectation
  that mTLS config is generally hot-reloadable?

--------------------------------------------------------------------------------
## 6. Cross-feature notes

- **Ordering.** No dependencies among F014, F015, F016. If all three ship, F015 last is
  marginally easier (its wrapper touches `server.cpp:242`, F014 touches `server.cpp` near
  `:180`; different hunks, no conflict).
- **Rebase surface.** F014 adds 2 new files + touches 6 existing; F015 adds 1 new header +
  touches 4 existing (2 lines in `server.cpp`); F016 adds 0 new files + touches 4 existing
  (1 line in `server-http.cpp`). All three keep their logic in new or already-forked files.
- **`--metrics` interaction.** F015's counters are only observable with `--metrics` and
  `PERM_METRICS`. F014 and F016 emit their signals through `SRV_WRN`/`SRV_ERR` and are
  independent of that.
- **YAML.** All three new flags are usable from `--config` with no `common/config.cpp` change
  (`common/config.h:14-18` resolves flags generically). Each still needs its `utils.py` field so
  the pytest harness can set it.

--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
# 7. Challenger revisions (BINDING - these override any conflicting text above)

Applied after the adversarial design-challenge pass on F014 and F016 (both
`security_sensitive: true`). F015 got a light pass limited to the no-secrets-in-labels
constraint and the two questions the brief asked about. Where sections 0-6 conflict with this
section, THIS section wins. The coder implements section 7 as written; sections 3, 4 and 5
remain the narrative contract only where section 7 is silent.

Two BLOCKERS were found: B1 (F014) and B2 (F016). Neither is a reason to abandon the feature;
both have concrete fixes below.

## 7.0 Verification of the design's load-bearing claims

Everything below was re-checked against the working tree, not against the design text.

| Design claim | Verdict | Evidence |
|---|---|---|
| `proxy_request` in `server-cors-proxy.h` is the enforcement point, not `server.cpp` | CONFIRMED | `tools/server/server-cors-proxy.h:22-75`; `server.cpp:330-337` only registers. |
| `server_http_proxy` is shared with router-mode child forwarding | CONFIRMED | ctor at `server-models.cpp:2036`; a guard there would break router mode. The defaulted-opts approach is correct. |
| `setup_redirect_client` does NOT copy `addr_map_` | CONFIRMED | `vendor/cpp-httplib/httplib.cpp:9700-9740` copies timeouts, keep-alive, `path_encode_`, compress, proxy settings - and forces `set_follow_location(true)`. No `addr_map_`. |
| addr_map pin is honoured at connect and resolved with `AI_NUMERICHOST` | CONFIRMED | `httplib.cpp:8911-8915` (`addr_map_.find(host_)`), `httplib.cpp:2174-2178` (`if (!ip.empty()) { node = ip; ai_family = AF_UNSPEC; ai_flags = AI_NUMERICHOST; }`). `host_` still drives Host/SNI/cert verification. |
| httplib might silently bypass the pin via an env proxy | NOT A RISK | `create_client_socket` short-circuits to `proxy_host_` (`httplib.cpp:8903-8909`), but `proxy_host_` is ONLY set by `ClientImpl::set_proxy` (`:11277`). httplib never reads `http_proxy`/`HTTP_PROXY` from the environment. No action needed. |
| CRLF smuggling through the proxied path | NOT A RISK | `path_encode_` defaults true; `detail::encode_path` (`httplib.cpp:1090-1105`) escapes `\r`/`\n`, and `write_request_line` rejects a bad target outright (`httplib.cpp:9894-9900`). No action needed. |
| `X509_STORE_CTX_lookup_crls_fn` is `(const X509_STORE_CTX *, const X509_NAME *)` on OpenSSL 3.x | CONFIRMED | `/opt/homebrew/Cellar/openssl@3/3.6.1/include/openssl/x509_vfy.h:271-273`. The 3.0+ build gate is the right call. |
| `harden_context` runs exactly once, at startup, before `listen` | CONFIRMED | `server-http.cpp:154`, inside the one-shot `server_http_context` init. The reload thread cannot be started twice. |
| `server-mtls.cpp` and `server-auth.cpp` are in the same static lib | CONFIRMED | both in `llama-server-impl` (`tools/server/CMakeLists.txt:38-54`). This matters for R-C1 below. |
| F007 trusted-proxy identity is gated on the real socket address | CONFIRMED | `server-http.cpp:266` (`ar.peer_addr = req.remote_addr`), `server-auth.cpp:1178` (`peer_is_trusted(req.peer_addr) && !req.x_auth_subject.empty()`). Never a header. This is what makes B1 exploitable. |

One anchor correction the design gets WRONG, and it matters for section 3.2:

- **`/cors-proxy` is NOT gated on `--ui-mcp-proxy` alone.** `-ag` / `--agent` (and
  `LLAMA_ARG_AGENT`) sets `params.ui_mcp_proxy = true` AND `params.server_tools = {"all"}`
  in one shot (`common/arg.cpp:3377-3394`). A single friendly two-letter flag turns on the
  proxy and every built-in tool including `exec_shell_command`. The design's "anyone reaching
  it has consciously turned on three things" (3.2, point 2) overstates the barrier: the
  realistic operator turned on ONE thing. This strengthens deny-by-default (see A1) and it
  makes OQ-A5 more urgent than section 3.9 implies.

## 7.1 BLOCKER B1 (F014) - the allowlist has no port dimension, and the design's own recommended remedy re-opens loopback SSRF and escalates PERM_PROXY to full admin

Section 3.4 defines allowlist entries as hostnames or CIDRs with NO port component, and
section 3.2 point 3 tells operators that "the common local-MCP case is restored by
`--proxy-allowed-hosts 127.0.0.1/32`". Section 3.8 then instructs that two existing tests be
fixed exactly that way. That single entry permits **every TCP port on the loopback interface** -
which is the entire target set the threat model in 3.1 was written to close
(`http://127.0.0.1:6379/`, `http://127.0.0.1:8500/`, ...). The feature would ship with its
headline mitigation documented as "type this and you are back to the pre-F014 blast radius,
minus the metadata endpoint".

That is bad on its own. The escalation is worse.

**Concrete failure scenario (PERM_PROXY -> admin, no credentials needed):**

1. Operator deploys per PLAN.md variant B: oauth2-proxy/nginx on the same host, so
   `--auth-trusted-proxies 127.0.0.1/32` (the single most common trusted-proxy value).
2. Operator runs the WebUI agent stack: `-ag`, plus `--proxy-allowed-hosts 127.0.0.1/32` as
   section 3.2 instructs, so a local MCP server on 127.0.0.1:9000 works.
3. A caller holding only `PERM_PROXY` (the lowest-value role in the fork; it is what the WebUI
   user gets) sends:

```
GET /cors-proxy?url=http://127.0.0.1:8080/slots
  x-llama-server-proxy-header-x-auth-subject: attacker
  x-llama-server-proxy-header-x-auth-roles: admin
```

   where 8080 is llama-server's own port. The header-forwarding loop
   (`server-cors-proxy.h:44-58`) copies both into the outbound request. The outbound connection
   originates from loopback, so `req.remote_addr` is `127.0.0.1`, so `peer_is_trusted` returns
   true (`server-auth.cpp:1178`), so `resolve_principal` builds an
   `AUTH_TRUSTED_PROXY` principal with roles `{admin}` (`server-auth.cpp:1180-1194`).
4. Every `PERM_ADMIN_STATE` / `PERM_ADMIN_MODELS` route is now reachable, and the response body
   is relayed back to the attacker verbatim.

This is not hypothetical plumbing: `test_proxy.py::test_mcp_proxy_custom_port` already proxies
to the server's own `/models` and asserts a 200. The loop works today.

Note that F014 as designed does not introduce this - it is live right now - but F014 is the
feature whose job is to close it, and as written it documents the configuration that keeps it
open. Shipping F014 with the section 3.2/3.8 guidance would put a fork-authored recommendation
behind a privilege escalation.

**BINDING FIX (all four parts are mandatory):**

**B1-a. Allowlist entries carry an optional port, and the default is not "any port".**
Entry grammar becomes, decided at `configure()` time:

```
entry     := target [ ":" portspec ]
target    := ipv4 | ipv4 "/" bits | "[" ipv6 "]" | "[" ipv6 "]" "/" bits | hostname
portspec  := decimal-port | "*"
```

- An IPv6 target MUST be bracketed when a port is present; unbracketed IPv6 with no port stays
  accepted for convenience (`fd00::1/64`). Reject an unbracketed IPv6 that is followed by a
  port-looking suffix rather than guessing.
- **No `portspec` means `{80, 443}` only** (the scheme default ports). This is the fail-closed
  default and it is what makes `--proxy-allowed-hosts mcp.corp.example` mean "the public HTTP
  service at mcp.corp.example", not "every service on that box".
- `:*` is the explicit any-port escape hatch. It is accepted, but `configure()` logs one
  `SRV_WRN` per `:*` entry naming the entry, so an any-port grant is visible in the startup log.
- The local-MCP guidance in 3.2 point 3 and the test updates in 3.8 change accordingly:
  `--proxy-allowed-hosts 127.0.0.1/32:9000`, not `127.0.0.1/32`.

**B1-b. Hard, non-overridable self-target block.** `server_ssrf::configure` records the server's
own listen port (`params.port`) and bind host (`params.hostname`). `check_target` denies, AFTER
S5 and regardless of any allowlist entry including `:*`, when `out.port == self_port` and the
pinned address is loopback, is the unspecified address, or equals a resolved address of
`params.hostname`. Log reason `"self-target"`. There is no flag to turn this off; a proxy that
can call itself is only ever a credential-confusion primitive or a recursion bomb.

**B1-c. Denylist the request-forwarded headers that this server's own auth layer trusts.**
In `proxy_request`'s header loop (`server-cors-proxy.h:46-58`), after computing `new_key`, skip
it (case-insensitively) when it is one of:

```
x-auth-subject, x-auth-roles, x-api-key, x-forwarded-for, x-forwarded-host,
x-forwarded-proto, x-real-ip, forwarded
```

`authorization` is deliberately NOT on this list - forwarding a bearer token to an MCP server is
the legitimate use of the mechanism, and a caller replaying their own `Authorization` back at
this server gains nothing they did not already have. `x-auth-subject`/`x-auth-roles` are the
only headers this server treats as an identity assertion on the basis of the peer address alone,
which is exactly the property the proxy launders. This denylist is cheap, always on, and
independent of the allowlist, so it holds even if an operator writes `:*`.

**B1-d. Startup cross-check.** If `--auth-trusted-proxies` is non-empty AND `/cors-proxy` is
enabled AND the allowlist contains any entry that could resolve into a trusted-proxy CIDR, emit
one `SRV_WRN` at startup naming both flags. Do not abort (the combination is legitimate once
B1-b and B1-c are in place) - but an operator who sees it should be told to check their
`--proxy-allowed-hosts` scope.

## 7.2 BLOCKER B2 (F016) - the "X509_STORE_add_crl safety net" does not exist; installing a lookup_crls callback REPLACES the store lookup rather than layering on it

Section 5.3's closing paragraph, and features.json F016 acceptance criterion 9, both assert:

> The startup path KEEPS F010a's `X509_STORE_add_crl` calls [...] If the callback were somehow
> not consulted [...] the store-resident CRLs still enforce, so the degenerate failure mode is
> "reload is a no-op", never "revocation silently stops".

This is backwards. There is exactly ONE `lookup_crls` slot per store, and the store-resident
CRLs are reachable ONLY through it:

- `X509_STORE_new` installs `X509_STORE_CTX_get1_crls` as the DEFAULT `lookup_crls`. That
  default is the function that reads the store's `add_crl`'d objects. There is no separate,
  additional path to them.
- `X509_STORE_CTX_init` copies `store->lookup_crls` into the per-verification context (the same
  copy-or-default pattern used for `check_issued`, `get_issuer`, etc.).
- `check_cert` -> `get_crl_delta` consults `ctx->crls` (the `X509_STORE_CTX_set0_crls` stack,
  unused here) and then calls `ctx->lookup_crls(ctx, nm)` - and nothing else.

Therefore `X509_STORE_set_lookup_crls(store, crl_lookup_cb)` **uninstalls** the store lookup.
After F016 lands, the `add_crl`'d CRLs from `load_crl_file` are dead weight; they are never
consulted by any verification. The claimed safety net is not a net, and the claimed degenerate
mode ("reload is a no-op") cannot occur.

The good news: the ACTUAL degenerate mode is fail-CLOSED, not fail-open. If `crl_lookup_cb`
returns an empty stack or `nullptr`, `get_crl_delta` finds no CRL (`ctx->crls` is NULL, so the
`if (!skcrl && crl) goto done` near-match escape does not fire), `check_cert` sets
`X509_V_ERR_UNABLE_TO_GET_CRL`, and every mTLS handshake fails. So the design's mechanism is
safe; only its risk narrative is wrong. But the narrative is load-bearing for a Haiku coder and
for a reviewer signing off against features.json, so it must be corrected.

**BINDING FIX:**

**B2-a.** Delete the "safety net" language from section 5.3 and from features.json F016
criterion 9. Replace it with the true statement: *installing `lookup_crls` replaces the store's
CRL lookup entirely; the startup `add_crl` calls become inert once the callback is installed;
the degenerate failure mode of a broken callback is `X509_V_ERR_UNABLE_TO_GET_CRL` on every
handshake, which is fail-closed.*

**B2-b.** Because the `add_crl` calls are inert, keeping them is not free: if a future refactor
removes or fails to install the callback, the store silently reverts to the FROZEN startup CRL,
which IS the fail-open case the design feared. Bind a startup self-check instead of a "net":
after `X509_STORE_set_lookup_crls`, assert `X509_STORE_get_lookup_crls(store) == crl_lookup_cb`
(the getter exists, `x509_vfy.h:574`) and `SRV_ERR` + `return false` if not. That is a real
assertion; the "net" was not.

**B2-c.** Eliminate the double parse and its TOCTOU. Section 5.6 has `harden_context` parse the
file at step 1 (`load_crl_file`) and AGAIN at step 2b (`crl_parse_file`), and does not say what
happens if the second parse fails. If the file is rotated between the two reads, the server can
start with a store CRL and a snapshot from different files - or, if step 2b returns nullptr,
with an EMPTY snapshot, meaning every handshake fails on a server that started "successfully".
Bind: `crl_parse_file` is called EXACTLY ONCE at startup; `load_crl_file` is rewritten as
`add snapshot to store + set flags`, taking the already-parsed snapshot. The same snapshot object
is published via `crl_set`. A parse failure at startup aborts, unchanged.

## 7.3 Binding revisions - F014, beyond B1

**R-A1. IPv4-preference in the pin (availability regression, not security).** S6 pins "the FIRST
collected address". `getaddrinfo` on a dual-stack host commonly returns the AAAA first, and
`set_hostname_addr_map` takes exactly one address, so F014 removes httplib's implicit
try-each-address behaviour. A host that works today over IPv4 on an IPv6-less network would
start failing after F014 with a confusing connect error. Bind: if the requested host was an
IPv6 literal, or the answer contains only AAAA records, pin the first IPv6 result; otherwise pin
the first IPv4 (or v4-mapped-unwrapped) result. Deterministic, one line, no security cost -
every collected address already passed S5.

**R-A2. S3 must run on the `std::string`, not on `c_str()`, and must reject the embedded NUL
explicitly.** `req.get_param("url")` returns a percent-DECODED value, so `%00` becomes a real
NUL byte inside `parsed_url.host`. `getaddrinfo` takes `c_str()` and truncates there, while any
`std::string` comparison against an allowlist hostname entry sees the full value. That is a
classic split-brain: `http://127.0.0.1%00.mcp.corp.example/` could be made to compare as one
thing and resolve as another. Section 3.4's S3 already forbids control bytes, but the coder must
be told that (a) the length check uses `host.size()`, never `strlen`, (b) NUL is a control byte
for this purpose, and (c) S3 runs BEFORE any allowlist comparison and before S4. Add a test for
the `%00` form specifically - the fork already has this exact test shape for paths in
`test_path_normalization.py`.

**R-A3. The out-of-range port throws before the guard can see it.**
`common_http_parse_url` does `parts.port = std::stoi(port_str)` (`common/http.h:88`).
`?url=http://h:99999999999/` throws `std::out_of_range`, which `ex_wrapper`
(`server.cpp:55-87`) maps to **500**, not to the uniform 403. That both violates the
uniform-error rule of 3.6 (a 500 vs 403 distinction is an oracle, however weak) and makes
features.json F014 criterion "port sanity ... not by an uncaught std::stoi exception turning
into a 500" unsatisfiable as designed, because the throw happens two statements before the
guard. Bind: `proxy_request` wraps the `common_http_parse_url` call in
`try { ... } catch (const std::exception &) { return the same 403 body; }`. Every malformed URL
then produces the identical 403 as every denied target, and the criterion becomes testable.

**R-A4. Strip `Location` from relayed 3xx responses.** Section 3.5 chooses `follow_location=false`
(correct - the pin is not carried into a redirect client, verified in 7.0) and then says "the
relayed 3xx status and `Location` header still reach the client, so a caller that genuinely
needs the hop can re-issue it through the guard". `should_strip_proxy_header`
(`server-models.cpp:1948-1963`) does not strip `location`, so the header is relayed verbatim.
The `/cors-proxy` caller is normally the WebUI's `fetch()`, which defaults to
`redirect: "follow"` and resolves a RELATIVE `Location` against the request URL - i.e. against
llama-server's own origin. An allowlisted-but-hostile (or merely compromised) target that answers
`302 Location: /slots` therefore steers the operator's authenticated browser into a same-origin
authenticated request to llama-server and hands the body to the page as if it were the proxy
response. Bind: for `/cors-proxy` responses only, drop the `Location` header (it is meaningless
to the client once redirects are refused) and keep the status. `server_http_proxy_opts` gains
`bool strip_location = false;` set to `true` from `server-cors-proxy.h`; the ctor's response
handler skips `location` when it is set. Router mode is unaffected (default `false`).
Update the features.json criterion, which currently REQUIRES the `Location` header to be present.

**R-A5. `--proxy-allowed-hosts` set while `/cors-proxy` is disabled.** Accept it, but log one
`SRV_WRN`. An operator who wrote the allowlist and forgot `-ag`/`--ui-mcp-proxy` should not
silently believe the proxy is running.

**R-A6. `getaddrinfo` DoS (OQ-A6): accepted, with one bound.** The resolution is not a NEW
exposure (httplib resolves at connect today), but F014 makes it caller-triggerable earlier and
per-request. Do not add a resolver thread. DO bind the cheap half: `check_target` is called
AFTER the RBAC decision (it already is - the auth middleware runs before the handler), so only
a `PERM_PROXY` holder can trigger it, and the allowlist means only allowlisted hostnames are
ever resolved... except that S4 runs before S5, so an arbitrary hostname IS resolved on any
request. Bind a reordering: when the allowlist contains ONLY CIDR entries (the common local-MCP
case), and the request host is not an IP literal, deny at S3.5 without resolving - there is no
hostname entry it could match, so the resolution can only ever produce an address that must then
be inside a CIDR, and an attacker-chosen hostname pointed at an allowlisted CIDR gains nothing a
direct IP literal would not. This turns the hostile-DNS hold-open into a no-op for the most
common configuration and costs four lines. For configurations WITH hostname entries, resolve
only if the request host exactly matches a hostname entry OR parses as an IP literal; never
resolve an arbitrary caller-supplied name. This is strictly stronger than 3.4 and removes the
DNS-existence-oracle concern of 3.6 at the source.

**R-A7. `/tools` under `PERM_PROXY` (OQ-A5) is confirmed out of scope for F014, but F014 must
warn.** `-ag` grants `server_tools = {"all"}`, which includes `exec_shell_command`
(`server-tools.cpp:581`), and the fork's route table maps `/tools` to `PERM_PROXY`
(`server-auth.cpp:255-257`). So in the fork's own recommended agent configuration, the
permission named "may fetch a URL" also means "may run shell commands as the server user". Bind:
`server_ssrf::configure` (or the nearest startup point that sees both) emits one `SRV_WRN` when
`params.server_tools` is non-empty AND auth is enabled, stating that `/tools` is gated by
`PERM_PROXY` and that any role holding `PERM_PROXY` has command execution. File the real fix
(a distinct `PERM_TOOLS` bit, or splitting `exec_shell_command` behind its own bit) as its own
feature. This is a should-fix at the fork level and arguably outranks F014 itself.

**R-A8. OQ-A7 answered: no remaining second-address path, given B1-b.** With
`follow_location=false` and the addr_map pin, a single accepted request reaches exactly one
`(ip, port)`. httplib's SAME-host redirect path (`httplib.cpp:9619-9621`) reuses the current
client and therefore keeps `addr_map_`, so even if `follow_location` were later flipped on by
mistake, a same-host redirect stays pinned; only the cross-host path
(`create_redirect_client`) escapes, and that is the one being refused. Keep-alive reuse of the
socket is bounded to the same client object. No action.

## 7.4 Binding revisions - F016, beyond B2

**R-C1. TLS session resumption bypasses the reload entirely - this is the real hole in F016.**
A resumed TLS session (TLS 1.3 tickets, or the TLS 1.2 server-side session cache) does NOT
re-run certificate chain verification; OpenSSL restores the stored peer cert and the stored
`SSL_get_verify_result`. `httplib::SSLServer` leaves OpenSSL's server defaults in place, which
means session caching is on and tickets are issued. So a client whose certificate was revoked by
the freshly-reloaded CRL keeps connecting, on new TCP connections, for as long as its ticket is
accepted. F016's headline promise - "revoke a cert and it stops working within `interval`
seconds" - is false for exactly the client that matters, because a client under an attacker's
control is the one that will hold and re-present a ticket.

Bind: when `cfg.enabled && cfg.crl_reload_interval > 0`, `harden_context` also calls

```cpp
SSL_CTX_set_session_cache_mode(c, SSL_SESS_CACHE_OFF);
SSL_CTX_set_options(c, SSL_OP_NO_TICKET);
SSL_CTX_set_num_tickets(c, 0);   // TLS 1.3; OpenSSL 1.1.1+
```

with one `SRV_INF` stating that session resumption is disabled so revocation takes effect within
the reload interval. The cost is a full handshake per connection on an mTLS admin interface,
which is the right trade for a feature whose entire purpose is timely revocation. If a future
operator objects, the correct knob is a separate flag, not silent resumption.
Add the acceptance criterion: a revoked client that reconnects with a previously-issued session
ticket is rejected after the reload.

**R-C2. `crl_reload_stop()` must not touch a mutex or a condition_variable.** Section 5.7
correctly avoids `pthread_join` because `server_http_context::stop()` is reachable from the
signal-delivery path (`server.cpp:26-38`), and then specifies "sets the stop flag and wakes the
thread" - i.e. `condition_variable::notify_one`, which locks. `notify_one` is not
async-signal-safe either, and calling it from a handler that interrupted a thread already
holding the associated mutex can deadlock the process during shutdown. Bind: drop the
`condition_variable`. The thread sleeps in 1-second increments and re-checks a
`std::atomic<bool>`; `crl_reload_stop()` is a single `store(true, std::memory_order_relaxed)`
and nothing else. Worst-case shutdown latency for a DETACHED thread that nobody waits on is
irrelevant.

**R-C3. Consider deleting the `server-http.cpp` call site entirely (simplification).** Once R-C2
lands, `crl_reload_stop()` does nothing except silence log lines during the last second of
shutdown. The thread is detached and the process is exiting. Removing the call removes F016's
ONLY touch of an existing upstream-owned source file, which is worth more on this fork than the
log tidiness. Recommendation: drop it; keep the `crl_reload_stop()` symbol unused-but-available
if the reviewer prefers. If it is kept, it is one line and R-C2 makes it safe. Either way, update
the features.json criterion that currently mandates the `server-http.cpp` change.

**R-C4. Persistent-failure visibility (OQ-C1). The design's alerting is NOT adequate.** Section
5.6 updates `last_attempted` on FAILURE too, so a permanently broken CRL file logs **exactly one**
`SRV_ERR`, ever. Combined with 5.4's "keep the last-known-good", the steady state is: revocation
silently frozen at whatever it was, with a single log line that scrolled away weeks ago. That is
precisely the "silently regresses to F010a's never-reload behaviour" outcome the brief worried
about, and the design's own text ("the operator's own CRL freshness alarm fires as nextUpdate
approaches") leans on an alarm the operator may not have.

Bind three things:

- Re-log the failure at `SRV_ERR`, rate-limited to once per hour, for as long as the active
  snapshot is older than the on-disk file - not once per distinct `(mtime, size)`. The
  `(mtime, size)` memo keeps controlling whether we RE-PARSE; it must not control whether we
  RE-WARN.
- Track `consecutive_failures` and `last_success_unix`. After 24h with no successful reload while
  reload is enabled, escalate the message text to name the flag and the file explicitly.
- Since `server-mtls.cpp` and `server-auth.cpp` are in the same static lib
  (`tools/server/CMakeLists.txt:38-54`), F016 exposes
  `server_mtls::crl_stats(uint64_t & reload_failures, int64_t & last_success_unix,
  int64_t & earliest_next_update)` and, IF F015 ships, F015's emitter appends
  `llamacpp_mtls_crl_reload_failures_total`, `llamacpp_mtls_crl_last_success_timestamp_seconds`
  and `llamacpp_mtls_crl_next_update_timestamp_seconds`. Three unlabelled series, no cardinality
  risk, and it is the only mechanism that actually gets a stale CRL noticed. If F015 does not
  ship, the hourly re-log stands alone and the operator must be told so in the flag help.

With those, "keep last-known-good, do not abort" is the right policy - see the C1 answer in 7.6.

**R-C5. The callback must be `noexcept`-in-practice and allocation-failure-safe.** Section 5.3
says it must never throw and never log; make that concrete: the whole body is wrapped in
`try { ... } catch (...) { return nullptr; }`, and `sk_X509_CRL_new_null()` returning NULL is
handled by returning NULL. Both produce fail-closed verification (7.2). Also bind: on the
`X509_CRL_up_ref` / `sk_X509_CRL_push` path, a failed `push` must `X509_CRL_free` the CRL it
just up-reffed, or the reload leaks a CRL per handshake.

**R-C6. Do not set `X509_STORE_set_flags` twice.** After B2-c, flags are set once by the
add-to-store step. The reload path must not touch the store at all, including flags - section
5.6 already says this; it is restated because it is the invariant that keeps the reload thread
independent of OpenSSL object lifetimes.

**R-C7. OQ-C7 answered in the flag help.** A CRL-only reload IS a coherent half-measure (CRLs
rotate hourly-to-daily by design; CAs rotate on a multi-year cadence), but the help text for
`--mtls-crl-reload-interval` must say in one sentence that `--mtls-client-ca-file` is still
loaded once at startup, so nobody infers general hot-reload.

## 7.5 F015 - light pass

Not `security_sensitive`, reviewed only against the no-secrets-in-labels constraint and the two
questions asked.

- **No secrets in labels: the design is correct as written.** Every label value in 4.2 comes from
  `auth_method_to_string()` (`server-auth.cpp:397-405`), `perm_to_string()`
  (`server-auth.cpp:383-395`) or a compile-time enum table, and storage is a fixed-shape
  `std::atomic` array indexed by enum, so an unbounded value cannot enter even by accident. Keep
  the 4.5 rule "the coder MUST NOT introduce a `std::string` label value from any other source"
  verbatim in the code as a comment; it is the whole feature.
- One gap: `perm_to_string()` returns `""` for a zero or multi-bit mask. `required_perm=""` would
  be emitted as an empty label value - valid Prometheus, but useless and it silently signals a
  bug. Bind: map an empty `perm_to_string()` result to the literal `"unknown"` in the emitter,
  and never to a formatted numeric mask.
- **OQ-B5 (raised to a binding change because it costs one enum value):** `t_fail_reason`
  defaulting to `no_credential` (4.3) hides a forgotten branch inside the busiest bucket. Use a
  distinct `unknown` reason as the default. A non-zero `reason="unknown"` series is a bug report;
  a silently inflated `no_credential` is not.

## 7.6 ANSWERS to the open questions (each is a decision, not a discussion)

**OQ-A1 - deny-by-default vs block-private-by-default: AGREE with deny-by-default, and the
`-ag` finding in 7.0 strengthens it.** The architect's argument stands unmodified: a
block-private policy is an allow-by-default policy for the rest of the internet, it does not stop
exfiltration to an attacker-controlled public endpoint, and it does not stop a public host that
redirects inward. The usability counter-argument is weaker than section 3.2 admits it is,
because the enabling flag is not the deliberate `--ui-mcp-proxy` but the casual `-ag`; an
operator who types `-ag` to try the agent WebUI has not consented to an unbounded outbound HTTP
primitive, and giving them a 403 with a flag name in the log is the right first experience. The
blast radius is genuinely bounded (opt-in feature, `PERM_PROXY`-gated, three tests in-repo).
Deny-by-default is confirmed. The private-address block stays as the second layer for hostname
entries, per 3.4/3.7. The one thing that must change is the REMEDY the design hands the operator
- see B1-a; `127.0.0.1/32` is not an acceptable thing to tell people to type.

**OQ-A2 - refusing all redirects: CONFIRMED, with R-A4.** Per-hop re-validation is more state
for a case the WebUI does not need. The `/mcp` -> `/mcp/` concern is real but is a SAME-host
redirect, which httplib handles on the current client with the addr_map intact - so if it ever
becomes a problem the narrow fix is "follow same-host redirects only", not a manual loop. Do not
build that now. Do strip `Location` (R-A4).

**OQ-A3 - all-must-pass vs filter-and-pick: KEEP all-must-pass, plus R-A1.** Because the
connection is pinned, filter-and-pick would be equally secure at the network layer - the design's
own S6 pin is what makes the difference moot. The tiebreaker is signal: a hostname in a narrow
allowlist whose answer contains a private address is either an attack or a misconfiguration, and
in both cases failing loudly beats silently succeeding over the other family. The DoS objection
is answered by B1-a's world where allowlists are explicit and narrow, and by the escape hatch of
spelling out a CIDR. The genuine availability problem in this area is NOT the strictness, it is
"pin the FIRST address" on a dual-stack host with no IPv6 route - fixed by R-A1's
prefer-IPv4 rule. On the mechanics: the design's `set_hostname_addr_map` +
`AI_NUMERICHOST` + `follow_location=false` claim is VERIFIED CORRECT against
`vendor/cpp-httplib/httplib.cpp:8911-8915`, `:2174-2178` and `:9700-9740` (see 7.0); the pin is
real, `host_` still drives Host/SNI/cert verification, and `setup_redirect_client` really does
not copy `addr_map_`.

**OQ-A4 - the ~40-line CIDR duplication: ACCEPT the duplication.** Exporting
`prefix_match`/`strip_v4mapped_prefix` from `server-auth.h` would put `<netinet/in.h>` into a
header included by the auth middleware and by tests, for 40 lines. The fork's overriding
constraint is a cheap perpetual rebase, and two small self-contained copies rebase better than
one shared header with two consumers. Keep 3.7 as written; the reviewer is pre-warned.

**OQ-A5 - `/tools` RCE under `PERM_PROXY`: separate feature, but F014 must warn.** See R-A7.

**OQ-A6 - hostile-DNS hold-open: bounded by R-A6's "never resolve a name that cannot match".**
Not the reverse proxy's job, because the reverse proxy cannot see which name is about to be
resolved.

**OQ-A7 - remaining second-address path: none.** See R-A8.

**OQ-B1 - `llamacpp_auth_*` underscore next to `llamacpp:*` colon: CONFIRMED, use the
underscore.** Propagating a known-wrong exposition convention into new metrics is worse than the
inconsistency, and the colon form is the one that will eventually have to be fixed upstream.

**OQ-B2 - disjoint-by-HTTP-status partition: CONFIRMED, the architect's partition is right.**
`unmapped_role` is a 403 with `authenticated == true`; filing it under
`llamacpp_auth_failures_total` would double-count it against the authz family and would make
`rate(llamacpp_auth_failures_total)` mean two different things. Operators who want "all auth
rejections" write `sum(rate(llamacpp_auth_failures_total[5m])) +
sum(rate(llamacpp_auth_authz_denied_total[5m]))`, which is exactly why disjointness is the
property worth preserving. Deviating from the F015 description text is correct here.

**OQ-B3 - router mode mixing router auth counters with child inference counters: acceptable, do
not add a label.** Both sets are already prefixed distinctly (`llamacpp_auth_*` vs
`llamacpp:*`) and the scrape target is the router, so "these are the router's numbers" is the
correct reading. Adding a `role="router"` label to only some series would be worse.

**OQ-B4 - `t_fail_reason` as a `thread_local`: accept, with the 4.3 discipline as written**
(reset at the TOP of `resolve_principal`, adjacent to the writes). It mirrors `t_principal`
exactly, and the alternative - a new DTO field threaded through every branch - is more churn on
security-sensitive code for an observability feature.

**OQ-B5 - default `t_fail_reason`: use `unknown`, not `no_credential`.** Raised to binding in
7.5.

**OQ-B6 - emitting only non-zero series: accept.** The zero-vs-not-wired-up ambiguity is
resolved by the always-emitted `# HELP`/`# TYPE` lines for each family; a family whose HELP line
is present with no series means "wired up, nothing counted".

**OQ-C1 - abort vs last-known-good on a bad reload: last-known-good is CORRECT, but the design's
alerting was NOT adequate and is now fixed by R-C4.** The DoS argument holds on its own terms: a
writer who can truncate the CRL file can also write a syntactically valid CRL that revokes
nothing, so "abort on bad parse" does not raise the bar against that attacker while it does hand
a trivial kill switch to a buggy cron job. The counter-argument in the brief is the real one and
it is about VISIBILITY, not about policy: a single `SRV_ERR` per distinct `(mtime, size)` means a
permanently broken reload is announced once and then never again, which is indistinguishable from
F010a's frozen behaviour. With R-C4's hourly re-log, the 24h escalation, and the CRL-freshness
gauges, "keep serving with a stale-but-valid CRL, loudly" strictly dominates both alternatives.
Note also that the truly dangerous case is already closed upstream of this decision: F010a's R1
rules reject a CRL whose `nextUpdate` has passed, so a stale file can never become the active
snapshot, and if the ACTIVE snapshot expires OpenSSL fails every handshake.

**OQ-C2 - poll vs SIGHUP: CONFIRMED, poll.** The design's rebuttal of "SIGHUP needs no thread" is
correct, and on this fork the decisive argument is the one in the table: SIGHUP means editing
`server.cpp`'s shared `shutdown_handler`/`signal_handler` pair, which is upstream-owned code that
moves. The operator-expectation counter-argument is answered by the flag help. Keep poll.

**OQ-C3 - the `X509_STORE_set_lookup_crls` mechanism: the MECHANISM is correct, the SAFETY-NET
REASONING IS WRONG - this is BLOCKER B2.** Concretely, to answer the two halves of the question:
(a) OpenSSL does NOT consult both the callback and the store-resident `add_crl`'d CRLs - the
store-resident CRLs are reachable only through the default `lookup_crls`
(`X509_STORE_CTX_get1_crls`), which the custom callback replaces, so after F016 the `add_crl`'d
CRLs are inert; (b) consequently there is NO path where the store-resident v1 CRL is preferred
over the callback's v2 CRL, so the fail-open the architect feared cannot happen - but neither can
the "safety net" they relied on, and an empty/failed callback result gives
`X509_V_ERR_UNABLE_TO_GET_CRL`, i.e. fail-CLOSED, not fail-open. Fix per B2-a/B2-b/B2-c. Test
5.8/3 remains the right load-bearing test and now proves something stronger than the design
claimed.

**OQ-C4 - audit a successful reload: no.** F006's schema is per-request; bending it for a
process-lifecycle event costs more than it returns. `SRV_INF` plus R-C4's
`llamacpp_mtls_crl_last_success_timestamp_seconds` covers the operational need.

**OQ-C5 - abort on a non-OpenSSL-3.0+ build: CONFIRMED, abort.** A silently ignored reload flag
is an operator who believes revocation is fresh when it is frozen - the exact failure this
feature exists to prevent.

**OQ-C6 - detached, never-joined thread: accept, with R-C2.** The lifetime reasoning in 5.7 is
sound once `crl_reload_stop()` stops touching a mutex.

**OQ-C7 - CRL-only reload: coherent, say so in the help.** See R-C7.

## 7.7 Should this live in the reverse proxy instead? (PLAN.md variant B)

Asked explicitly of every subsystem.

- **F014: NO, it belongs here.** An egress firewall or a squid-style forward proxy is the classic
  answer, and it is a good defence in depth, but it cannot express "this llama-server's
  `/cors-proxy` may reach X" separately from "this host may reach X"; it does not see the
  `?url=` parameter; and it cannot close the DNS-rebinding window (which is fixed by pinning the
  validated IP into the connect, something only the code making the connection can do). Keep
  F014 in-process. The one part that IS reverse-proxy-shaped - rate limiting `/cors-proxy` - is
  correctly absent from the design.
- **F016: NO, but it is close.** Terminating mTLS in nginx/envoy gives CRL reload for free and is
  the better answer for most deployments, and the design's own section 0 already says "DEFER in
  favour of short-lived certs" when there is no real CRL distribution point. That recommendation
  should be repeated in the flag help. But once the fork supports mTLS in-process at all (F008,
  already merged and reviewed), leaving revocation frozen until restart is not a defensible
  half-feature, so F016 is the right completion of F010a rather than a new subsystem.
- **F015: NO.** A reverse proxy can count 401s and 403s, but not `reason=unmapped_role` vs
  `reason=invalid_key`, which is the entire operational value.

## 7.8 Smaller design that does 90% of the job

For the record, since simplification is a standing question:

- **F014 could ship as B1-a + S1-S6 with the private-range table DELETED.** Once every entry must
  be an explicit host-or-CIDR plus port, the compiled-in blocked-range table (3.7, ~40 lines of
  table plus the CIDR matcher) only defends the hostname-entry branch against a repointed DNS
  answer. That is a real case, so the table earns its place - but if the coder is struggling, the
  table is the part to cut, not the pinning or the redirect refusal. Do not cut it silently;
  cutting it means a hostname entry can reach a private address, which must then be documented.
- **F016 has no meaningful 90% version.** The reload loop is trivial; the OpenSSL mechanism is the
  feature. Cutting the expiry warnings (5.6) would save ~20 lines and is the only optional part -
  but R-C4 makes them the primary operator-visible signal, so they now carry weight.
- **F015 could drop the router-mode streaming append (4.4 step 6) entirely** and return
  the proxied body untouched in router mode, at the cost of OQ-B3's question disappearing along
  with the router's own counters. Not recommended, but it is the cuttable third of the feature.

## 7.9 Confirmed correct - do NOT change

- F014's placement of the guard in `server-cors-proxy.h` rather than in `server_http_proxy`
  (router mode would break; verified at `server-models.cpp:1192`, `:1826`).
- The defaulted `server_http_proxy_opts` trailing parameter so both router call sites are
  untouched.
- The uniform 403 body for every denial reason (3.6), and keeping the distinguishing detail in
  `SRV_WRN` without the resolved IP.
- The scope correction that `/tools` performs no client-controlled outbound HTTP - re-verified:
  `grep -n "httplib::Client" tools/server/server-tools.cpp tools/server/server-mcp.cpp` returns
  nothing, and MCP transport is a stdio subprocess.
- F015's response-wrapper approach and the `server-context.cpp`-stays-clean constraint (the
  `test-chat` link boundary is real).
- F016's poll-over-SIGHUP choice, the 3.0+ build gate, the `(mtime, size)` change detection, and
  the in-flight-connections-are-unaffected reasoning (verification happens at handshake time
  only - which is precisely why R-C1's session-resumption gap matters).
