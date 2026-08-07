# PR3 design: mTLS client-certificate authentication

Status: in_design
Features: F008a (flags + params + harness), F008b (SSLServer client-CA + SSL_CTX hardening +
build gating), F008c (certificate identity extraction + DTO), F008d (SAN->role policy mapping +
resolve_principal precedence + audit).

This document is the implementation contract for a Haiku-class coder. Every non-obvious
decision is settled here. Do not invent behavior that is not written down; if something is
missing, stop and ask the architect.

ASCII only in all code and docs (AGENTS.md): no em-dash, no unicode arrows, use `-` and `->`.

PR3 builds on merged PR1 (docs/design/pr1-rbac-core.md) and PR2
(docs/design/pr2-principal-proxy.md). It reuses PR2 conventions verbatim: all auth policy logic
in server-auth.{h,cpp}; a NEW file pair server-mtls.{h,cpp} owns X.509/TLS-context handling;
existing files get call sites only; fail closed; deny-by-default; no hand-rolled crypto.

--------------------------------------------------------------------------------
## 0. Scope and non-goals

In scope for PR3:
- Construct the httplib SSL server with a client-CA file/dir so the TLS stack requests and
  verifies client certificates, with three enforcement modes (off/optional/required).
- Harden the TLS context: minimum protocol version, certificate-chain verify depth, and the
  optional-mode verify override.
- Extract a client identity (SAN URI, then SAN DNS; never CN) from the verified peer
  certificate and carry it into the auth request DTO.
- Map that SAN identity to a role via a new policy `mtls` section (exact + trailing-wildcard),
  reusing the persisted `g_role_perms`; unmapped SAN -> deny (no default role).
- Precedence: mTLS -> trusted-proxy headers -> API key (mTLS inserted ahead of the PR2 chain).
- New flags: `--mtls-client-ca-file`, `--mtls-client-ca-dir`, `--mtls-required`,
  `--mtls-verify-depth`, `--tls-min-version`. Fail-closed on any misconfiguration.

Explicitly NOT in PR3 (do not implement, do not add fields beyond what is noted):
- CRL / OCSP revocation. DEFERRED to PR5 (section 9). Do NOT add `--mtls-crl-file` in PR3, even
  though PLAN.md 4.5 lists it. Recommend short-lived certs (SPIFFE/SVID) in the flag help.
- `X-Forwarded-Client-Cert` (XFCC) parsing for the behind-a-terminator case (PLAN.md 4.3
  variant B). PR2 already STRIPS that header; PR3 does the DIRECT client-cert case only. XFCC
  consumption is deferred (section 8, open question OQ4).
- OIDC (PR4). `AUTH_MTLS` is added to the enum now; `AUTH_OIDC` is not.
- mTLS identity for the gcp async internal-dispatch path beyond the PR2 by-value principal copy
  (no change needed; the principal is resolved in the middleware and copied as in PR2).

Hard rules (CLAUDE.md) honored:
- Fail closed: mTLS flags with no SSL build, no server cert/key, an unreadable CA, an invalid
  mode/version string, or a failed context hardening call -> `init`/server-start returns false
  and the server aborts.
- No hand-rolled crypto: certificate chain verification is done by the TLS backend
  (SSL_VERIFY_PEER); SAN extraction uses the vendored httplib `tls::PeerCert` abstraction (the
  library's own X.509 parsing); the only direct OpenSSL calls are three `SSL_CTX_*` hardening
  setters, gated on `CPPHTTPLIB_OPENSSL_SUPPORT`.
- No secrets on argv: CA paths and a cert/key path are not secrets; there is no private material
  on the command line.
- Minimize footprint in existing files: server-http.cpp gets the SSLServer construction change
  plus one `server_mtls::extract_identity` call site in `middleware_authz`; server-auth.cpp gets
  the policy `mtls` parse and the `resolve_principal` mTLS branch; all cert/context code is in
  server-mtls.cpp.

--------------------------------------------------------------------------------
## 1. Discrepancies between PLAN.md / the task framing and the current code

Anchors verified on branch `master` after PR2 merged. THESE MATTER - PLAN.md 4.3 was written
against an older httplib and is wrong in three load-bearing ways.

| PLAN.md / task claim | Reality (verified) | Impact |
|---|---|---|
| `srv->ssl_context()` returns `SSL_CTX*` | The vendored httplib exposes `SSLServer::tls_context()` returning `tls::ctx_t` (a `void*`), httplib.h:2844. There is NO `ssl_context()` method. | Cast `tls_context()` to `SSL_CTX*` inside server-mtls.cpp, gated on `CPPHTTPLIB_OPENSSL_SUPPORT`. |
| `httplib::Request` has an `SSL* ssl` field | `Request::ssl` is `tls::const_session_t` (a `const void*`), httplib.h:1408-1409, present only under `CPPHTTPLIB_SSL_ENABLED`. | Pass `req.ssl` as `const void*`; extract via the httplib TLS abstraction, not a raw `SSL*`. |
| Use `SSL_get1_peer_certificate()` + manual GENERAL_NAMES/SAN parsing | The vendored httplib provides a backend-agnostic extractor: `tls::get_peer_cert_from_session(req.ssl)` -> `tls::PeerCert` with `.sans()` returning `std::vector<tls::SanEntry>` (`SanType::URI`/`DNS`/`IP`/`EMAIL`/`OTHER`), plus `.subject_cn()`, `.issuer_name()`, `.validity()`, `.serial()` (httplib.h:1268-1341; impl httplib.cpp:12709-12711, 12931-12956, get_cert_sans 13649-13710). | DECISION (see 1a): use the httplib `tls::PeerCert` API for SAN extraction instead of raw OpenSSL. It is the vendored library's own tested code (not "hand-rolled crypto"), and it keeps identity extraction backend-portable. Flagged for the challenger (OQ1). |
| httplib does not harden the context | httplib ALREADY sets `SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)` in `create_server_context` (httplib.cpp:13110) and, when a client CA is supplied, sets `SSL_VERIFY_PEER \| SSL_VERIFY_FAIL_IF_NO_PEER_CERT` via `set_verify_client(ctx, true)` (httplib.cpp:12057-12067, 13303-13309). | We still set min-version explicitly (to honor `--tls-min-version 1.3`), set verify depth (httplib does NOT), and, for optional mode, DROP `FAIL_IF_NO_PEER_CERT` by re-calling `SSL_CTX_set_verify`. |
| SSL construction "~line 107" | server-http.cpp:108-127 (the `#ifdef CPPHTTPLIB_OPENSSL_SUPPORT` block). Construction is `std::make_unique<httplib::SSLServer>(cert, key)` (two-arg). | Extend to the four-arg CA constructor and add the hardening call. |
| `CPPHTTPLIB_OPENSSL_SUPPORT` defined? | YES on this build. Root `CMakeLists.txt:127` `option(LLAMA_OPENSSL ... ON)`; vendor/cpp-httplib/CMakeLists.txt:126-149 runs `find_package(OpenSSL)` and defines `CPPHTTPLIB_OPENSSL_SUPPORT` publicly (line 185-186). PR2 build log showed OpenSSL 3.6.1. The macro that gates the abstraction is `CPPHTTPLIB_SSL_ENABLED` (any backend). | mTLS code is gated on `CPPHTTPLIB_OPENSSL_SUPPORT` for the ctx hardening and on `CPPHTTPLIB_SSL_ENABLED` for the `req.ssl` extraction. Build without SSL => mTLS flags refuse to start. |

### 1a. The identity-extraction decision (OQ1, settled here, flagged for challenger)

PLAN.md 4.3 says use `SSL_get1_peer_certificate()` and parse SANs by hand. The vendored httplib
now ships a well-tested, backend-agnostic peer-cert wrapper. This design uses
`tls::get_peer_cert_from_session` / `tls::PeerCert::sans()` for two reasons: (1) it avoids adding
our own OpenSSL X.509 SAN-walking code (fewer of our own lines touching the cert parser), which is
squarely in the spirit of the "reuse existing infrastructure / no hand-rolled crypto" rules; and
(2) it keeps SAN extraction working if the build ever switches TLS backends. The ONLY places we
touch OpenSSL directly are the three `SSL_CTX_*` hardening setters, which are inherently
backend-specific and are `#ifdef CPPHTTPLIB_OPENSSL_SUPPORT`-gated with a fail-closed `#else`.
If the challenger prefers raw OpenSSL SAN parsing, section 4.3 lists exactly what would change.

--------------------------------------------------------------------------------
## 2. File layout

New files (mTLS X.509 / TLS-context logic):
- `tools/server/server-mtls.h`  - the `server_mtls` interface + the `mtls_identity` struct +
  the `server_mtls_config` struct. Includes nothing from OpenSSL; takes `const void *` handles.
- `tools/server/server-mtls.cpp` - `configure_server_tls` (build the config, validate),
  `harden_context` (SSL_CTX setters), `extract_identity` (PeerCert -> SANs).

Modified files (call sites / config only):
- `tools/server/CMakeLists.txt` - add `server-mtls.cpp` / `server-mtls.h` to the
  `llama-server-impl` target next to server-auth.cpp (CMakeLists.txt around the existing
  server-auth entries).
- `tools/server/server-http.cpp` - SSLServer construction with the client CA + hardening call
  (section 3.3); one `server_mtls::extract_identity(req.ssl, ...)` call in `middleware_authz`
  populating the DTO (section 4.4).
- `tools/server/server-auth.h` - add `AUTH_MTLS` to `server_auth_method`; add the mTLS identity
  fields to `server_auth_request` (section 4.1).
- `tools/server/server-auth.cpp` - parse the policy `mtls` section in `init`; add the mTLS
  branch (precedence-first) to `resolve_principal`; add `AUTH_MTLS -> "mtls"` in
  `auth_method_to_string` (section 5, 6).
- `common/common.h` - five new `common_params` fields (section 7.1).
- `common/arg.cpp` - five new CLI flags + env vars (section 7.2).
- `tools/server/tests/utils.py` - thread the five flags into `ServerProcess` (section 10).

No change to server.cpp: `server_auth::init` at server.cpp:179 already runs after
`ctx_http.init` (server.cpp:173); the mTLS policy parse rides inside `server_auth::init`, and the
SSLServer construction is inside `ctx_http.init`. Ordering is correct as-is (section 6.3).

--------------------------------------------------------------------------------
## 3. F008b: SSL server construction + context hardening + build gating

### 3.1 server-mtls.h contract (config + hardening)

```cpp
#pragma once

#include <string>

struct common_params;

// Resolved, validated mTLS configuration. Built once from common_params.
struct server_mtls_config {
    bool        enabled        = false;   // required or optional mode requested
    bool        require_cert   = false;   // true = required mode (fail handshake if no cert)
    std::string client_ca_file;           // may be empty if dir is set
    std::string client_ca_dir;            // may be empty if file is set
    int         verify_depth   = 1;       // SSL_CTX_set_verify_depth argument (C5: SPIFFE leaf-under-issuer)
    int         min_tls_version = 0x0303; // TLS1_2 (0x0303) or TLS1_3 (0x0304)
    // identity_source is a POLICY concern (server-auth.cpp), not here.
};

struct server_mtls {
    // Parse and validate common_params into a server_mtls_config. Returns false (and logs a
    // SRV_ERR) on any invalid combination: an unknown --mtls-required value, an unknown
    // --tls-min-version value, a negative --mtls-verify-depth, or (mode != off) with neither
    // --mtls-client-ca-file nor --mtls-client-ca-dir set. Never throws.
    static bool configure(const common_params & params, server_mtls_config & out);

    // Apply OpenSSL hardening to ANY SSL server context (the value from
    // SSLServer::tls_context()) - call it on both the mTLS and the plain-TLS SSLServer paths.
    // ctx is a tls::ctx_t (void*); cast to SSL_CTX* internally under CPPHTTPLIB_OPENSSL_SUPPORT.
    // ALWAYS sets the min proto version from cfg.min_tls_version (so --tls-min-version is honored
    // with or without mTLS - S2). WHEN cfg.enabled additionally sets the verify depth, and - when
    // cfg.require_cert is false (optional mode) - re-sets the verify mode to SSL_VERIFY_PEER
    // WITHOUT SSL_VERIFY_FAIL_IF_NO_PEER_CERT so a client may connect without a cert. Returns
    // false on any setter failure or if built without OpenSSL support. Never throws.
    static bool harden_context(void * ctx, const server_mtls_config & cfg);

    // (declared here, implemented for F008c - section 4.2)
    static bool extract_identity(const void * ssl_session, struct mtls_identity & out);
};
```

`configure` maps `--mtls-required`:
- `off` (default) -> `enabled=false`. CA files, if provided, are IGNORED with a `SRV_WRN`
  ("--mtls-client-ca-* ignored because --mtls-required is off"). No client-cert auth.
- `optional` -> `enabled=true`, `require_cert=false`. Requires a CA (file or dir), else fail.
- `required` -> `enabled=true`, `require_cert=true`. Requires a CA, else fail.

`--tls-min-version` maps `"1.2"` -> `0x0303`, `"1.3"` -> `0x0304`; any other string -> fail.
An empty `--tls-min-version` keeps the default `0x0303` (TLS 1.2). `configure` ALWAYS populates
`cfg.min_tls_version`, even when `--mtls-required` is `off`, because the min-version applies to
ANY SSL server, not only the mTLS path (S2). `harden_context` is therefore called on BOTH the
mTLS and the plain-TLS SSLServer branches (section 3.3), so `--ssl-cert-file --tls-min-version
1.3` without mTLS is honored (httplib otherwise hardcodes TLS 1.2 for every SSL context,
httplib.cpp:13298). This resolves OQ3: min-version tightening is not confined to mTLS.

### 3.2 mtls_identity struct (server-mtls.h)

```cpp
struct mtls_identity {
    bool        present = false;   // a verified peer cert was presented
    std::string san_uri;          // first SAN of type URI ("" if none)
    std::string san_dns;          // first SAN of type DNS ("" if none)
    // deliberately NO cn / subject_dn field: CN is not used for authz (PLAN.md 4.3), and the
    // full DN is PII we must not surface or log. issuer is set to a constant by the caller.
};
```

### 3.3 server-http.cpp construction change (the ONLY existing-file TLS change)

Replace the two-arg SSLServer construction (server-http.cpp:108-127). New logic, same location,
still fully inside the existing `#ifdef CPPHTTPLIB_OPENSSL_SUPPORT` / `#else` structure:

```
build server_mtls_config cfg via server_mtls::configure(params, cfg); on false -> return false

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    has_server_tls = !ssl_file_key.empty() && !ssl_file_cert.empty()
    if cfg.enabled && !has_server_tls:
        SRV_ERR("mTLS requires --ssl-cert-file and --ssl-key-file"); return false   // fail closed
    if has_server_tls:
        if cfg.enabled:
            srv = make_unique<SSLServer>(cert, key,
                     cfg.client_ca_file.empty() ? nullptr : cfg.client_ca_file.c_str(),
                     cfg.client_ca_dir.empty()  ? nullptr : cfg.client_ca_dir.c_str())
        else:
            srv = make_unique<SSLServer>(cert, key)          // plain-TLS path
        if !srv->is_valid(): SRV_ERR("failed to init SSL server (cert/key/CA)"); return false
        // harden ANY SSL server: min-version always; verify-depth + optional-mode override only
        // when mTLS is enabled (S2 - min-version must apply to plain TLS too).
        auto ssl_srv = static_cast<httplib::SSLServer *>(srv.get())
        if !server_mtls::harden_context(ssl_srv->tls_context(), cfg):
            SRV_ERR("failed to harden TLS context"); return false                    // fail closed
        is_ssl = true
    else:
        srv = make_unique<httplib::Server>()                 // no TLS
#else
    if cfg.enabled || (ssl_file_key/cert set):
        SRV_ERR("the server is built without SSL support"); return false             // fail closed
    srv.reset(new httplib::Server())
#endif
```

Key points:
- `SSLServer` with a client CA already sets `SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT`
  (httplib.cpp:12066). `harden_context` LEAVES that as-is for required mode and DROPS
  `FAIL_IF_NO_PEER_CERT` for optional mode.
- `srv->is_valid()` is false when the SSLServer ctor failed (bad cert/key/CA); we must check it
  and fail closed (today's code does not, but with a CA a bad path would otherwise start a broken
  listener).
- The `#else` (no-SSL build) branch refuses to start if ANY mTLS flag OR the existing ssl flags
  are set - extends the current behavior at server-http.cpp:122-125.

### 3.4 harden_context implementation (server-mtls.cpp)

```cpp
bool server_mtls::harden_context(void * ctx, const server_mtls_config & cfg) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    if (!ctx) return false;
    SSL_CTX * c = static_cast<SSL_CTX *>(ctx);
    // Always applied (any SSL server, mTLS or plain) - S2.
    if (SSL_CTX_set_min_proto_version(c, cfg.min_tls_version) != 1) return false;
    // Client-cert specifics only when mTLS is enabled.
    if (cfg.enabled) {
        SSL_CTX_set_verify_depth(c, cfg.verify_depth);       // void; no error return
        if (!cfg.require_cert) {
            // optional mode: request a cert but do not fail the handshake if none is sent.
            SSL_CTX_set_verify(c, SSL_VERIFY_PEER, nullptr);
        }
    }
    return true;
#else
    (void) ctx; (void) cfg;
    return false;   // fail closed: hardening impossible without OpenSSL
#endif
}
```

Notes:
- `<openssl/ssl.h>` is included in server-mtls.cpp ONLY inside `#ifdef CPPHTTPLIB_OPENSSL_SUPPORT`.
  server-mtls.h stays OpenSSL-free (handles are `void*`), so server-http.cpp/server-auth.cpp do
  not gain an OpenSSL include.
- For optional mode we deliberately re-set the verify mode AFTER the ctor (which set the
  fail-if-no-cert bit). An invalid cert that IS presented still fails the handshake in optional
  mode, because SSL_VERIFY_PEER verifies any presented cert; only the ABSENCE of a cert is
  tolerated. This is the behavior tested in section 10 (wrong-CA/expired certs are rejected in
  both modes).

--------------------------------------------------------------------------------
## 4. F008c: certificate identity extraction + DTO

### 4.1 DTO additions (server-auth.h, server_auth_request)

Append three fields to `server_auth_request` (they default empty/false, so existing
construction in `middleware_authz` still compiles):

```cpp
struct server_auth_request {
    // ... existing PR2 fields ...
    bool        mtls_present = false;   // a verified client cert was presented (F008c)
    std::string mtls_san_uri;           // SAN URI from the client cert ("" if none)
    std::string mtls_san_dns;           // SAN DNS from the client cert ("" if none)
};
```

Rationale: extraction happens in the middleware (which owns `req.ssl`); the resolved identity
selection (URI vs DNS) and role mapping are POLICY and live in resolve_principal, so the DTO
carries the raw SANs, not a pre-chosen identity. This mirrors how the DTO carries raw
`x_auth_subject`/`x_auth_roles` and lets resolve_principal apply `identity_source`.

### 4.2 extract_identity (server-mtls.cpp)

**Correction found during implementation review (post-coder, reviewer pass):**
`httplib::tls::get_peer_cert_from_session()` is NOT reachable via qualified lookup from outside
httplib.cpp - it is declared only as a `friend` inside `PeerCert` (httplib.h:1340), which grants
access but does not add it to ordinary/qualified namespace lookup. `server-mtls.cpp` including
`httplib.h` and calling `httplib::tls::get_peer_cert_from_session(ssl_session)` does NOT compile
("no member named 'get_peer_cert_from_session' in namespace 'httplib::tls'"). The only public way
to obtain a `PeerCert` is `httplib::Request::peer_cert()` (a real member function declared in the
header, implemented in httplib.cpp using the friend access from inside that translation unit).

`extract_identity` therefore takes the address of a `httplib::tls::PeerCert` already obtained by
the caller via `req.peer_cert()`, as an opaque `const void *` (so `server-mtls.h` still stays free
of httplib/OpenSSL types - only the .cpp casts it back). This is a signature change from the
original plan (`ssl_session` = `req.ssl`) but the security contract is unchanged: all SAN parsing
and the C1 ambiguous-SAN fail-closed rule remain the single implementation in server-mtls.cpp;
server-http.cpp's only mTLS-specific code is obtaining the `PeerCert` and passing its address.

Second bug found and fixed in the same pass: the original `#ifdef CPPHTTPLIB_SSL_ENABLED` guard
placed AROUND the `#include "vendor/cpp-httplib/httplib.h"` line in server-mtls.cpp was
self-referential and always false - `CPPHTTPLIB_SSL_ENABLED` is defined *inside* httplib.h itself
(derived from `CPPHTTPLIB_OPENSSL_SUPPORT`/MBEDTLS/WOLFSSL), so it can never be defined yet at the
point of the guard. This silently skipped the httplib.h include (and, since `extract_identity`'s
body is ALSO gated on the same always-undefined macro, silently compiled out the whole function
body every build), making `extract_identity` a permanent no-op that always returned
`present=false` - even on a full OpenSSL build. httplib.h must be included unconditionally in
server-mtls.cpp (as server-http.cpp already does); `CPPHTTPLIB_SSL_ENABLED` becomes correctly
defined once httplib.h has actually been included, and every `#ifdef CPPHTTPLIB_SSL_ENABLED`
block AFTER that include behaves as designed.

```cpp
bool server_mtls::extract_identity(const void * peer_cert, mtls_identity & out) {
    out = mtls_identity{};
#ifdef CPPHTTPLIB_SSL_ENABLED
    if (!peer_cert) return false;                    // no session (plain HTTP) -> no identity
    const auto & cert = *static_cast<const httplib::tls::PeerCert *>(peer_cert);
    if (!cert) return false;                          // no client cert presented (optional mode)
    out.present = true;
    // C1: SANs come back in cert-author-controlled order, so "first URI" is nondeterministic for
    // the policy author. Count each selected type; MORE THAN ONE URI (or DNS) -> ambiguous ->
    // leave that identity field EMPTY (fail-closed: empty identity maps to perms=0 -> 403).
    int n_uri = 0, n_dns = 0;
    std::string uri, dns;
    for (const auto & s : cert.sans()) {
        if (s.type == httplib::tls::SanType::URI) { if (n_uri++ == 0) uri = s.value; }
        if (s.type == httplib::tls::SanType::DNS) { if (n_dns++ == 0) dns = s.value; }
    }
    if (n_uri == 1) out.san_uri = uri;               // exactly one -> deterministic identity
    if (n_dns == 1) out.san_dns = dns;               // >1 or 0 -> empty -> denied downstream
    return true;
#else
    (void) peer_cert;
    return false;
#endif
}
```

- `peer_cert` is the address of a `httplib::tls::PeerCert` obtained by the CALLER via
  `req.peer_cert()` (see 4.4); server-mtls.cpp includes httplib.h unconditionally to reach the
  `tls::` API (the include cannot be guarded by `CPPHTTPLIB_SSL_ENABLED`, see above - that macro
  is defined only once httplib.h has already been processed). server-mtls.h does NOT include
  httplib.h (keeps the public interface clean; the pointer is `const void*` there).
- The cert is already chain-verified by the TLS stack before this runs (SSL_VERIFY_PEER), so
  extract_identity does NOT re-verify; it only reads SANs. CN is never read (PLAN.md 4.3).
- Returns false (and leaves `out.present=false`) when there is no cert or no client cert
  presented; the middleware then leaves the DTO mTLS fields empty and auth falls through to the
  next method.

### 4.3 If the challenger vetoes the httplib abstraction (raw-OpenSSL fallback)

Only section 4.2 changes: `#ifdef CPPHTTPLIB_OPENSSL_SUPPORT`, cast the underlying session to
`const SSL *` (obtained from `req.ssl`, not from `req.peer_cert()`), `SSL_get1_peer_certificate`,
walk `subjectAltName` GENERAL_NAMES for `GEN_URI` then `GEN_DNS` with
`ASN1_STRING_get0_data`/length (reject embedded NUL), `X509_free`. Nothing else in the design
moves. Kept as a fallback; the abstraction is the default (1a / OQ1).

### 4.4 middleware call site (server-http.cpp middleware_authz)

In `middleware_authz` (server-http.cpp:215-235), after the existing DTO field assignments and
before the `authorize_request(ar)` call, add (inside `#ifdef CPPHTTPLIB_SSL_ENABLED`):

```cpp
#ifdef CPPHTTPLIB_SSL_ENABLED
    mtls_identity id;
    auto peer_cert = req.peer_cert();  // the only public accessor httplib exposes (see 4.2)
    if (server_mtls::extract_identity(&peer_cert, id)) {
        ar.mtls_present = id.present;
        ar.mtls_san_uri = id.san_uri;
        ar.mtls_san_dns = id.san_dns;
    }
#endif
```

This is the whole existing-file change for F008c. No cert/SAN parsing lives in server-http.cpp;
`req.peer_cert()` is a plain httplib accessor, not our code.

--------------------------------------------------------------------------------
## 5. F008d: policy mtls section + SAN->role mapping + precedence

### 5.1 Policy schema addition (parsed in server_auth::init)

Extend the policy JSON (PLAN.md 4.1) with an optional `mtls` object:

```json
"mtls": {
  "identity_source": "san_uri",
  "role_map": {
    "spiffe://corp/ns/ml/sa/ops": "admin",
    "spiffe://corp/ns/*":         "user"
  }
}
```

- `identity_source`: `"san_uri"` (default) or `"san_dns"`. Selects WHICH SAN the identity is
  taken from. Any other string -> `init` fails. Absent -> default `"san_uri"`.
- `role_map`: object mapping a SAN identity pattern -> a role name. The role name MUST exist in
  `roles` (or the compiled-in defaults), else `init` fails (fail closed, same rule as
  `api_keys`). A pattern is either an exact string or a trailing-wildcard `prefix*` (a single
  `*` as the last character; `*` anywhere else -> `init` fails to avoid ambiguous globs).
- Absent `mtls` object -> empty role map -> every presented cert is unmapped -> denied (403).
  This is fail-closed: to AUTHORIZE mTLS clients an operator MUST supply `--auth-policy-file`
  with an `mtls.role_map`. Document in the flag help.

New file-scope state in server-auth.cpp (next to `g_role_perms`, `g_trusted_proxies`):

```cpp
std::string g_mtls_identity_source = "san_uri";               // "san_uri" | "san_dns"
struct mtls_map_entry { std::string pattern; bool wildcard; uint32_t perms; std::string role; };
std::vector<mtls_map_entry> g_mtls_role_map;                   // built in init
```

### 5.2 Wildcard matching rule (deterministic, settled)

`mtls_lookup(identity) -> (matched, perms, role)`:
- First pass: exact match (`entry.wildcard == false && entry.pattern == identity`). If found,
  return it (exact always wins).
- Second pass: among wildcard entries whose prefix (pattern without the trailing `*`) is a prefix
  of `identity`, choose the one with the LONGEST prefix. Ties are impossible (two identical
  prefixes would be duplicate keys in the JSON object). Return it.
- No match -> matched=false.

Empty `identity` never matches (an empty SAN is treated as no identity upstream).

### 5.3 init changes (server-auth.cpp)

1. Add `has_mtls` alongside `has_api_keys` / `has_trusted_proxies`. Its value comes from
   `params.mtls_required`: `has_mtls = (params.mtls_required == "optional" ||
   params.mtls_required == "required")`. (The full TLS config validation is F008b's
   `server_mtls::configure`, called from server-http.cpp; init only needs the boolean to decide
   enforcement and to know whether to require a role map. Do NOT re-validate the CA here.)
2. The PR2 auth-disabled early return (server-auth.cpp:646) becomes
   `else if (!has_api_keys && !has_trusted_proxies && !has_mtls)`. With mTLS enabled, control
   falls through so the default `admin`/`user` roles and `g_role_perms` are built (needed for
   SAN->role mapping even without a policy file).
3. `g_auth_enabled = has_policy_file || has_api_keys || has_trusted_proxies || has_mtls;`
   (server-auth.cpp:658). Enabling mTLS ENABLES enforcement (parallels F007 Q5 for
   trusted-proxies); document the behavior flip in the flag help. Flagged OQ2.
4. After `g_role_perms` is persisted (server-auth.cpp:698), parse `policy["mtls"]` if present:
   read `identity_source` into `g_mtls_identity_source` (validate the two allowed values); build
   `g_mtls_role_map` from `role_map` (validate each role exists in `role_perms`, resolve to
   `perms`, detect wildcard, reject a `*` that is not the sole trailing char). Any violation ->
   `SRV_ERR` + `return false`.
5. **Defensive startup invariant (S1) - MANDATORY, do NOT rely on steps 2+3 alone.** Steps 2 and
   3 are a two-line coupling (extend the auth-disabled early-return guard AND OR `has_mtls` into
   `g_auth_enabled`) that fails OPEN if only one line is applied: mTLS-only mode (no policy, keys,
   or proxies) would hit the PR2 early return, set `g_auth_enabled=false; return true`, and
   `authorize_request` would then ALLOW-ALL on a server the operator believes requires client
   certs (the PR2-4b class of bug). To make this independent of getting two separate edits right,
   add, as the LAST check before `init` returns success:

   ```cpp
   if (has_mtls && !g_auth_enabled) {
       SRV_ERR("%s", "mTLS is enabled but auth enforcement is off; refusing to start\n");
       return false;   // fail closed
   }
   ```

   This is a belt-and-suspenders guard: if any future refactor lets `has_mtls` be true while
   `g_auth_enabled` is false, the server refuses to start instead of silently serving open.

### 5.4 resolve_principal precedence (server-auth.cpp:783)

Insert the mTLS branch as the FIRST check, ahead of the existing trusted-proxy and API-key
branches (new precedence: mTLS -> trusted-proxy -> API key -> anonymous):

```
resolve_principal(req):
    // 1. mTLS (highest precedence). A presented cert is chain-verified by the TLS stack.
    if req.mtls_present:
        identity = (g_mtls_identity_source == "san_dns") ? req.mtls_san_dns : req.mtls_san_uri
        server_auth_principal p
        p.authenticated = true            // valid cert -> authenticated, even if unmapped
        p.method        = AUTH_MTLS
        p.issuer        = "mtls"          // constant; never the CA DN (no PII in principal)
        p.subject       = identity        // the SAN value (URI/DNS); not a secret
        p.perms         = 0
        (matched, perms, role) = mtls_lookup(identity)
        if matched:
            p.perms = perms
            if !role.empty(): p.roles = { role }
        // unmapped SAN or empty identity -> authenticated, perms=0 -> caller denies 403
        return p

    // 2. trusted-proxy headers (unchanged PR2 block)
    // 3. API key (unchanged PR2 block)
    // 4. anonymous
```

Decisions (mirror the PR2 trusted-proxy fail-closed contract):
- A presented cert whose SAN is unmapped is `authenticated=true, perms=0`: it passes
  authentication but is DENIED (403) on every CLASSIFIED protected route. This is "unmapped SAN =
  deny, no default role" (task item 3). It does NOT fall through to API-key auth: a presented cert
  is the identity for the connection (precedence). Document this so operators know a cert client
  cannot also silently use an API key.
  - C4 accuracy note: on a `NORM_UNMATCHED` (out-of-prefix) or otherwise unclassified path, an
    unmapped-but-authenticated principal follows the pre-existing PR2 rule for ANY authenticated
    caller - it returns `allow` and falls through to httplib, which 404s the unregistered route
    (server-auth.cpp authorize_request). So "403 on every protected route" is precise; it does not
    imply a 403 on unregistered paths, which 404 as they do today. No code change; accuracy only.
- Empty identity (cert present but the selected SAN type is absent) -> `perms=0` -> 403. Do not
  fall back to the other SAN type: `identity_source` is an explicit operator choice.
- `optional` mode with NO cert -> `req.mtls_present == false` -> this branch is skipped -> auth
  falls through to trusted-proxy/API-key/anonymous (task item 1). This is the ONLY case where a
  cert-less client proceeds under an mTLS-enabled server.
- Authorization is ONLY on `p.perms` (the F007 Q4 hard rule): no code branches on role names or
  on the raw SAN string.

### 5.5 audit + enum

- Add `AUTH_MTLS` to `server_auth_method` (server-auth.h:30), AFTER `AUTH_TRUSTED_PROXY` to keep
  existing values stable: `{ AUTH_NONE, AUTH_API_KEY, AUTH_TRUSTED_PROXY, AUTH_MTLS }`.
- Add the case to `auth_method_to_string` (server-auth.cpp:377): `AUTH_MTLS -> "mtls"`.
- The audit line's `subject_hash` is `sha256_hex(p.subject + salt)`; since `p.subject` is the SAN
  value, the raw SAN is NEVER written (only its salted hash), satisfying "do not log full DN /
  PII". `peer_ip` is the TCP peer as today. No cert bytes, no DN, no issuer DN are logged.

--------------------------------------------------------------------------------
## 6. Data flow and ordering

```
TLS handshake (httplib SSLServer)
  |  client CA loaded -> SSL_VERIFY_PEER [+ FAIL_IF_NO_PEER_CERT if required]
  |  harden_context: min proto, verify depth, optional-mode verify override
  |  cert chain + expiry verified by OpenSSL here; wrong-CA/expired -> handshake fails
  v
pre_routing_handler (server-http.cpp:261)
  |  server_auth::reset_principal()                     (PR2, unchanged)
  |  CORS / OPTIONS / server_state / frontend carve-out (unchanged)
  |  middleware_authz:
  |     build server_auth_request ar (PR2 fields)
  |     server_mtls::extract_identity(req.ssl, id) -> ar.mtls_* (F008c)
  |     server_auth::authorize_request(ar):
  |        resolve_principal: mTLS -> trusted-proxy -> API key (F008d)
  |        deny-by-default authz on p.perms (PR1/PR2, unchanged)
  |        audit_emit (auth_method="mtls" when applicable)
  v
get/post/del -> req.principal = principal_at_construction()  (PR2, unchanged)
```

### 6.3 Startup ordering (verified, no server.cpp change)

server.cpp:173 `ctx_http.init(params)` (constructs the SSLServer + hardening) precedes
server.cpp:179 `server_auth::init(params)` (parses the policy mtls section). The mTLS policy
parse only needs `params`, not the live TLS context, so this order is fine. If
`server_mtls::configure` fails, `ctx_http.init` returns false at server.cpp:173 and the server
aborts before `server_auth::init` runs. Both are fail-closed.

--------------------------------------------------------------------------------
## 7. Config: flags and common_params

### 7.1 common/common.h (near ssl_file_cert / ssl_file_key at common.h:650-651)

```cpp
std::string mtls_client_ca_file = "";   // --mtls-client-ca-file
std::string mtls_client_ca_dir  = "";   // --mtls-client-ca-dir
std::string mtls_required       = "off";// --mtls-required {off|optional|required}
int         mtls_verify_depth   = 1;    // --mtls-verify-depth (C5: default leaf-under-issuer)
std::string tls_min_version     = "1.2";// --tls-min-version {1.2|1.3}
```

### 7.2 common/arg.cpp (follow the --ssl-cert-file pattern at arg.cpp:3408-3421)

Five flags, all `.set_examples({LLAMA_EXAMPLE_SERVER})` with env vars:
- `--mtls-client-ca-file PATH` (`LLAMA_ARG_MTLS_CLIENT_CA_FILE`) -> `params.mtls_client_ca_file`.
- `--mtls-client-ca-dir PATH` (`LLAMA_ARG_MTLS_CLIENT_CA_DIR`) -> `params.mtls_client_ca_dir`.
- `--mtls-required VALUE` (`LLAMA_ARG_MTLS_REQUIRED`) -> `params.mtls_required`. Help lists the
  three values, states the default is `off`, and that `optional`/`required` ENABLE auth
  enforcement (deny-by-default) and require an `--auth-policy-file` with an `mtls.role_map` to
  authorize any client. The setter stores the raw string; validation is in
  `server_mtls::configure` (fail-closed on an unknown value).
- `--mtls-verify-depth N` (`LLAMA_ARG_MTLS_VERIFY_DEPTH`) -> `params.mtls_verify_depth`
  (`std::stoi`; negative -> `server_mtls::configure` fails). Default 1 (C5). Help: "max
  intermediate CA depth in the client cert chain; default 1 (one intermediate); 0 = client cert
  must be signed directly by a configured CA. Raise only if your PKI uses deeper chains".
- `--tls-min-version VALUE` (`LLAMA_ARG_TLS_MIN_VERSION`) -> `params.tls_min_version`. Help lists
  `1.2` (default) and `1.3`, and notes it applies to any HTTPS server (with or without mTLS).

Help text must mention:
- CRL/OCSP is NOT implemented (use short-lived certs); CA paths are not secrets; there is no
  client private material on argv.
- **C2 (byte-exact SAN matching):** the `mtls.role_map` keys are matched byte-for-byte against
  the SAN as the CA encodes it (raw ASN.1 IA5String; no percent-decoding, no case-folding, no
  trailing-dot normalization). Write the SAN exactly as issued (e.g. `%2F` vs `/`, a trailing `.`
  on a DNS SAN) or it silently never matches (fail-closed, but a footgun).
- **C3 (wildcard is a raw byte prefix):** a trailing `*` in a `role_map` key matches any byte
  suffix and is NOT segment-bounded (`spiffe://corp/ns*` would also match
  `spiffe://corp/nsEVIL`). Always include the trailing delimiter (`spiffe://corp/ns/*`) and map
  wildcards to the least-privileged role.

--------------------------------------------------------------------------------
## 8. Interaction with trusted-proxy mode (PR2) and XFCC

- A DIRECT client presenting a real client cert is the PR3 case: mTLS wins precedence over
  trusted-proxy headers and over API keys.
- `X-Forwarded-Client-Cert` (a proxy that terminated mTLS and forwards the client cert as a
  header) is NOT consumed in PR3. PR2 already STRIPS `X-Forwarded-Client-Cert` in `get_headers`
  (server-http.cpp:507-511 via `server_auth::identity_headers()`), so it never reaches a handler.
  PR3 does not read it. XFCC parsing (trust only from a listed proxy peer, then map its SAN) is
  deferred (OQ4) - it belongs with the trusted-proxy trust model, not the direct-cert path.
- If a client is BOTH behind a trusted proxy AND presents a direct cert to llama-server, mTLS
  (direct cert) wins. In a real variant-B deployment the proxy terminates TLS, so llama-server
  sees no client cert and `mtls_present` is false; the trusted-proxy branch then applies. The two
  paths do not conflict.

--------------------------------------------------------------------------------
## 9. CRL / revocation - DEFERRED to PR5 (explicit)

PR3 does NOT implement CRL or OCSP. `--mtls-crl-file` (PLAN.md 4.5) is intentionally NOT added in
PR3. Rationale: CRL needs file distribution + refresh, and OCSP stapling is not exposed by
httplib. The realistic mitigation, documented in the `--mtls-required` help and the README, is
SHORT-LIVED client certificates (SPIFFE/SVID, hours) so revocation is handled by expiry. CRL is
tracked under F010 (PR5). This is a conscious residual risk (PLAN.md 4.3, section 8): a compromised
client cert remains valid until it expires.

--------------------------------------------------------------------------------
## 10. Test strategy (for the test-planner; coder threads flags only)

New file `tools/server/tests/unit/test_mtls.py`. A pytest fixture generates, with the `cryptography`
lib (or `openssl` CLI) into a tmp dir: a CA; a server cert/key signed by it; a VALID client cert
with `SAN URI=spiffe://corp/ns/ml/sa/ops`; a second VALID client cert with
`SAN URI=spiffe://corp/ns/ml/sa/dev` (matches the `spiffe://corp/ns/*` wildcard -> user); a client
cert with an UNMAPPED SAN (`spiffe://corp/other/x`); a client cert signed by a DIFFERENT CA; an
EXPIRED client cert signed by the good CA. A policy file maps the two mapped SANs to admin/user.

`ServerProcess` (utils.py) gains: `ssl_file_cert`, `ssl_file_key` (if not already), plus
`mtls_client_ca_file`, `mtls_client_ca_dir`, `mtls_required`, `mtls_verify_depth`,
`tls_min_version`, each appended to `server_args` when set (mirror the `auth_policy_file`
pattern at utils.py). The Python client must present a client cert: `requests`/`httpx` with
`cert=(client_cert_path, client_key_path)` and `verify=<ca_path>` (so the client trusts the
server cert). Tests use `https://` URLs.

Cases (negative first):
1. `required` mode, client presents NO cert -> the TLS handshake is REJECTED (connection/SSL
   error at the transport layer, not an HTTP 401). Assert an exception, not a status code.
2. `required` mode, client presents a cert from the WRONG CA -> handshake REJECTED.
3. `optional`/`required` mode, client presents an EXPIRED (good-CA) cert -> handshake REJECTED
   (SSL_VERIFY_PEER verifies any presented cert in both modes).
4. Valid client cert with SAN mapped to `admin` -> `POST /slots/0` (ADMIN_STATE) succeeds with no
   API key; audit `auth_method=mtls`, non-anonymous `subject_hash`.
5. Valid client cert with SAN mapped to `user` -> `POST /completions` (INFER) succeeds;
   `POST /slots/0` (ADMIN_STATE) -> 403.
6. Valid client cert with an UNMAPPED SAN -> `POST /completions` -> 403 (authenticated, perms=0),
   NOT 401 and NOT a default role.
7. `optional` mode, client presents NO cert but a VALID `user` API key -> falls through to
   API-key auth; `POST /completions` succeeds (task item: optional no-cert falls to api-key).
8. `optional` mode, no cert, no key -> anonymous -> 401 on a protected route (enforcement is on).
9. Startup fail-closed: `--mtls-required required` with NO `--ssl-cert-file` -> server refuses to
   start; `--mtls-required required` with NO CA file/dir -> refuses to start;
   `--mtls-required bogus` -> refuses to start; `--tls-min-version 1.4` -> refuses to start.
10. `--tls-min-version 1.3`: a TLS-1.2-only client is rejected (best-effort; may be environment
    dependent - the test-planner decides whether to gate this on client capability).
11. S2 (plain HTTPS min-version): `--ssl-cert-file`/`--ssl-key-file` with `--tls-min-version 1.3`
    and NO mTLS -> a TLS-1.2-only client is rejected (min-version is honored without mTLS).
12. C1 (ambiguous SAN): a valid good-CA client cert carrying TWO URI SANs -> denied (403 on a
    protected route), not resolved to the first URI.
13. S1 (mTLS-only enforcement): `--mtls-required optional` with no key, no policy, no proxies; a
    request with NO cert and NO key to a protected route returns 401 (proves the server did not
    silently start in allow-all mode).

Note: the pytest harness needs HTTPS support and client-cert presentation; the test-planner
verifies `ServerProcess` currently has no SSL wiring and adds `ssl_file_cert`/`ssl_file_key`
threading if absent.

--------------------------------------------------------------------------------
## 11. Fail-closed behavior summary

| Condition | Behavior |
|---|---|
| mTLS flag set, server built without SSL support | server-http.cpp `#else` returns false; abort |
| `--mtls-required optional/required` without `--ssl-cert-file`/`--ssl-key-file` | `ctx_http.init` returns false; abort |
| `--mtls-required optional/required` without a client CA file or dir | `server_mtls::configure` returns false; abort |
| Unknown `--mtls-required` / `--tls-min-version` value, negative verify depth | `server_mtls::configure` returns false; abort |
| SSLServer ctor failed (bad cert/key/CA path) | `srv->is_valid()` false -> abort |
| `harden_context` setter fails (e.g. bad min-version) on any SSL server | returns false -> abort |
| mTLS enabled but `g_auth_enabled` ended up false (S1 half-applied coupling) | `server_auth::init` returns false; abort (defensive invariant) |
| Client cert with more than one URI (or DNS) SAN of the selected type (C1) | selected identity left empty -> perms=0 -> 403 |
| Policy `mtls.role_map` names a nonexistent role, or bad `identity_source`, or misplaced `*` | `server_auth::init` returns false; abort |
| Client cert presented, SAN unmapped or empty | authenticated, perms=0 -> 403 (no default role) |
| No policy `mtls` section but mTLS enabled | empty role map -> every cert 403; enforcement still on |
| Optional mode, no cert | mTLS branch skipped -> trusted-proxy/API-key/anonymous applies |
| Wrong-CA or expired cert (any mode) | rejected at TLS handshake, never reaches authz |
| Compromised but unexpired client cert | accepted until expiry (CRL deferred to PR5) - documented residual risk |

--------------------------------------------------------------------------------
## 12. Feature mapping

- F008a: flags + `common_params` fields + `ServerProcess` threading. Files: common/common.h,
  common/arg.cpp, tools/server/tests/utils.py. Sections 7, 10.
- F008b: server-mtls.{h,cpp} (`configure`, `harden_context`) + CMake + SSLServer construction +
  build/SSL/cert fail-closed gating. Files: server-mtls.h/.cpp, tools/server/CMakeLists.txt,
  tools/server/server-http.cpp. Sections 3, 11.
- F008c: `mtls_identity` + `extract_identity` (httplib PeerCert) + DTO fields + middleware call
  site. Files: server-mtls.h/.cpp, server-auth.h, tools/server/server-http.cpp. Section 4.
- F008d: policy `mtls` parse + `AUTH_MTLS` + `resolve_principal` mTLS-first precedence + wildcard
  SAN->role map + audit `auth_method`. Files: server-auth.h, server-auth.cpp. Sections 5, 6.

Suggested implementation order: F008a -> F008b -> F008c -> F008d (matches `depends_on`).

--------------------------------------------------------------------------------
## 13. Open questions - challenger (Fable) verdict folded in

The challenger reviewed this design: NO blockers; core crypto/precedence sound and fail-closed.
The should-fixes are folded in (S1 defensive startup invariant section 5.3 step 5; S2 min-version
on any SSL server sections 3.1/3.3/3.4; C1 multi-URI/DNS-SAN ambiguity -> deny section 4.2; C2/C3
flag-help section 7.2; C4 accuracy note section 5.4; C5 default verify-depth 1 sections 3.1/7).
Resolutions:

- OQ1 (RESOLVED - keep the httplib abstraction): use `tls::PeerCert::sans()` for SAN extraction.
  Challenger confirmed embedded-NUL safe and DNS-vs-URI type-distinct; C1 adds the multi-SAN
  ambiguity guard. The raw-OpenSSL fallback (4.3) stays documented but is not taken.
- OQ2 (RESOLVED - enforce): enabling mTLS flips a keyless/policyless server to deny-by-default,
  now backed by the S1 startup invariant so it cannot silently fail open.
- OQ3 (RESOLVED - apply to plain TLS too): `--tls-min-version` is honored on any SSL server, not
  only the mTLS path (S2).
- OQ4 (DEFERRED, confirmed): `X-Forwarded-Client-Cert` is stripped (PR2) but not consumed; XFCC
  parsing belongs with the trusted-proxy trust model in a later PR.
- OQ5 (RESOLVED - default 1): `--mtls-verify-depth` defaults to 1 (SPIFFE/SVID leaf-under-issuer),
  operator-overridable (C5).
- OQ6 (RESOLVED - strict precedence kept): a presented-but-unmapped cert yields 403 and does NOT
  fall back to API-key auth on the same request; documented in section 5.4.
