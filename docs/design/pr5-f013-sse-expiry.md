# PR5 design: enforce access-token expiry during long SSE streams (F013)

Status: in_design
Feature: F013 (Enforce token exp during long SSE streams)
Depends on: F009d (OIDC principal wiring, done). Interacts with F010b (introspection, in flight).

This document is the implementation contract for a Haiku-class coder. Every non-obvious
decision is settled here. Do not invent behavior that is not written down; if something is
missing, stop and ask the architect.

ASCII only in all code and docs (AGENTS.md): no em-dash, no unicode arrows, use `-` and `->`.

Hard rules honored: fail closed; all new logic in `server-auth.{h,cpp}`; existing files get
call sites only; no hand-rolled crypto (this feature adds none); no secrets in logs.

--------------------------------------------------------------------------------
## 0. Problem statement

Authorization is evaluated exactly once, in `middleware_authz` -> `server_auth::authorize_request`,
at the start of a request. `server_auth_principal::expires_at` (server-auth.h:54) is populated
from the JWT `exp` by the OIDC branch of `resolve_principal` (server-auth.cpp:1152) but is never
read again. A streamed generation can therefore keep delivering SSE chunks for minutes or hours
on a connection whose bearer token expired long ago (PLAN.md 8.4).

Goal, stated as a precise security property:

> **No SSE chunk is written to the socket at or after the deadline derived from the request
> principal's `expires_at`.**

Non-goal (see section 7): terminating an *idle* connection that is producing no bytes, and
cutting non-streaming responses.

--------------------------------------------------------------------------------
## 1. Anchor verification (PLAN.md / features.json vs the current tree)

Verified on branch `master` at the time of writing. Re-`grep` before editing; these rot.

| Claim | Reality | Impact |
|---|---|---|
| features.json F013 `files: ["tools/server/server-context.cpp"]` | **STALE / WRONG as the sole file.** The completions SSE loop is `server_routes::handle_completions_impl`, the `res->set_next(...)` lambda at server-context.cpp:4247 (function starts at 4090, `content_type = "text/event-stream"` at 4246). But it is only ONE of six stream producers (row below), and in router mode the completions stream does not pass through it at all. | F013 is re-scoped to the HTTP choke point; `files` updated |
| PLAN.md 8.4 "requires a check in the generation loop in `server-context.cpp`" | Only partly right. `server-models.cpp:2073` (`server_http_proxy::server_http_proxy`) is the streaming path for **router mode** proxied `/v1/chat/completions`; a check in `handle_completions_impl` would miss it entirely. | PLAN.md guidance is insufficient; design deviates deliberately (section 2) |
| Stream producers today | six `next`/`set_next` sites: server-context.cpp:4247 (completions/chat/infill/responses/messages), server-models.cpp:1719 (`/models/sse`), server-models.cpp:2073 (router proxy), server-stream.cpp:487 (`GET /v1/stream` replay), server-tools.cpp:1302 (tool stream), plus the spipe tee wrapper server-stream.cpp:655 | all six funnel through one function (next row) |
| Single choke point exists? | YES: `process_handler_response` (server-http.cpp:598); every streamed response is served by the `chunked_content_provider` lambda at server-http.cpp:609, which is the only caller of `response->next(chunk)` on the HTTP path | the gate goes here |
| Is `req.principal` reachable from the streaming loop? | YES. `process_handler_response` receives `server_http_req_ptr && request` and keeps it alive as `q_ptr` (server-http.cpp:606) for the whole stream. `request->principal` is populated by F005 at get/post/del (server-http.cpp:653/704/725). | no new plumbing needed |
| gcp `/predict` streaming | not applicable: `payload["stream"] = false` is forced (server-http.cpp:864) | no gcp work |
| `params.oidc_clock_skew` | common/common.h:666, `int`, default 60, documented clamp [0,300] | reused as the grace, section 3.2 |
| `params.sse_ping_interval` | common/common.h:616, default 30 s | bounds the staleness window for completions, section 3.3 |
| existing mid-stream error convention | server-context.cpp:4248-4257, the `format_error` static inside the completions `set_next` lambda: Anthropic gets `format_anthropic_sse({{"event","error"},{"data",...}})`, everything else gets `format_oai_sse({{"error", ...}})`, then `return false` to terminate. Client disconnect / `should_stop` is a **silent** close (`return false`, no output). | F013 reuses the error-event convention verbatim, section 4 |

No blocker. The one substantive correction to PLAN.md/features.json framing: the fix does **not**
belong in `server-context.cpp`'s generation loop, because that loop is bypassed in router mode
and does not cover the other four SSE producers.

--------------------------------------------------------------------------------
## 2. Decision 1: where the check goes

**`tools/server/server-http.cpp`, `process_handler_response`, inside the
`chunked_content_provider` lambda (currently line 609), as the FIRST statement, before
`response->next(chunk)` is called.**

Rationale:

- It is the single choke point for every streamed response. One call site covers all six
  producers today, including the router-mode proxy stream that `handle_completions_impl` does
  not see.
- It is rebase-robust in the same spirit as the deny-by-default route table: a new upstream
  streaming endpoint inherits the check automatically instead of silently becoming an
  unbounded post-expiry data feed.
- `request->principal` is already in scope there (F005), so no principal plumbing is added to
  any generation code.
- It gives the exact property from section 0: the check runs immediately before each chunk is
  written, so no byte can leave after the deadline.

The gate is placed **before** `response->next(chunk)` so that on expiry we do not even ask the
producer for another chunk (this also means nothing is teed into the spipe replay buffer by the
cut invocation, see section 7).

--------------------------------------------------------------------------------
## 3. Decision 2: cadence and the deadline

### 3.1 Cadence: every chunk, no throttling

The gate reads the wall clock once per `chunked_content_provider` invocation, i.e. once per SSE
chunk. There is **no** N-tokens / N-seconds throttle and **no** cached-time state.

Justification: one `std::time(nullptr)` is a vDSO read on the order of tens of nanoseconds; a
chunk costs at least one token decode, i.e. milliseconds. The overhead is below noise, and
adding throttle state would only buy staleness and bugs. The staleness window is therefore
exactly "one chunk", which is the minimum achievable without a separate watchdog thread
(explicitly out of scope).

### 3.2 The deadline

```
deadline = principal.expires_at + grace          , when principal.expires_at >  0
deadline = 0  (gate disabled, never cuts)        , when principal.expires_at <= 0
```

`grace` is a process-wide value fixed at startup:

```
g_stream_expiry_grace_sec = clamp(params.oidc_clock_skew, 0, 300)      // default 60
```

Why the grace equals the OIDC clock skew, and is not a new flag:

- Initial validation accepts a token whose `exp` is up to `oidc_clock_skew` seconds in the past
  (jwt-cpp `.leeway(...)`, F009c). Using a *smaller* grace here would cut a stream the instant
  it started for a token the server had just accepted - an authorize/cut contradiction.
  Using the same leeway makes the two checks consistent by construction.
- It is testable: a test sets `--oidc-clock-skew 0` and gets a cut exactly at `exp`.
- It adds no CLI surface. `params.oidc_clock_skew` has a value (60) even when OIDC is not
  configured, so a future non-OIDC method that sets `expires_at` still gets a sane grace.
- The local `clamp` is a safety net: `server_oidc::init` only validates the flag when OIDC is
  actually configured.

`g_stream_expiry_grace_sec` is assigned unconditionally near the TOP of `server_auth::init`
(immediately after `g_api_prefix = params.api_prefix;`, server-auth.cpp:507), because `init` has
an auth-disabled early return at server-auth.cpp:692-695 that would otherwise skip it.

### 3.3 Resulting staleness window

| Stream | Bound on "time between deadline and the cut" |
|---|---|
| completions / chat / infill / responses / messages (`handle_completions_impl`) | <= `sse_ping_interval` seconds (default 30), because the SSE keep-alive ping is itself a chunk and forces the provider to return even when the model is stalled |
| router-mode proxy, `/models/sse`, tool stream, `GET /v1/stream` replay | unbounded **only while the stream is idle**; the cut happens on the first chunk that would otherwise be written |

Both rows satisfy section 0: an idle connection past the deadline carries no data. This is an
accepted, documented residual (section 7), not a defect.

--------------------------------------------------------------------------------
## 4. Decision 3: what the client sees

**An SSE error event, then the stream is closed.** Not a silent close.

This reuses the convention already in the codebase for mid-stream errors
(server-context.cpp:4248-4257): a mid-stream failure emits an error event and returns `false`;
only *client disconnect* is a silent close. A silent close here would be indistinguishable from
a truncated success and would make an expired-token cut look like a server bug to the client.

Two dialects, exactly mirroring the existing `format_error` split:

- **Default (OpenAI-compatible, used by every stream except Anthropic)** -
  `format_oai_sse(json{{"error", format_error_response("access token expired", ERROR_TYPE_AUTHENTICATION)}})`, i.e. the bytes:

  ```
  data: {"error":{"code":401,"message":"access token expired","type":"authentication_error"}}\n\n
  ```

- **Anthropic (`/v1/messages`, `TASK_RESPONSE_TYPE_ANTHROPIC`)** -
  `format_anthropic_sse(json{{"event","error"},{"data", format_error_response("access token expired", ERROR_TYPE_AUTHENTICATION)}})`, i.e.:

  ```
  event: error\ndata: {"code":401,"message":"access token expired","type":"authentication_error"}\n\n
  ```

(`json` is `nlohmann::ordered_json`, so the key order `code, message, type` produced by
`format_error_response` is stable; the byte sequences above are exact.)

After writing the chunk the provider calls `sink.done()` and returns `false`, matching how the
existing `!has_next` branch terminates a stream.

The HTTP status is **not** changed to 401: response headers were already flushed when the stream
started. The 401 lives in the error payload only. This is the same limitation the existing
mid-stream error path has and is not worked around.

--------------------------------------------------------------------------------
## 5. Interfaces

### 5.1 `tools/server/server-auth.h` - four new members of `struct server_auth`

Add at the end of `struct server_auth` (after `identity_headers()`, currently line 140):

```cpp
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

    // The SSE chunk written immediately before an expired stream is cut. Two dialects,
    // mirroring the mid-stream error convention in handle_completions_impl: _oai() is the
    // default "data: {\"error\":...}" form used by every stream except Anthropic,
    // _anthropic() is the "event: error" form. Both return a reference to a
    // function-local static built once, so there is no per-chunk cost.
    static const std::string & sse_expired_chunk_oai();
    static const std::string & sse_expired_chunk_anthropic();
```

### 5.2 `tools/server/server-auth.cpp` - implementation

Add to the anonymous namespace, next to the other `g_` state:

```cpp
    // F013: grace added to principal.expires_at before a stream is cut. Equals the OIDC
    // clock skew so the cut uses the same leeway that accepted the token.
    int64_t g_stream_expiry_grace_sec = 60;
```

In `server_auth::init`, immediately after `g_api_prefix = params.api_prefix;`
(server-auth.cpp:507), before anything that can return early:

```cpp
    // F013: same leeway that jwt-cpp applied to exp at validation time
    g_stream_expiry_grace_sec = std::min<int64_t>(300, std::max<int64_t>(0, params.oidc_clock_skew));
```

Implementations (place them together, after `identity_headers()`):

```cpp
int64_t server_auth::stream_deadline(const server_auth_principal & p) {
    if (p.expires_at <= 0) {
        return 0;  // no expiry: api key, mTLS, trusted proxy, or auth disabled
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

const std::string & server_auth::sse_expired_chunk_anthropic() {
    static const std::string chunk = format_anthropic_sse(json {
        { "event", "error" },
        { "data",  format_error_response("access token expired", ERROR_TYPE_AUTHENTICATION) },
    });
    return chunk;
}
```

Notes for the coder:
- `format_oai_sse`, `format_anthropic_sse`, `format_error_response` and `error_type` all come
  from server-common.h, which server-auth.h already includes (server-auth.h:3). No new include
  is needed except `<ctime>` and `<algorithm>`, both already present in server-auth.cpp.
- The function-local statics are initialized on first use; C++11 guarantees this is
  thread-safe. Do not make them namespace-scope globals (static init order).

### 5.3 `tools/server/server-http.h` - one new field

Add to `struct server_http_res`, directly after the `next` / `is_stream()` pair (currently
lines 29-32):

```cpp
    // F013: SSE chunk written just before this stream is cut because the caller's access
    // token expired. Empty means "use server_auth::sse_expired_chunk_oai()". A producer
    // whose SSE dialect differs (Anthropic) sets it at response-construction time.
    std::string sse_expired_chunk;
```

It is a plain data member with an empty default; `server_http_res` is not an aggregate-
initialized type at any call site (all producers do `make_unique<...>()` then assign fields), so
adding a member is source-compatible everywhere.

--------------------------------------------------------------------------------
## 6. Call sites in existing files (exhaustive - do not add any others)

### 6.1 `tools/server/server-http.cpp`, `process_handler_response` (line 598)

Two edits inside the `if (response->is_stream())` branch.

(a) Compute the deadline **before** `request` is moved into `q_ptr` (currently line 606):

```cpp
        // F013: deadline after which no further chunk may be written (0 = principal never expires)
        const int64_t auth_deadline = server_auth::stream_deadline(request->principal);
        std::shared_ptr<server_http_req> q_ptr = std::move(request);
```

(b) Capture it by value and gate the provider (currently line 609). The gate is the FIRST
statement of the lambda body:

```cpp
        const auto chunked_content_provider = [response = r_ptr, auth_deadline](size_t, httplib::DataSink & sink) -> bool {
            if (server_auth::stream_expired(auth_deadline)) {
                // F013: the caller's access token expired mid-stream. Emit one SSE error
                // event (same convention as other mid-stream errors) and close.
                const std::string & chunk = response->sse_expired_chunk.empty()
                    ? server_auth::sse_expired_chunk_oai()
                    : response->sse_expired_chunk;
                sink.write(chunk.data(), chunk.size());
                sink.done();
                SRV_INF("%s", "auth: access token expired mid-stream, terminating stream\n");
                return false;
            }
            std::string chunk;
            const bool has_next = response->next(chunk);
            ... unchanged ...
        };
```

Capture `auth_deadline` **by value** (an `int64_t`); do not capture `q_ptr` or the principal.
The log line carries no subject, path, token or header value (CLAUDE.md: no secrets in logs).
The return value of `sink.write` is deliberately ignored - if the peer is already gone the
stream ends either way.

No other change to server-http.cpp. The non-stream branch (line 630) is untouched.

### 6.2 `tools/server/server-context.cpp`, `handle_completions_impl`

One statement, immediately after `res->content_type = "text/event-stream";` (line 4246) and
before `res->set_next(...)`:

```cpp
        if (res_type == TASK_RESPONSE_TYPE_ANTHROPIC) {
            // F013: cut this stream with an Anthropic-dialect error event
            res->sse_expired_chunk = server_auth::sse_expired_chunk_anthropic();
        }
```

`server_auth::` is reachable: server-context.cpp includes server-http.h, which includes
server-auth.h. Do NOT touch the `set_next` lambda, the `format_error` helper, or the generation
loop in any way.

### 6.3 Files deliberately NOT touched

`server-models.cpp`, `server-tools.cpp`, `server-stream.cpp`, `server.cpp`, `common/arg.cpp`,
`common/common.h`, `tools/server/tests/utils.py`. There is no new flag, so nothing to thread
into `ServerProcess`.

--------------------------------------------------------------------------------
## 7. Scope decisions and accepted residuals

| Case | Behavior | Rationale |
|---|---|---|
| `principal.expires_at == 0` (API key, mTLS, trusted proxy, auth disabled) | **Never cut.** `stream_deadline` returns 0 and `stream_expired(0)` is always false. | These methods carry no expiry; cutting them would be a regression with no security gain. This is a REQUIRED acceptance criterion. |
| Opaque token via RFC-7662 introspection (F010b) | Covered automatically, no F013 change, as soon as F010b sets `expires_at` from the introspection `exp` (docs/design/pr5-optional.md section 3). If introspection returns no `exp`, `expires_at` stays 0 and the stream is not cut - the short positive-cache TTL is the control there. | the gate keys off `expires_at`, never off `method` |
| Non-streaming long generation whose token expires mid-generation | **Not cut.** Standard resource-server semantics: one request, authorized once at entry, one response delivered at the end. There is no open-ended data feed to stop. | documented residual; revisit only if a threat model demands it |
| Idle stream (no chunk produced) past the deadline | Connection stays open until the next chunk, `should_stop`, or the HTTP timeout. No data crosses the deadline. | matches the stated property in section 0; a watchdog thread is out of scope |
| `server_res_spipe::on_complete()` background drain (server-stream.cpp:631-653) | **Not gated.** After the cut, if `X-Conversation-Id` was set, generation continues into the replay ring buffer. Those bytes are only readable via `GET /v1/stream`, which is a fresh request that goes through `authorize_request` (and through this same gate) with a fresh token. | no unauthorized delivery; gating it would require threading the deadline into `server_res_spipe`, a second existing-file change for no security gain. Open question OQ3. |
| Wall-clock jump (NTP) | A backward jump delays the cut, a forward jump cuts early. Accepted: `exp` is defined in unix time and jwt-cpp validates it against `system_clock`, so using the same clock is the only self-consistent choice. | no monotonic-clock alternative exists for comparing against `exp` |
| HTTP status on cut | stays 200 (headers already sent); 401 appears only inside the SSE error payload. | same as every existing mid-stream error |
| Audit line on cut | **None in F013.** Only a non-identifying `SRV_INF`. `server_http_req` has no `method` field, so an `audit_emit` line would have to carry `method: ""`, and adding an audit field would break F006's "exactly nine fields" criterion. | Open question OQ2 |

--------------------------------------------------------------------------------
## 8. Fail-closed summary

| Condition | Behavior |
|---|---|
| `expires_at > 0` and clock past `expires_at + grace` | stream cut before the next chunk is written |
| `expires_at > 0`, token accepted inside the clock-skew window | not cut instantly: the grace equals that same skew, so at least the skew window of streaming remains |
| `expires_at == 0` | never cut (explicitly, not accidentally) |
| `server_auth::init` not called / auth disabled | `g_stream_expiry_grace_sec` keeps its default 60 and every principal has `expires_at == 0`, so the gate is inert |
| A new upstream streaming route appears after a rebase | inherits the gate automatically (single choke point), no silent post-expiry feed |
| `sse_expired_chunk` left empty by a producer | falls back to the OAI-dialect error event, never to a silent close |

--------------------------------------------------------------------------------
## 9. Test strategy (acceptance criteria are in features.json F013)

All tests belong in `tools/server/tests/unit/test_oidc.py`, which already has a mock IdP, a
`_mint(...)` helper taking `exp_delta`, and a `server.oidc_clock_skew` knob (test_oidc.py:186,
247, 335). Negative cases first.

1. **Cut happens** - `--oidc-clock-skew 0`, token `exp_delta=4`, streaming
   `POST /v1/chat/completions` with a large `n_predict` so generation runs well past 4 s.
   Assert: the raw response text contains the exact OAI expiry chunk, does NOT contain
   `data: [DONE]`, and the stream ends within ~ (4 s + `sse_ping_interval` + slack).
2. **No false positive** - same server, token `exp_delta=300`, same streaming request runs to a
   normal `data: [DONE]` termination with no error chunk.
3. **`expires_at == 0` is never cut** - API-key-only server (no OIDC), a long streaming
   completion runs to `data: [DONE]`. This is the most important regression guard.
4. **Skew consistency** - `--oidc-clock-skew 60`, token minted with `exp_delta=-30` (accepted
   under leeway): the stream produces at least one real content chunk and is not cut
   immediately at the first provider invocation.
5. **Anthropic dialect** - streaming `POST /v1/messages` with an expiring token yields the exact
   `event: error` chunk, not the OAI form.
6. **Code inspection (reviewer, not pytest)** - the F013 code path in server-auth.cpp contains
   no reference to `AUTH_OIDC`, `p.method`, or any auth-method name; and the only existing-file
   edits are the three described in section 6.

--------------------------------------------------------------------------------
## 10. Open questions for the challenger

- **OQ1 (dialect coverage).** The default expiry chunk is the OAI form. `/v1/responses`
  (`TASK_RESPONSE_TYPE_OAI_RESP`) speaks the `event:`/`data:` dialect (`format_oai_resp_sse`)
  but the *existing* mid-stream `format_error` already sends it the plain OAI form, so F013
  mirrors that. Is inheriting that inconsistency correct, or should F013 fix it (which would
  mean touching a path F013 otherwise leaves alone)?
- **OQ2 (audit).** No audit line is written when a stream is cut, only a non-identifying
  `SRV_INF`. Is that acceptable observability for a security-relevant termination, or is an
  audit line required? An audit line needs either a `method` field on `server_http_req` or an
  audit-schema change that conflicts with F006's "exactly nine fields" criterion.
- **OQ3 (spipe drain).** After a cut, `server_res_spipe::on_complete()` keeps draining
  generation into the replay ring buffer, consuming a slot on behalf of an expired principal.
  Replay requires a freshly authorized `GET /v1/stream`, so nothing is delivered - but is the
  continued *resource consumption* on an expired token acceptable, or should the drain be gated
  too (second existing-file change)?
- **OQ4 (grace source).** `grace = clamp(oidc_clock_skew, 0, 300)` couples a generic mechanism
  to an OIDC-named flag. Is that acceptable, or is a separate `--auth-stream-expiry-grace` flag
  worth the CLI surface? (The design says no: consistency with initial validation matters more
  than naming, and a second knob invites the two from drifting apart.)
- **OQ5 (idle streams).** An idle stream past its deadline stays connected until the next chunk.
  Is "no data after the deadline" a sufficient property, or is "no *connection* after the
  deadline" required (which would need a watchdog thread or a shorter poll)?

--------------------------------------------------------------------------------
## 11. Challenger revisions (BINDING - these override any conflicting text above)

Applied after the adversarial design-challenge pass. Where sections 0-10 conflict, THIS section
wins. The coder implements section 11 as written; sections 2-6 remain the narrative contract only
where section 11 is silent. Every anchor below was re-verified against the working tree at the
time of writing; the coder MUST still re-grep.

### 11.0 Anchor corrections and confirmations

| Design text says | Verified reality |
|---|---|
| `process_handler_response` is the single choke point (server-http.cpp:598) | CONFIRMED. `set_chunked_content_provider` appears exactly once in `tools/server` (server-http.cpp:629) and `process_handler_response` has exactly three callers (server-http.cpp:655/706/727). |
| `request->principal` is in scope there | CONFIRMED. Set at server-http.cpp:653/704/725 from `server_auth::principal_at_construction()`, which returns the request-scoped `thread_local t_principal` (server-auth.cpp:58/1330). |
| `expires_at` is only ever written by the OIDC branch | CONFIRMED. `p.expires_at = v.expires_at` at server-auth.cpp:1152 is the ONLY assignment outside the default member initializer (server-auth.h:54). mTLS, trusted-proxy, API-key and anonymous principals all leave it at 0. |
| `t_principal` is assigned before every early return in `authorize_request` | CONFIRMED. `t_principal = p` at server-auth.cpp:1226 precedes the public-route short-circuit (:1264) and the F011 `g_public_endpoints` short-circuit (:1270). |
| six SSE producers | CONFIRMED as the set of `next` assignments: server-context.cpp:4247, server-models.cpp:1719, server-models.cpp:2073, server-stream.cpp:487, server-tools.cpp:1302, plus the spipe tee at server-stream.cpp:655. |
| `params.sse_ping_interval` bounds the completions staleness window | **WRONG.** See 11.4. |
| `server_http_proxy` is "the streaming path for router mode" | **UNDERSTATED and it is a blocker.** `server_http_proxy` sets `next` unconditionally (server-models.cpp:2073), so in router mode EVERY proxied response is `is_stream()`, including non-streaming `application/json` bodies. See 11.2. |
| `format_error_response(..., ERROR_TYPE_AUTHENTICATION)` yields `{"code":401,"message":...,"type":"authentication_error"}` | CONFIRMED, server-common.cpp:17-58, key order `code, message, type`. |
| `server_http_res` gains a member safely | CONFIRMED, it has virtual members so it is not an aggregate and no call site brace-initializes it. (Note `server_http_req` IS brace-initialized at three sites; do NOT add fields to it.) |

### 11.1 BLOCKER B1 - the gate is placed before `next()`, so a chunk CAN be written after the deadline

Section 0 states the security property as "no SSE chunk is written to the socket at or after the
deadline". Section 6.1 as written does not deliver it. The provider body is

```
check deadline -> response->next(chunk)  [BLOCKS]  -> sink.write(chunk)
```

and `next()` blocks for an unbounded time at every producer:

- server-context.cpp:4298 `rd.next(...)` blocks until a result arrives, the caller-supplied
  `sse_ping_interval` elapses, or `should_stop`. Waiting for a free slot or processing a large
  prompt keeps it inside `next()` for minutes.
- server-models.cpp:2073 `pipe->read(msg, should_stop)` blocks until the child sends bytes, bounded
  only by `--timeout-read` (default hundreds of seconds).
- server-models.cpp:1719 `sse_client->next(...)` blocks until a model-registry event exists,
  i.e. potentially forever.
- server-stream.cpp:487 `pipe->read(...)` blocks until replay bytes arrive.
- server-tools.cpp:1302 `queue_res.recv(id)` blocks until the tool produces output.

Failure scenario: an attacker holds a token with `exp = now + 5`. It sends
`POST /v1/chat/completions` with `"stream": true` and `"sse_ping_interval": -1` (a per-request
field, server-schema.cpp:40, applied at server-context.cpp:4157) on a busy server. The gate passes
at t=0, the request sits in the queue for four minutes, `next()` then returns the first real
content chunk, and it is written at t=240 - 235 seconds past the deadline. The stated property is
violated on the very first chunk, which is the one carrying model output.

BINDING FIX: check the deadline TWICE per provider invocation - once before `next()` (so an
already-expired stream never asks the producer for more work) and once after `next()` returns and
BEFORE `sink.write` (so nothing produced before the deadline is written after it). The
post-`next()` check makes the section-0 property true by construction and makes the cadence
argument in section 3.1 sound.

### 11.2 BLOCKER B2 - in router mode the gate would inject SSE bytes into non-SSE bodies

`server_http_proxy::server_http_proxy` assigns `this->next` unconditionally (server-models.cpp:2073)
and `server_models::proxy_request` (server-models.cpp:1175) is used for EVERY request the router
forwards to a child, not just streaming ones. Therefore in router mode
`response->is_stream()` is true for `POST /v1/chat/completions` with `"stream": false`, for
`POST /v1/embeddings`, for `POST /v1/rerank`, for proxied `GET /props`, and so on. Their
`content_type` is whatever the child returned, typically `application/json; charset=utf-8`
(assigned in the proxy constructor from the first pipe message, server-models.cpp:2186-2196, i.e.
already correct by the time `process_handler_response` runs).

Failure scenario: a router-mode client posts a non-streaming embeddings request with a token that
expires during the child's compute. The gate fires and appends
`data: {"error":{"code":401,...}}\n\n` to a partially delivered JSON body. The client gets a
truncated JSON document with SSE framing glued onto it: an unparseable response, no usable error,
and a direct contradiction of acceptance criterion 13 ("non-streaming responses are unaffected"),
which silently only held in single-server mode.

BINDING FIX: the gate applies ONLY when the response is actually SSE, tested as
`response->content_type.rfind("text/event-stream", 0) == 0`. For any other content type the gate is
inert and the response is delivered normally. This is not a fail-open hole: today the only non-SSE
chunked producer is `server_http_proxy` carrying a single logical response, which section 7 already
classifies as "non-streaming, not cut". All five genuine SSE producers set
`content_type = "text/event-stream"` explicitly (server-context.cpp:4246, server-models.cpp:1718,
server-stream.cpp:479, server-tools.cpp:1299, and the proxy when the child is streaming). Record
this exhaustive list in the code comment so a rebase that adds a sixth non-SSE chunked producer is
visible in review.

### 11.3 The gate, as it must be written (replaces section 6.1 (b))

```cpp
        // F013: deadline after which no further SSE chunk may be written (0 = never expires)
        const int64_t auth_deadline = server_auth::stream_deadline(request->principal);
        std::shared_ptr<server_http_req> q_ptr = std::move(request);
        std::shared_ptr<server_http_res> r_ptr = std::move(response);

        const auto chunked_content_provider = [response = r_ptr, auth_deadline](size_t, httplib::DataSink & sink) -> bool {
            // F013: only SSE responses are gated. In router mode server_http_proxy sets next()
            // unconditionally, so non-streaming JSON bodies are also "streams" here; writing SSE
            // framing into those would corrupt them. Producers that are really SSE all set this
            // content type: server-context.cpp (completions/chat/infill/responses/messages),
            // server-models.cpp (/models/sse), server-stream.cpp (GET /v1/stream),
            // server-tools.cpp (tool stream), and the proxy when the child streams.
            const bool auth_gated = auth_deadline > 0 &&
                response->content_type.rfind("text/event-stream", 0) == 0;
            const auto cut = [&]() -> bool {
                const std::string & chunk = response->sse_expired_chunk.empty()
                    ? server_auth::sse_expired_chunk_oai()
                    : response->sse_expired_chunk;
                sink.write(chunk.data(), chunk.size());
                sink.done();
                response->auth_expired = true;
                SRV_WRN("auth: access token expired mid-stream, terminating stream for %s\n",
                        response->content_type.c_str());
                return false;
            };
            if (auth_gated && server_auth::stream_expired(auth_deadline)) {
                return cut();
            }
            std::string chunk;
            const bool has_next = response->next(chunk);
            // F013: next() can block for an unbounded time (slot queue, proxy read, tool wait),
            // so re-check before writing: no byte may cross the deadline (B1).
            if (auth_gated && server_auth::stream_expired(auth_deadline)) {
                return cut();
            }
            if (!chunk.empty()) {
                ... unchanged ...
```

Constraints that remain binding: `auth_deadline` is captured BY VALUE as an `int64_t`; neither
`q_ptr` nor the principal is captured; the `sink.write` return value is deliberately ignored.

The log message must not carry a subject, path, token, DN or header value. `content_type` is a
server-chosen constant, not attacker-controlled data, and is included only to distinguish the
producer; a coder who prefers a fixed string may drop it. `SRV_WRN` replaces `SRV_INF`: a security
control firing is not informational (see 11.8, OQ2).

### 11.4 SHOULD-FIX S1 - `sse_ping_interval` is caller-controlled, so section 3.3's bound is false

`sse_ping_interval` is a per-request JSON field (`server-schema.cpp:40`, applied at
server-context.cpp:4157, `-1` disables pings entirely per common/arg.cpp:3652). A client that sets
`"sse_ping_interval": -1` removes the keep-alive chunk and with it the only thing that forced the
provider to return while the model was stalled.

BINDING FIX: delete the claim that the completions staleness window is bounded by
`sse_ping_interval`. The correct statement, after B1, is:

> No SSE byte crosses the deadline on any producer. The CONNECTION may remain open past the
> deadline for as long as the producer stays inside `next()`; that duration is caller-influenced
> (`sse_ping_interval`) and is not bounded by the server. This is the accepted OQ5 residual.

Section 3.3's table and features.json acceptance criterion 5 are corrected accordingly.

### 11.5 SHOULD-FIX S2 - signed overflow in `stream_deadline`

`p.expires_at + g_stream_expiry_grace_sec` is signed-integer addition on an attacker-influenced
value (`exp` comes from the token). A token with `exp` near `INT64_MAX` makes the sum overflow,
which is undefined behavior and can wrap to a negative deadline. A negative deadline makes
`stream_expired` return false, i.e. the failure direction is fail-open.

BINDING FIX:

```cpp
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
```

Add `<limits>` to server-auth.cpp if it is not already included. Also note for F010b: introspection
must set `expires_at` only from a positive integral `exp`; a float, a string, or a negative value
must leave it at 0 rather than produce a garbage deadline.

### 11.6 SHOULD-FIX S3 - do not call `server_auth::` from server-context.cpp

`server-context.cpp` belongs to the `server-context` static library (tools/server/CMakeLists.txt:5-26),
which does NOT contain `server-auth.cpp` (that is in `llama-server-impl`,
tools/server/CMakeLists.txt:38-52) and which is linked standalone by
`tests/CMakeLists.txt:163` (`target_link_libraries(test-chat PRIVATE server-context)`).
`server-context.cpp` currently contains ZERO `server_auth::` references; section 6.2 would
introduce the first one and make a previously self-contained library depend on the auth library for
symbol resolution. Whether `test-chat` breaks depends on which objects the linker pulls from the
archive - a coin flip that should not be in a security feature's diff.

BINDING FIX: build the dialect-specific chunk in place with the formatting helpers that
server-context.cpp already uses, and DELETE `server_auth::sse_expired_chunk_anthropic()` from the
section 5.1 interface (it becomes dead). Section 6.2 becomes:

```cpp
        // F013: dialect-correct chunk used if this stream is cut for token expiry
        if (res_type == TASK_RESPONSE_TYPE_ANTHROPIC) {
            res->sse_expired_chunk = format_anthropic_sse(json {
                {"event", "error"},
                {"data",  format_error_response("access token expired", ERROR_TYPE_AUTHENTICATION)},
            });
        } else if (res_type == TASK_RESPONSE_TYPE_OAI_RESP) {
            res->sse_expired_chunk = format_oai_resp_sse(json {
                {"event", "error"},
                {"data",  format_error_response("access token expired", ERROR_TYPE_AUTHENTICATION)},
            });
        }
```

`server_auth::sse_expired_chunk_oai()` stays in server-auth.cpp: it is the fallback consumed by
server-http.cpp, which is in the same library as server-auth.cpp.

### 11.7 SHOULD-FIX S4 - gate the spipe drain (this is the ANSWER to OQ3)

Section 7's rationale for leaving `server_res_spipe::on_complete()` alone is "Replay requires a
freshly authorized `GET /v1/stream`, so nothing is delivered". Verified against the code, that
rationale is wrong in two ways:

1. `stream_session_manager` keys sessions on the client-supplied conversation id ALONE
   (server-stream.cpp:57, :235, :257). Nothing binds a session to the principal that created it.
   `GET /v1/stream?conv_id=...` (server-stream.cpp:459-466) authorizes the CALLER but never checks
   that the caller is the OWNER. So the bytes generated after the cut are retrievable by any
   principal that holds `/v1/stream` permission and knows or guesses the id - not only by the
   original user with a refreshed token. This is a pre-existing IDOR that F013 does not introduce,
   but it does invalidate the "nothing is delivered" argument.
2. The resource consumption is not incidental: `on_complete()` runs the FULL generation to
   completion (server-stream.cpp:640-652, `while (!spipe->is_cancelled())`), holding a slot on
   behalf of a principal the server has just decided is no longer authorized. "Fail closed" in
   CLAUDE.md is not satisfied by "we keep computing for the expired principal but promise not to
   hand it over".

BINDING FIX (small, reuses existing machinery):

- `tools/server/server-http.h`: add `bool auth_expired = false;` to `server_http_res`, next to the
  new `sse_expired_chunk`.
- `tools/server/server-http.cpp`: the `cut()` helper in 11.3 sets `response->auth_expired = true;`
  before returning (already shown).
- `tools/server/server-stream.cpp`, at the top of `server_res_spipe::on_complete()` (currently
  line 631), before the `next_orig` check:

```cpp
    // F013: the caller's access token expired mid-stream. Do not keep generating on behalf of
    // an expired principal, and do not leave the partial output discoverable for replay.
    if (auth_expired) {
        g_stream_sessions.evict_and_cancel(server_stream_conv_id_from_headers(req->headers));
        return;
    }
```

`evict_and_cancel` (server-stream.cpp:291) is the same path `DELETE /v1/stream` already uses
(server-stream.cpp:570), so this reuses a tested cancellation route rather than inventing one.
`req` is still alive: the httplib `on_complete` lambda holds the request `shared_ptr` and calls
`response->on_complete()` before resetting it (server-http.cpp:624-628).

ACCEPTED RESIDUAL that must be written into section 7: in ROUTER mode this fix has no effect on
the child. The router cuts the proxy stream, but the child process owns the spipe session and never
saw the token, so the child keeps generating into its own replay buffer until the generation ends.
Stopping that would require the router to issue `DELETE /v1/stream` to the child on cut; that is
deliberately out of F013 scope. File it, do not silently drop it.

SEPARATE FEATURE (do not fold into F013): bind stream sessions to the creating principal's subject
and reject `GET /v1/stream` / `POST /v1/streams/lookup` / `DELETE /v1/stream` from a different
subject. Without it, conversation ids are bearer capabilities across users.

### 11.8 Answers to OQ1-OQ5 (binding)

- **OQ1 (`/v1/responses` dialect): FIX IT, do not inherit the inconsistency.** A frame with only a
  `data:` line has SSE event type `message`; a Responses-API client dispatches on the event name
  and will drop it, so for `/v1/responses` the "error event" degrades into exactly the silent
  truncation section 4 argues against. The fix costs two lines in the edit section 6.2 already
  makes (see 11.6) and touches no other code. The pre-existing inconsistency in the completions
  `format_error` helper is NOT fixed by F013 and stays out of scope.
- **OQ2 (audit): NO audit line in F013 - confirmed - but upgrade the log and file the follow-up.**
  `audit_emit` is file-static in server-auth.cpp and its nine fields are an F006 acceptance
  criterion; more importantly `server_http_req` carries neither `method` nor the `request_id`
  generated at server-auth.cpp:1208, so an audit line emitted here could not be correlated with the
  allow decision it revokes - it would be a ninth-field-breaking line with no investigative value.
  Binding: use `SRV_WRN` (not `SRV_INF`), and file a separate feature "audit stream lifecycle
  events" that plumbs `request_id` onto `server_http_req` and adds an `event` field to the audit
  schema. Do not attempt it inside F013.
- **OQ3 (spipe drain): GATE IT.** See 11.7. The "nothing is delivered" premise is false (no owner
  binding on conversation ids) and continuing to burn a slot for an expired principal contradicts
  the fail-closed rule.
- **OQ4 (grace source): KEEP `--oidc-clock-skew`, no new flag.** The grace must equal the leeway
  that ACCEPTED the token, otherwise authorize and cut contradict each other. For F010b that leeway
  is also `g_oidc_clock_skew`: docs/design/pr5-optional.md section 8.1 makes the introspection
  response's clock check `exp + g_oidc_clock_skew <= now -> DENY`. So the flag is already the
  single skew constant for both methods and is not OIDC-JWKS-specific in practice. A second knob
  would only create the drift it is meant to avoid. Keep the local clamp to `[0, 300]`, since
  `server_oidc::init` (server-oidc.cpp:460) only range-validates when OIDC is configured. Revisit
  only if a future method arrives with its own, different validation leeway.
- **OQ5 (idle streams): ONCE-PER-CHUNK IS SUFFICIENT - but only with the B1 fix, and the stated
  bound must be corrected.** With checks on both sides of `next()`, the property "no SSE byte at or
  after the deadline" holds exactly, with no watchdog thread and no timer. What is NOT bounded is
  how long the connection stays open with no data, because the producer can sit in `next()` for an
  unbounded, partly caller-controlled time (11.4). Accept that residual explicitly: F013 guarantees
  "no data after the deadline", not "no connection after the deadline". A watchdog stays out of
  scope; if a threat model later demands connection teardown, the right lever is httplib's
  read/write timeouts plus a bounded `sse_ping_interval`, not a new thread.

### 11.9 Answers to the four directed checks

1. **`expires_at == 0` in ALL codepaths: HOLDS, verified.** `expires_at` has exactly one
   assignment outside its default initializer (server-auth.cpp:1152, OIDC), so API-key, mTLS,
   trusted-proxy, anonymous and auth-disabled principals all reach the gate with 0. There is only
   ONE gate, so there is no second codepath that could compute a deadline differently - including
   router mode: `server_http_proxy` responses are served by the same
   `chunked_content_provider`, and `request->principal` is populated for router routes by the same
   `post()`/`get()` registration (server-http.cpp:653/704/725). The GCP `/predict` fan-out
   (server-http.cpp:884-893) copies `req.principal` into each internal request and forces
   `stream = false`, so it never reaches the gate. With 11.5 applied, no arithmetic path can turn a
   zero or garbage `expires_at` into a live deadline.
2. **Stale-principal race: NONE, in either direction.** `principal_at_construction()` returns a
   const reference to `t_principal`, and `request->principal = ...` (server-http.cpp:653/704/725)
   immediately deep-copies it into the request. Nothing retains a reference to the thread_local.
   The deadline is then computed from that copy and captured by value as an `int64_t`, so the
   lambda holds no reference to any principal at all. The ordering is fixed by httplib:
   `set_pre_routing_handler` runs `reset_principal()` then `middleware_authz` (which assigns
   `t_principal` at server-auth.cpp:1226) on the same connection thread before routing dispatches
   to the handler, and `process_handler_response` runs on that same thread. A worker thread reused
   for the next request re-enters `reset_principal()` first, and even if it did not, the in-flight
   stream's `auth_deadline` is an immutable stack copy. Binding constraint restated: capture by
   value, never capture `q_ptr` or a `server_auth_principal &`.
3. **Connection held open with no chunk: YES, this is possible and is the accepted residual.** A
   caller can send `"sse_ping_interval": -1` and a request that stalls (queued behind other slots,
   or a `/models/sse` subscription with no events, or a tool stream that never produces), leaving
   the producer inside `next()` indefinitely with the deadline long past. No data crosses the
   deadline (with B1 applied), only the socket stays up, bounded by nothing except
   `--timeout-read` / `--timeout-write` (server-http.cpp:209-210) and the client. Documented, not
   fixed. Correct section 3.3 accordingly (11.4).
4. **Token already past `exp` at stream start: CONSISTENT, with one one-second boundary note.**
   jwt-cpp validates with `.leeway(g_oidc_clock_skew)` (server-oidc.cpp:631) and
   `g_oidc_clock_skew = params.oidc_clock_skew` (server-oidc.cpp:464) after a `[0,300]` range check
   that refuses to start the server outside that range (server-oidc.cpp:460-462). The gate's grace
   is `clamp(params.oidc_clock_skew, 0, 300)`, i.e. the same number, so a token accepted at
   `exp - k` for `k <= skew` streams for at least `skew - k` more seconds. The only rough edge is
   the boundary: jwt-cpp accepts while `now <= exp + leeway`, whereas `stream_expired` cuts at
   `now >= deadline`, so a token accepted in its final second is cut on its first provider
   invocation with an error event rather than a 401. That is the fail-closed direction and is
   acceptable; it does mean the "skew consistency" test must mint a token comfortably inside the
   window (e.g. `exp = now - 5` with `--oidc-clock-skew 60`), not at its edge.

### 11.10 CONSIDER-level findings (not binding, record the decision)

- **C1 - F011 public endpoints.** `t_principal` is assigned before the `g_public_endpoints`
  short-circuit (server-auth.cpp:1226 vs :1270), so a route an operator has explicitly made public
  still gets cut if the caller happens to present an expiring bearer token. Security-neutral
  (nothing is protected there anyway) but an availability surprise. Either accept and document, or
  skip the gate when the route was public. Recommendation: accept and document - a caller that
  presents a token is asking to be treated as that principal.
- **C2 - rebase fragility of the choke point.** The "new upstream streaming endpoint inherits the
  check automatically" guarantee is enforced by nothing but the fact that
  `set_chunked_content_provider` currently appears once. Unlike the route table there is no startup
  assertion, and there cannot easily be one. Cheapest real guard: a comment at server-http.cpp:629
  stating the invariant, plus a one-line check in the test suite or CI that
  `grep -c set_chunked_content_provider tools/server` equals 1. An alternative structure that would
  be robust by construction - wrapping `response->next` itself instead of gating the provider - was
  considered and rejected as more surprising for a Haiku-class coder, but it is the right move if a
  future upstream adds a second streaming mechanism.
- **C3 - reverse proxy (PLAN.md variant B) cannot do this.** Worth stating explicitly in section 2
  so the in-tree cost is justified: oauth2-proxy, nginx `auth_request` and Envoy ext_authz all
  authorize once per request and none of them re-evaluate a token mid-response-body. Mid-stream
  expiry is genuinely not delegable, unlike most of the auth surface.
- **C4 - simplification actually taken.** With 11.6 applied the feature is: two functions in
  server-auth.{h,cpp} (`stream_deadline`, `stream_expired`, plus one cached OAI chunk string), two
  plain data members on `server_http_res`, one gate in `process_handler_response`, one
  `if/else if` in server-context.cpp, and a four-line early return in server-stream.cpp. There is no
  smaller version that still satisfies the section-0 property across router mode; dropping the SSE
  error event entirely would remove roughly a third of it at the cost of making every cut
  indistinguishable from a truncation, which is not worth it.
