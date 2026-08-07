# PR1 test-harness notes (path normalization, F001)

Empirically verified against the actual test client (`tools/server/tests/utils.py::ServerProcess.make_request`, which uses the Python `requests` library). This note is load-bearing: ignoring it produces tests that pass for the wrong reason.

## The problem: the `requests` client normalizes some adversarial paths client-side

`requests`/urllib3 rewrites the request target before it goes on the wire. Measured behavior:

| Test input path        | What actually reaches the server |
|------------------------|----------------------------------|
| `//slots`              | `GET /slots`   (leading double-slash COLLAPSED) |
| `/v1/../slots`         | `GET /slots`   (dot segments RESOLVED)          |
| `/slots/`              | `GET /slots/`  (preserved)                      |
| `/v1/%2e%2e/slots`     | `GET /v1/../slots` (percent-decoded to dots, NOT resolved -> reaches server with literal `..`) |
| `/slots%00`            | `GET /slots%00` (preserved, still encoded)      |
| `/Slots`               | `GET /Slots`   (preserved)                      |
| `/slots%2fx`           | `GET /slots%2Fx` (preserved, hex uppercased -> server decodes to `/slots/x`) |

Consequence: a test that sends `//slots` or `/v1/../slots` through `make_request` and asserts "403/400/blocked" is VACUOUS - the server only ever sees `/slots`, so the assertion tells you nothing about normalize_path. These two cases MUST use a raw client that sends the literal bytes.

## Required approach for F001 tests

Split the path-normalization cases into two groups:

1. Cases `requests` preserves (`/slots/`, `/v1/%2e%2e/slots`, `/slots%00`, `/Slots`, `/slots%2fx`, and any single-segment case): test via the normal `server.make_request(...)` for consistency with the rest of the suite.

2. Cases `requests` mangles (`//slots`, `/v1/../slots`, and any leading-`//` or unencoded-dot-segment case): test with a raw client that writes the exact request line. Use `http.client.HTTPConnection` with `putrequest(method, path, skip_host=True, skip_accept_encoding=True)` then `putheader`/`endheaders`, or a raw socket. `http.client` does NOT collapse `//` or resolve `..`, so the literal target is sent. Add a small helper to the test module (do not modify `make_request` itself for PR1).

Sketch (illustrative, coder to finalize against suite style):

```python
import http.client

def raw_get(server, raw_path, api_key=None):
    conn = http.client.HTTPConnection(server.server_host, server.server_port, timeout=10)
    conn.putrequest("GET", raw_path, skip_host=False, skip_accept_encoding=True)
    if api_key:
        conn.putheader("Authorization", f"Bearer {api_key}")
    conn.endheaders()
    resp = conn.getresponse()
    status = resp.status
    resp.read()
    conn.close()
    return status
```

Verify the raw client actually sends the literal path (e.g. `//slots` stays `//slots`) before trusting the assertions - `http.client` is known-good here but confirm in-suite.

## Expected server outcomes per the (revised) F001 design

Cross-check with the final `docs/design/pr1-rbac-core.md` section 5, but the intent after the challenger's B1 fix is:

- `//slots` (empty path segment)        -> normalize REJECT -> HTTP 400
- `/v1/../slots` (literal `..` segment)  -> REJECT -> 400
- `/v1/%2e%2e/slots` -> reaches server as `/v1/../slots` -> `..` segment -> REJECT -> 400
- `/slots/` (trailing slash, non-root)   -> REJECT -> 400  (prevents the `POST /slots/` -> `/slots/:id_slot` matcher-desync bypass)
- `/slots%00` -> reaches server as `/slots%00`; httplib decodes to `/slots\0`; NUL byte -> REJECT -> 400
- `/Slots` -> not the `/slots` route; with auth enabled, deny-by-default (401 anon) then httplib 404 for an authenticated caller; must NOT reach the real `/slots` handler
- `/slots%2fx` -> httplib decodes to `/slots/x` -> a real 2-segment path, matched as such (not a bypass)

The must-not-happen assertion for each: none of these reach the `/slots` (or `/slots/:id_slot`) handler with a 2xx. Assert the specific status where the design fixes it (400), and separately assert the admin handler did not run.
