import os
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from utils import *

server = ServerPreset.tinyllama2()


@pytest.fixture(autouse=True)
def create_server():
    global server
    server = ServerPreset.tinyllama2()


def test_mcp_no_proxy():
    global server
    server.ui_mcp_proxy = False
    server.start()

    res = server.make_request("GET", "/cors-proxy")
    assert res.status_code == 403


def test_mcp_proxy():
    global server
    server.ui_mcp_proxy = True
    # F014: deny-by-default (docs/design/pr7-additional-hardening.md section 3.8) - the target
    # must be explicitly allowlisted. No portspec means 80/443 only, which matches this target.
    server.proxy_allowed_hosts = "example.com"
    server.start()

    url = f"http://{server.server_host}:{server.server_port}/cors-proxy?url=http://example.com"
    res = requests.get(url)
    assert res.status_code == 200
    assert "Example Domain" in res.text


def test_mcp_proxy_no_allowlist_denied():
    # F014: with --ui-mcp-proxy on and --proxy-allowed-hosts unset, every target is denied.
    global server
    server.ui_mcp_proxy = True
    server.start()

    url = f"http://{server.server_host}:{server.server_port}/cors-proxy?url=http://example.com"
    res = requests.get(url)
    assert res.status_code == 403
    assert res.json()["error"]["type"] == "proxy_target_denied"


def test_mcp_proxy_custom_port():
    # F014 B1-b: the server's own port is a non-overridable self-target block, so this must
    # proxy to a SEPARATE local HTTP fixture rather than the server's own /models endpoint.
    class ModelsLikeHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"data": []}')

        def log_message(self, format, *args):
            pass

    target = ThreadingHTTPServer(("127.0.0.1", 0), ModelsLikeHandler)
    target_thread = threading.Thread(target=target.serve_forever, daemon=True)
    target_thread.start()

    try:
        global server
        server.ui_mcp_proxy = True
        server.proxy_allowed_hosts = f"127.0.0.1/32:{target.server_port}"
        server.start()

        res = server.make_request("GET", f"/cors-proxy?url=http://127.0.0.1:{target.server_port}/models")
        assert res.status_code == 200
        assert "data" in res.body
    finally:
        target.shutdown()
        target.server_close()


def test_mcp_proxy_self_target_denied():
    # F014 B1-b: proxying to the server's own listening port is always denied, even when the
    # allowlist would otherwise permit it (e.g. a wide-open ":*" entry).
    global server
    server.ui_mcp_proxy = True
    server.proxy_allowed_hosts = "127.0.0.1/32:*"
    server.start()

    res = server.make_request("GET", f"/cors-proxy?url=http://127.0.0.1:{server.server_port}/models")
    assert res.status_code == 403
    assert res.body["error"]["type"] == "proxy_target_denied"


def test_mcp_proxy_self_target_denied_with_exact_port_allowlisted():
    # F014 B1-b: the self-target block is non-overridable even when the allowlist names the
    # server's own port EXACTLY (not just via a wildcard ':*' entry).
    global server
    server.ui_mcp_proxy = True
    server.proxy_allowed_hosts = f"127.0.0.1/32:{server.server_port}"
    server.start()

    res = server.make_request("GET", f"/cors-proxy?url=http://127.0.0.1:{server.server_port}/models")
    assert res.status_code == 403
    assert res.body["error"]["type"] == "proxy_target_denied"


def test_mcp_proxy_port_scoped_allowlist_denies_other_port():
    """F014 regression guard for the reviewer-fixed BLOCKER: an allowlist entry scoped to one
    port (e.g. '127.0.0.1/32:9000') must NOT grant every port on that address. Before the fix,
    the CIDR branch of the allowlist silently discarded the portspec, so this exact
    configuration reached any service on 127.0.0.1 regardless of the port named in the flag.
    """
    class MarkerHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"marker": "reached"}')

        def log_message(self, format, *args):
            pass

    allowed_target = ThreadingHTTPServer(("127.0.0.1", 0), MarkerHandler)
    other_target = ThreadingHTTPServer(("127.0.0.1", 0), MarkerHandler)
    threading.Thread(target=allowed_target.serve_forever, daemon=True).start()
    threading.Thread(target=other_target.serve_forever, daemon=True).start()

    try:
        global server
        server.ui_mcp_proxy = True
        server.proxy_allowed_hosts = f"127.0.0.1/32:{allowed_target.server_port}"
        server.start()

        # sanity: the explicitly allowlisted port works
        res_ok = server.make_request("GET", f"/cors-proxy?url=http://127.0.0.1:{allowed_target.server_port}/")
        assert res_ok.status_code == 200

        # a DIFFERENT port on the SAME address must still be denied
        res = server.make_request("GET", f"/cors-proxy?url=http://127.0.0.1:{other_target.server_port}/")
        assert res.status_code == 403
        assert res.body["error"]["type"] == "proxy_target_denied"
    finally:
        allowed_target.shutdown()
        allowed_target.server_close()
        other_target.shutdown()
        other_target.server_close()


def test_mcp_proxy_bare_cidr_entry_allows_only_80_443():
    # F014 B1-a: an allowlist entry with NO portspec permits only ports 80/443, not
    # arbitrary ports on the allowed address.
    class OkHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, format, *args):
            pass

    target = ThreadingHTTPServer(("127.0.0.1", 0), OkHandler)
    threading.Thread(target=target.serve_forever, daemon=True).start()

    try:
        global server
        server.ui_mcp_proxy = True
        server.proxy_allowed_hosts = "127.0.0.1/32"  # no portspec
        server.start()

        res = server.make_request("GET", f"/cors-proxy?url=http://127.0.0.1:{target.server_port}/")
        assert res.status_code == 403
        assert res.body["error"]["type"] == "proxy_target_denied"
    finally:
        target.shutdown()
        target.server_close()


def test_mcp_proxy_wildcard_port_grants_any_port_and_warns_at_startup():
    # F014 B1-a: a ':*' allowlist entry grants any port on the address AND logs exactly one
    # SRV_WRN at startup naming the entry.
    class OkHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, format, *args):
            pass

    target = ThreadingHTTPServer(("127.0.0.1", 0), OkHandler)
    threading.Thread(target=target.serve_forever, daemon=True).start()

    fd, log_path = tempfile.mkstemp(suffix=".log")
    os.close(fd)

    try:
        global server
        server.ui_mcp_proxy = True
        server.proxy_allowed_hosts = "127.0.0.1/32:*"
        server.log_path = log_path
        server.start()

        with open(log_path) as f:
            log_text = f.read()
        assert "127.0.0.1/32:*" in log_text
        assert "grants all ports" in log_text

        res = server.make_request("GET", f"/cors-proxy?url=http://127.0.0.1:{target.server_port}/")
        assert res.status_code == 200
    finally:
        target.shutdown()
        target.server_close()
        os.remove(log_path)


def test_mcp_proxy_enabled_no_allowlist_warns_at_startup():
    # F014 acceptance criterion: with --ui-mcp-proxy on and --proxy-allowed-hosts unset,
    # startup must log exactly one SRV_WRN naming --proxy-allowed-hosts (without aborting).
    fd, log_path = tempfile.mkstemp(suffix=".log")
    os.close(fd)

    try:
        global server
        server.ui_mcp_proxy = True
        server.log_path = log_path
        server.start()  # must not abort

        with open(log_path) as f:
            log_text = f.read()
        assert "proxy-allowed-hosts" in log_text.lower()
    finally:
        os.remove(log_path)


def test_mcp_proxy_no_allowlist_denied_post():
    # F014: deny-by-default applies to POST as well as GET.
    global server
    server.ui_mcp_proxy = True
    server.start()

    res = server.make_request("POST", "/cors-proxy?url=http://example.com", data={})
    assert res.status_code == 403
    assert res.body["error"]["type"] == "proxy_target_denied"


def test_mcp_proxy_embedded_nul_in_host_denied():
    # F014 R-A2: req.get_param('url') percent-decodes the query string, so %00 becomes a real
    # NUL byte inside parsed_url.host. It must be rejected as a control byte before any
    # allowlist comparison or DNS resolution, not silently truncated/passed through.
    global server
    server.ui_mcp_proxy = True
    server.proxy_allowed_hosts = "example.com"
    server.start()

    url = f"http://{server.server_host}:{server.server_port}/cors-proxy?url=http://example.com%00.evil.com/"
    res = requests.get(url)
    assert res.status_code == 403
    assert res.json()["error"]["type"] == "proxy_target_denied"


def test_mcp_proxy_malformed_port_returns_403_not_500():
    # F014 R-A3: common_http_parse_url's std::stoi throws std::out_of_range for a port far
    # outside 1..65535; proxy_request must catch it and return the uniform 403, never a 500.
    global server
    server.ui_mcp_proxy = True
    server.proxy_allowed_hosts = "example.com"
    server.start()

    url = f"http://{server.server_host}:{server.server_port}/cors-proxy?url=http://example.com:99999999999/"
    res = requests.get(url)
    assert res.status_code == 403
    assert res.json()["error"]["type"] == "proxy_target_denied"


def test_mcp_proxy_redirect_not_followed_location_stripped():
    # F014 R-A4: /cors-proxy passes follow_location=false and strips the Location header, so an
    # allowlisted-but-hostile target cannot use a 3xx to steer the caller (or llama-server
    # itself) at a private/internal address via a same-origin relative redirect.
    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/secret")
            self.end_headers()

        def log_message(self, format, *args):
            pass

    target = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    threading.Thread(target=target.serve_forever, daemon=True).start()

    try:
        global server
        server.ui_mcp_proxy = True
        server.proxy_allowed_hosts = f"127.0.0.1/32:{target.server_port}"
        server.start()

        res = server.make_request("GET", f"/cors-proxy?url=http://127.0.0.1:{target.server_port}/redirect")
        assert res.status_code == 302
        assert not any(k.lower() == "location" for k in res.headers.keys())
    finally:
        target.shutdown()
        target.server_close()


def test_mcp_proxy_hostname_allowlist_still_blocks_private_resolved_address():
    # F014: a hostname allowlist entry can only ever reach PUBLIC addresses - the compiled-in
    # blocked-ranges table is layered on top even for an allowlisted hostname. 'localhost'
    # resolves to a loopback address (127.0.0.0/8 / ::1), which is blocked.
    global server
    server.ui_mcp_proxy = True
    server.proxy_allowed_hosts = "localhost"
    server.start()

    res = server.make_request("GET", "/cors-proxy?url=http://localhost/")
    assert res.status_code == 403
    assert res.body["error"]["type"] == "proxy_target_denied"


def test_mcp_proxy_trusted_headers_never_forwarded_via_proxy_header_prefix():
    # F014 B1-c: the trusted-header denylist must catch attempts smuggled through the
    # x-llama-server-proxy-header-* mechanism, not just headers sent directly. This closes the
    # PERM_PROXY -> admin escalation: a caller who can only reach /cors-proxy must not be able
    # to forge x-auth-subject/x-auth-roles/x-api-key/x-forwarded-*/x-real-ip/forwarded on the
    # outbound request. 'authorization' is deliberately NOT denylisted - forwarding it is the
    # proxy's legitimate job.
    class CaptureHeadersHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.server.captured_headers = dict(self.headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, format, *args):
            pass

    target = ThreadingHTTPServer(("127.0.0.1", 0), CaptureHeadersHandler)
    target.captured_headers = {}
    threading.Thread(target=target.serve_forever, daemon=True).start()

    try:
        global server
        server.ui_mcp_proxy = True
        server.proxy_allowed_hosts = f"127.0.0.1/32:{target.server_port}"
        server.start()

        res = server.make_request("GET", f"/cors-proxy?url=http://127.0.0.1:{target.server_port}/capture", headers={
            "x-llama-server-proxy-header-x-auth-subject": "admin",
            "x-llama-server-proxy-header-x-auth-roles": "admin",
            "x-llama-server-proxy-header-x-api-key": "sk-stolen",
            "x-llama-server-proxy-header-x-forwarded-for": "10.0.0.1",
            "x-llama-server-proxy-header-x-forwarded-host": "internal.example",
            "x-llama-server-proxy-header-x-forwarded-proto": "https",
            "x-llama-server-proxy-header-x-real-ip": "10.0.0.1",
            "x-llama-server-proxy-header-forwarded": "for=10.0.0.1",
            "x-llama-server-proxy-header-authorization": "Bearer legit",
        })

        assert res.status_code == 200
        captured = {k.lower(): v for k, v in target.captured_headers.items()}
        for denied in ["x-auth-subject", "x-auth-roles", "x-api-key", "x-forwarded-for",
                       "x-forwarded-host", "x-forwarded-proto", "x-real-ip", "forwarded"]:
            assert denied not in captured, f"{denied} must never be forwarded"
        assert captured.get("authorization") == "Bearer legit"
    finally:
        target.shutdown()
        target.server_close()
