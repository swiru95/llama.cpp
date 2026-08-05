import json
import os
import tempfile
import http.client
import pytest
from utils import *

# PR2 F006: audit log. One JSON-lines record per authn/authz decision, minus
# matched-PERM_PUBLIC allows. No secrets. Newline/UTF-8 safe (json escaping).
# Fail-open: an audit problem never turns a correct decision into a 500.

AUDIT_FIELDS = {"ts", "subject_hash", "method", "path", "decision",
                "required_perm", "auth_method", "peer_ip", "request_id"}

TEST_KEY = "sk-audit-secret"


def _audit_server(api_key=None, trusted_proxies=None):
    server = ServerPreset.tinyllama2()
    fd, path = tempfile.mkstemp(suffix=".jsonl", prefix="audit_")
    os.close(fd)
    os.unlink(path)  # let the server create it fresh (append mode)
    server.auth_audit_log = path
    server.api_key = api_key
    server.auth_trusted_proxies = trusted_proxies
    server._audit_path = path
    return server


def _read_audit_lines(server) -> list:
    with open(server._audit_path) as f:
        return [json.loads(line) for line in f if line.strip()]


def _raw_get(server, raw_path: str, api_key: str | None = None) -> int:
    # http.client sends the literal target bytes (requests would normalize them).
    conn = http.client.HTTPConnection(server.server_host, server.server_port, timeout=10)
    conn.putrequest("GET", raw_path, skip_host=False, skip_accept_encoding=True)
    conn.putheader("Host", f"{server.server_host}:{server.server_port}")
    if api_key:
        conn.putheader("Authorization", f"Bearer {api_key}")
    conn.endheaders()
    resp = conn.getresponse()
    status = resp.status
    resp.read()
    conn.close()
    return status


def test_audit_records_deny_and_allow_with_all_fields():
    server = _audit_server(api_key=TEST_KEY)
    try:
        server.start()
        assert server.make_request("GET", "/props").status_code == 401  # deny
        assert server.make_request("GET", "/props", headers={
            "Authorization": f"Bearer {TEST_KEY}"}).status_code == 200   # allow
    finally:
        server.stop()
    lines = _read_audit_lines(server)
    decisions = [r["decision"] for r in lines if r["path"] == "/props"]
    assert "deny" in decisions and "allow" in decisions
    for r in lines:
        assert AUDIT_FIELDS.issubset(r.keys()), f"missing fields in {r}"
    os.unlink(server._audit_path)


def test_public_health_not_audited():
    server = _audit_server(api_key=TEST_KEY)
    try:
        server.start()
        for _ in range(5):
            server.make_request("GET", "/health")
        server.make_request("GET", "/v1/health")
    finally:
        server.stop()
    lines = _read_audit_lines(server)
    assert all("health" not in r["path"] for r in lines), "public health routes must not be audited"
    os.unlink(server._audit_path)


def test_audit_contains_no_secrets():
    server = _audit_server(api_key=TEST_KEY)
    try:
        server.start()
        server.make_request("GET", "/props", headers={"Authorization": f"Bearer {TEST_KEY}"})
    finally:
        server.stop()
    with open(server._audit_path) as f:
        blob = f.read()
    assert TEST_KEY not in blob
    assert "Authorization" not in blob
    assert "Bearer" not in blob
    os.unlink(server._audit_path)


def test_audit_newline_injection_is_single_line():
    # a path with an encoded newline must not split the audit into two lines
    server = _audit_server(api_key=TEST_KEY)
    try:
        server.start()
        _raw_get(server, "/foo%0Abar", api_key=TEST_KEY)
    finally:
        server.stop()
    with open(server._audit_path) as f:
        raw_lines = [ln for ln in f.read().splitlines() if ln.strip()]
    for ln in raw_lines:
        json.loads(ln)  # each physical line is one valid JSON object
    assert any("foo" in ln for ln in raw_lines)
    os.unlink(server._audit_path)


def test_invalid_utf8_path_is_not_500_and_audited_once():
    # reviewer blocker regression: invalid UTF-8 path must yield the normal
    # decision code (401), not a 500, and still produce a valid audit line.
    server = _audit_server(api_key=TEST_KEY)
    try:
        server.start()
        status = _raw_get(server, "/%C0%80slots")
        assert status == 401, f"invalid-utf8 path should be 401, got {status}"
    finally:
        server.stop()
    lines = _read_audit_lines(server)  # must parse (valid JSON despite bad bytes)
    assert len(lines) >= 1
    os.unlink(server._audit_path)


def test_public_health_not_audited_in_auth_disabled_mode():
    # audit enabled but auth disabled (no key, no policy, no proxies):
    # public routes still must not flood the audit log (challenger finding 3c)
    server = _audit_server()
    try:
        server.start()
        for _ in range(5):
            server.make_request("GET", "/health")
    finally:
        server.stop()
    if os.path.exists(server._audit_path):
        lines = _read_audit_lines(server)
        assert all("health" not in r["path"] for r in lines)
        os.unlink(server._audit_path)
