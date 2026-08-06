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


def test_distinct_request_ids_on_each_audit_line():
    # Catch hoisting error in lazy request_id generation: each audit line must have unique ID
    server = _audit_server(api_key=TEST_KEY)
    try:
        server.start()
        # Make two requests that will be audited
        server.make_request("GET", "/props")
        server.make_request("GET", "/props")
    finally:
        server.stop()
    lines = _read_audit_lines(server)
    request_ids = [r["request_id"] for r in lines if r["path"] == "/props"]
    assert len(request_ids) >= 2, f"expected at least 2 audit lines, got {len(request_ids)}"
    assert len(set(request_ids)) == len(request_ids), f"request_ids should be distinct, got {request_ids}"
    os.unlink(server._audit_path)


def test_auth_disabled_with_audit_produces_allow_for_non_public():
    # auth disabled (no api key, no policy) but audit enabled.
    # hit a non-public route, verify: subject_hash="anonymous", auth_method="none", decision="allow"
    server = _audit_server()
    try:
        server.start()
        # /props is not a public route (requires READ_STATE permission)
        status = server.make_request("GET", "/props").status_code
        assert status == 200, f"auth-disabled mode should allow /props, got {status}"
    finally:
        server.stop()
    if os.path.exists(server._audit_path):
        lines = _read_audit_lines(server)
        props_lines = [r for r in lines if r["path"] == "/props"]
        assert len(props_lines) > 0, "expected at least one audit line for /props"
        line = props_lines[0]
        assert line["subject_hash"] == "anonymous", f"expected subject_hash='anonymous', got {line['subject_hash']}"
        assert line["auth_method"] == "none", f"expected auth_method='none', got {line['auth_method']}"
        assert line["decision"] == "allow", f"expected decision='allow', got {line['decision']}"
        os.unlink(server._audit_path)


def test_sha256_known_answer():
    # Known-answer check end-to-end using LLAMA_AUTH_AUDIT_SALT env var
    import hashlib
    server = _audit_server(trusted_proxies="127.0.0.1/32")
    known_salt = "fixed-test-salt"
    known_subject = "testsubject@example.com"
    try:
        # Set the auth audit salt via environment variable
        os_env = os.environ.copy()
        os_env["LLAMA_AUTH_AUDIT_SALT"] = known_salt
        server.start(env=os_env)
        # Make request with trusted proxy and X-Auth-Subject header
        headers = {
            "X-Auth-Subject": known_subject,
            "X-Forwarded-For": "127.0.0.1"
        }
        server.make_request("GET", "/props", headers=headers)
    finally:
        server.stop()
    if os.path.exists(server._audit_path):
        lines = _read_audit_lines(server)
        props_lines = [r for r in lines if r["path"] == "/props"]
        assert len(props_lines) > 0, "expected at least one audit line for /props"
        line = props_lines[0]
        # Calculate the expected hash using Python's hashlib
        expected_hash = hashlib.sha256((known_subject + known_salt).encode()).hexdigest()
        assert line["subject_hash"] == expected_hash, \
            f"SHA-256 mismatch: expected {expected_hash}, got {line['subject_hash']}"
        os.unlink(server._audit_path)
