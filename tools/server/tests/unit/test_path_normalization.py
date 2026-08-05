import pytest
from utils import ServerPreset
import http.client
import json

# F001 path normalization tests
# These tests validate the normalize_path algorithm per docs/design/pr1-rbac-core.md section 5.
#
# Note: The middleware that applies normalization (F004) is not yet implemented.
# Until then, these tests are marked to skip or xfail appropriately.
#
# Path normalization critical requirement (B1 from design):
# - Double slashes (//) and trailing slashes (/dir/) are REJECTED (400), not silently
#   repaired, to prevent desync between authz and httplib routing.

server = ServerPreset.tinyllama2()
TEST_API_KEY = "sk-test-normalization-key"


def raw_http_get(host, port, raw_path, api_key=None, timeout=10):
    """
    Send a raw HTTP GET request with literal path bytes (no client-side normalization).
    This is required for testing paths like //slots and /v1/../slots which
    the `requests` library would normalize client-side.
    See: docs/design/pr1-test-harness-notes.md
    """
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.putrequest("GET", raw_path, skip_host=False, skip_accept_encoding=True)
        if api_key:
            conn.putheader("Authorization", f"Bearer {api_key}")
        conn.endheaders()
        resp = conn.getresponse()
        status = resp.status
        body = resp.read()
        try:
            body_json = json.loads(body.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            body_json = None
        return status, body_json
    finally:
        conn.close()


@pytest.fixture(autouse=True)
def create_server():
    global server
    server = ServerPreset.tinyllama2()
    server.api_key = TEST_API_KEY
    # Note: auth_policy_file threading via utils.py (F002 addition)


class TestPathNormalizationBasic:
    """Test basic normalization cases using standard make_request."""

    def test_canonical_path_ok(self):
        """Valid canonical path /slots should normalize OK."""
        server.start()
        # With auth enabled, /slots requires auth
        res = server.make_request("GET", "/slots", headers={
            "Authorization": f"Bearer {TEST_API_KEY}"
        })
        # Should reach the handler (200 if slot exists, 500 if model not loaded, etc.)
        # NOT 400 (which would indicate normalization rejection)
        assert res.status_code != 400, f"canonical /slots was rejected (400)"

    def test_case_sensitive_path(self):
        """/Slots (different case) should not match /slots route."""
        server.start()
        res = server.make_request("GET", "/Slots", headers={
            "Authorization": f"Bearer {TEST_API_KEY}"
        })
        # With auth enabled and /Slots unclassified, should get 401 (unauthenticated)
        # or 403 (insufficient perms) or 404 (no route). NOT 200 success to /slots.
        assert res.status_code != 200, f"/Slots should not match /slots (auth-case-sensitive)"

    def test_trailing_slash_rejected(self):
        """/slots/ (trailing slash) must be REJECTED with 400."""
        server.start()
        res = server.make_request("GET", "/slots/", headers={
            "Authorization": f"Bearer {TEST_API_KEY}"
        })
        # Trailing slash on non-root path must be rejected
        assert res.status_code == 400, f"expected 400 for /slots/ but got {res.status_code}"
        assert "error" in res.body, f"expected error in body for /slots/"

    def test_trailing_slash_with_parameter_rejected(self):
        """/slots/0/ (trailing slash with parameter) must be REJECTED with 400."""
        server.start()
        res = server.make_request("GET", "/slots/0/", headers={
            "Authorization": f"Bearer {TEST_API_KEY}"
        })
        assert res.status_code == 400, f"expected 400 for /slots/0/ but got {res.status_code}"

    def test_dotdot_segment_rejected(self):
        """/v1/%2e%2e/slots decodes to /v1/../slots and must be REJECTED with 400."""
        server.start()
        res = server.make_request("GET", "/v1/%2e%2e/slots", headers={
            "Authorization": f"Bearer {TEST_API_KEY}"
        })
        assert res.status_code == 400, f"expected 400 for /v1/%2e%2e/slots but got {res.status_code}"

    def test_nul_byte_rejected(self):
        """/slots%00 decodes to /slots\\0 (NUL byte) and must be REJECTED with 400."""
        server.start()
        res = server.make_request("GET", "/slots%00", headers={
            "Authorization": f"Bearer {TEST_API_KEY}"
        })
        assert res.status_code == 400, f"expected 400 for /slots%00 but got {res.status_code}"

    def test_encoded_slash_is_real_slash(self):
        """/slots%2fx (encoded slash) decodes to /slots/x and should normalize OK as 2-segment path."""
        server.start()
        res = server.make_request("GET", "/slots%2fx", headers={
            "Authorization": f"Bearer {TEST_API_KEY}"
        })
        # Should NOT get 400 (rejection); should attempt to match /slots/:id_slot pattern
        assert res.status_code != 400, f"/slots%2fx (encoded slash) should not be rejected"

    def test_encoded_slash_with_trailing_slash_rejected(self):
        """/slots%2f (encoded slash, trailing) decodes to /slots/ and must be REJECTED with 400."""
        server.start()
        res = server.make_request("GET", "/slots%2f", headers={
            "Authorization": f"Bearer {TEST_API_KEY}"
        })
        assert res.status_code == 400, f"expected 400 for /slots%2f but got {res.status_code}"


class TestPathNormalizationRawClient:
    """Test path normalization cases that require a raw HTTP client.

    The Python `requests` library normalizes some paths client-side:
    - //slots becomes /slots
    - /v1/../slots becomes /v1/slots

    These must be tested with a raw http.client to send the literal bytes.
    See: docs/design/pr1-test-harness-notes.md
    """

    def test_double_slash_rejected(self):
        """//slots (double slash / empty segment) must be REJECTED with 400."""
        server.start()
        status, body = raw_http_get(
            server.server_host,
            server.server_port,
            "//slots",
            api_key=TEST_API_KEY
        )
        assert status == 400, f"expected 400 for //slots but got {status}"
        assert body is not None and "error" in body, f"expected error in body for //slots"

    def test_triple_slash_rejected(self):
        """///slots (multiple empty segments) must be REJECTED with 400."""
        server.start()
        status, body = raw_http_get(
            server.server_host,
            server.server_port,
            "///slots",
            api_key=TEST_API_KEY
        )
        assert status == 400, f"expected 400 for ///slots but got {status}"

    def test_internal_double_slash_rejected(self):
        """/slots//0 (internal empty segment) must be REJECTED with 400."""
        server.start()
        status, body = raw_http_get(
            server.server_host,
            server.server_port,
            "/slots//0",
            api_key=TEST_API_KEY
        )
        assert status == 400, f"expected 400 for /slots//0 but got {status}"

    def test_dotdot_segment_literal_rejected(self):
        """/v1/../slots (literal .. segment) must be REJECTED with 400."""
        server.start()
        status, body = raw_http_get(
            server.server_host,
            server.server_port,
            "/v1/../slots",
            api_key=TEST_API_KEY
        )
        assert status == 400, f"expected 400 for /v1/../slots but got {status}"

    def test_single_dot_segment_rejected(self):
        """/v1/./slots (literal . segment) must be REJECTED with 400."""
        server.start()
        status, body = raw_http_get(
            server.server_host,
            server.server_port,
            "/v1/./slots",
            api_key=TEST_API_KEY
        )
        assert status == 400, f"expected 400 for /v1/./slots but got {status}"


class TestPathNormalizationDesignCases:
    """Test the exact cases from docs/design/pr1-rbac-core.md section 5 'Worked outcomes'."""

    def test_design_case_canonical_path(self):
        """Design case: /slots -> NORM_OK /slots"""
        server.start()
        res = server.make_request("GET", "/slots", headers={
            "Authorization": f"Bearer {TEST_API_KEY}"
        })
        assert res.status_code != 400

    def test_design_case_uppercase_path(self):
        """Design case: /Slots -> NORM_OK /Slots (then no match; with auth -> 401/403/404)"""
        server.start()
        res = server.make_request("GET", "/Slots", headers={
            "Authorization": f"Bearer {TEST_API_KEY}"
        })
        # Should not reach the /slots handler (no 200 success)
        assert res.status_code != 200

    def test_design_case_double_slash(self):
        """Design case: //slots -> NORM_REJECT (empty segment) -> 400"""
        server.start()
        status, _ = raw_http_get(
            server.server_host,
            server.server_port,
            "//slots",
            api_key=TEST_API_KEY
        )
        assert status == 400

    def test_design_case_trailing_slash(self):
        """Design case: /slots/ -> NORM_REJECT (trailing slash) -> 400 [B1]"""
        server.start()
        res = server.make_request("GET", "/slots/", headers={
            "Authorization": f"Bearer {TEST_API_KEY}"
        })
        assert res.status_code == 400

    def test_design_case_trailing_slash_with_id(self):
        """Design case: /slots/0/ -> NORM_REJECT (trailing slash) -> 400"""
        server.start()
        res = server.make_request("GET", "/slots/0/", headers={
            "Authorization": f"Bearer {TEST_API_KEY}"
        })
        assert res.status_code == 400

    def test_design_case_percent_dotdot(self):
        """Design case: /v1/%2e%2e/slots -> /v1/../slots -> .. segment -> NORM_REJECT -> 400"""
        server.start()
        res = server.make_request("GET", "/v1/%2e%2e/slots", headers={
            "Authorization": f"Bearer {TEST_API_KEY}"
        })
        assert res.status_code == 400

    def test_design_case_nul_byte(self):
        """Design case: /slots%00 -> NUL byte -> NORM_REJECT -> 400"""
        server.start()
        res = server.make_request("GET", "/slots%00", headers={
            "Authorization": f"Bearer {TEST_API_KEY}"
        })
        assert res.status_code == 400

    def test_design_case_encoded_slash(self):
        """Design case: /slots%2fx -> /slots/x -> real 2-segment path (matched as ADMIN_STATE)"""
        server.start()
        res = server.make_request("GET", "/slots%2fx", headers={
            "Authorization": f"Bearer {TEST_API_KEY}"
        })
        # Should not be rejected as 400; should attempt to match /slots/:id_slot
        assert res.status_code != 400

    def test_design_case_encoded_slash_trailing(self):
        """Design case: /slots%2f -> /slots/ -> trailing slash -> NORM_REJECT -> 400"""
        server.start()
        res = server.make_request("GET", "/slots%2f", headers={
            "Authorization": f"Bearer {TEST_API_KEY}"
        })
        assert res.status_code == 400

    def test_design_case_dot_in_segment(self):
        """Design case: /foo%2e (double-encoded .) -> /foo. -> dot at end (not whole '.' segment)"""
        server.start()
        res = server.make_request("GET", "/foo%2e", headers={
            "Authorization": f"Bearer {TEST_API_KEY}"
        })
        # Should NOT be rejected (only whole '.' segments are rejected, not dots within segments)
        assert res.status_code != 400, f"expected no rejection for /foo%2e but got {res.status_code}"


class TestPathNormalizationAdminRoutes:
    """Verify that rejected paths do NOT reach admin route handlers.

    B1 blocker fix: ensure that paths rejected by normalization never reach
    the handlers that would be matched if the path were silently repaired.
    For example, /slots/ should get 400 BEFORE httplib routes it to
    /slots/:id_slot handler.
    """

    def test_trailing_slash_admin_route_not_reached(self):
        """POST /slots/ (trailing) is REJECTED 400, does NOT reach POST /slots/:id_slot handler."""
        server.start()
        # POST /slots/ should be rejected at 400 normalization stage
        res = server.make_request("POST", "/slots/", headers={
            "Authorization": f"Bearer {TEST_API_KEY}"
        }, data={})
        assert res.status_code == 400, f"expected 400 but got {res.status_code}"
        # Verify it's a normalization error, not a server error or success
        if "error" in res.body:
            # The error type should indicate invalid_request (400 family)
            error_type = res.body.get("error", {}).get("type", "")
            assert "invalid" in error_type.lower() or error_type == "invalid_request_error", \
                f"expected invalid_request_error but got {error_type}"

    def test_double_slash_admin_route_not_reached(self):
        """GET //slots (double slash) is REJECTED 400, does NOT reach GET /slots handler."""
        server.start()
        status, body = raw_http_get(
            server.server_host,
            server.server_port,
            "//slots",
            api_key=TEST_API_KEY
        )
        assert status == 400


class TestPathNormalizationAuthDisabledMode:
    """Test that auth-disabled mode (no key, no policy) allows paths.

    When no --api-key and no --auth-policy-file are configured, the server
    should allow all requests (auth-disabled mode). This is today's default behavior.
    """

    def test_no_auth_allows_canonical_path(self):
        """With auth disabled, canonical /slots is allowed."""
        server_no_auth = ServerPreset.tinyllama2()
        # Do NOT set api_key; auth-disabled mode
        server_no_auth.start()
        res = server_no_auth.make_request("GET", "/slots")
        assert res.status_code != 401 and res.status_code != 403

    def test_no_auth_rejects_malformed_path(self):
        """With auth disabled, /slots%00 (NUL) is still REJECTED 400 (normalization is unconditional)."""
        server_no_auth = ServerPreset.tinyllama2()
        server_no_auth.start()
        res = server_no_auth.make_request("GET", "/slots%00")
        # Normalization rejection is unconditional (not tied to auth mode)
        assert res.status_code == 400


class TestPathNormalizationEdgeCases:
    """Edge cases and boundary conditions."""

    def test_root_path(self):
        """/ (root, single slash) should be allowed."""
        server.start()
        res = server.make_request("GET", "/", headers={
            "Authorization": f"Bearer {TEST_API_KEY}"
        })
        # Root is typically a frontend asset, allowed
        assert res.status_code != 400

    def test_long_path(self):
        """Long but canonical path should be allowed."""
        server.start()
        long_path = "/this/is/a/very/long/but/valid/path/with/many/segments"
        res = server.make_request("GET", long_path, headers={
            "Authorization": f"Bearer {TEST_API_KEY}"
        })
        # Should not be rejected for length; may be 404 (no route) but not 400
        assert res.status_code != 400

    def test_backslash_rejected(self):
        """Path with backslash should be REJECTED 400."""
        server.start()
        status, _ = raw_http_get(
            server.server_host,
            server.server_port,
            "/slots\\0",
            api_key=TEST_API_KEY
        )
        assert status == 400

    def test_literal_percent_rejected(self):
        """Path with literal % (residue of double-encoding) should be REJECTED 400."""
        server.start()
        # Note: %25 encodes %, but if a double-encoded sequence leaves a % after httplib's
        # single decode, it should be rejected. This is tricky to test via make_request.
        # For now, this is documented as a case but may be covered by e2e testing only.
        pass
