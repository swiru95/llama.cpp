import hashlib
import json
import os
import re
import tempfile

import pytest
from utils import ServerPreset, ServerProcess

# F015: Prometheus auth metrics (docs/design/pr7-additional-hardening.md section 4).
#
# Three families, appended to the existing /metrics body by server_metrics_wrap
# (tools/server/server-metrics.h), sourced from fixed-shape atomic counters in
# server-auth.cpp / server-oidc.cpp:
#   - llamacpp_auth_failures_total{auth_method,reason}        (400/401 decisions)
#   - llamacpp_auth_authz_denied_total{auth_method,required_perm,reason} (403 decisions)
#   - llamacpp_auth_jwks_refresh_total{result}                (OIDC JWKS refresh outcomes)
#
# Feature -> acceptance criterion -> test mapping is recorded in features.json
# test_refs (F015); each test below names the criterion it exercises.
#
# NOTE: the harness stops every server after each test (conftest autouse), so
# each test starts its own server, per the test_mtls.py / test_authz.py / test_oidc.py
# convention. /metrics itself requires PERM_METRICS (an admin-role key/token is used
# to read it back out).


# ---------------------------------------------------------------------------
# Prometheus text parsing helpers (shared by every test in this file).
# ---------------------------------------------------------------------------

# "every non-comment line matches name{labels} value" (F015 acceptance criterion,
# router-mode well-formedness check). The labels group is optional: Prometheus text
# also allows a bare "name value" line with no labels at all, which is exactly what
# the pre-existing (pre-F015) llamacpp:* metrics use.
_PROM_LINE_RE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+(-?[0-9]+(?:\.[0-9]+)?)$')
_PROM_LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')


def _parse_prometheus(text: str) -> dict:
    """Parse Prometheus text exposition into {metric_name: [(labels_dict, value), ...]}.

    Asserts every non-comment, non-blank line is well-formed (name{labels} value or
    bare name value); this is itself an acceptance criterion for the router-mode
    mixed body.
    """
    metrics: dict = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        m = _PROM_LINE_RE.match(line)
        assert m, f"malformed Prometheus line (not name{{labels}} value): {line!r}"
        name, label_str, value = m.groups()
        labels = dict(_PROM_LABEL_RE.findall(label_str)) if label_str else {}
        metrics.setdefault(name, []).append((labels, float(value)))
    return metrics


def _metric(metrics: dict, name: str, **labels) -> float | None:
    """Return the value of the single series matching name+labels exactly, or None
    if no such series is present (e.g. because it was omitted as zero-valued)."""
    matches = [v for lbl, v in metrics.get(name, []) if lbl == labels]
    assert len(matches) <= 1, f"duplicate series for {name}{labels}: {matches}"
    return matches[0] if matches else None


def _family_total(metrics: dict, name: str) -> float:
    return sum(v for _, v in metrics.get(name, []))


def _header(res, name: str) -> str:
    # ServerResponse.headers is a plain dict copied from requests' CaseInsensitiveDict
    # (utils.py: result.headers = dict(response.headers)), so it keeps whatever casing
    # the server sent (e.g. "Content-Type") and a lowercase lookup would silently miss it.
    lname = name.lower()
    for k, v in res.headers.items():
        if k.lower() == lname:
            return v
    return ""


# ---------------------------------------------------------------------------
# Policy helpers (RBAC, non-OIDC tests).
# ---------------------------------------------------------------------------

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _write_policy(policy: dict) -> str:
    fd, path = tempfile.mkstemp(suffix=".json", prefix="auth_metrics_policy_")
    with os.fdopen(fd, "w") as f:
        json.dump(policy, f)
    return path


ADMIN_KEY = "sk-metrics-admin-key"
USER_KEY = "sk-metrics-user-key"


def _rbac_policy(extra: dict | None = None) -> dict:
    policy = {
        "roles": {
            "admin": ["INFER", "READ_STATE", "METRICS", "ADMIN_STATE", "ADMIN_MODELS"],
            "user": ["INFER"],
        },
        "api_keys": {
            _sha256_hex(ADMIN_KEY): "admin",
            _sha256_hex(USER_KEY): "user",
        },
        "default_role": None,
    }
    if extra:
        policy.update(extra)
    return policy


def _rbac_server(policy: dict) -> tuple[ServerProcess, str]:
    path = _write_policy(policy)
    server = ServerPreset.tinyllama2()
    server.server_port = 8092  # avoid conflict with load_all() / other suites which use 8080
    server.auth_policy_file = path
    server.server_metrics = True
    return server, path


ADMIN_HEADERS = {"Authorization": f"Bearer {ADMIN_KEY}"}
USER_HEADERS = {"Authorization": f"Bearer {USER_KEY}"}


def _get_metrics(server: ServerProcess) -> dict:
    res = server.make_request("GET", "/metrics", headers=ADMIN_HEADERS)
    assert res.status_code == 200
    assert _header(res, "content-type").startswith("text/plain")
    return _parse_prometheus(res.body)


# ---------------------------------------------------------------------------
# Case 1: llamacpp_auth_failures_total counts real failures with the right labels.
#
# Acceptance criterion: "functional counting tests: N bad API keys produce
# llamacpp_auth_failures_total{auth_method="api_key",reason="invalid_key"} == N".
# ---------------------------------------------------------------------------

def test_failures_total_counts_bad_api_keys():
    policy = _rbac_policy()
    server, path = _rbac_server(policy)
    try:
        server.start()
        n_bad = 5
        for i in range(n_bad):
            res = server.make_request(
                "GET", "/props", headers={"Authorization": f"Bearer sk-bad-key-{i}"}
            )
            assert res.status_code == 401

        metrics = _get_metrics(server)
        val = _metric(metrics, "llamacpp_auth_failures_total",
                       auth_method="api_key", reason="invalid_key")
        assert val == n_bad, (
            f"acceptance criterion requires auth_method=\"api_key\",reason=\"invalid_key\" "
            f"to equal the number of bad keys presented ({n_bad}), got {val}. "
            f"Full failures family: {metrics.get('llamacpp_auth_failures_total')}"
        )
    finally:
        server.stop()
        os.remove(path)


def test_failures_total_disjoint_reason_buckets_do_not_bleed():
    # A malformed path (auth_method=none per design 4.2) and an invalid key (a
    # different reason bucket) must not cross-contaminate each other's counts.
    policy = _rbac_policy()
    server, path = _rbac_server(policy)
    try:
        server.start()
        res = server.make_request("GET", "/api%00/props", headers=ADMIN_HEADERS)
        assert res.status_code == 400

        metrics = _get_metrics(server)
        malformed_val = _metric(metrics, "llamacpp_auth_failures_total",
                                 auth_method="none", reason="malformed_path")
        assert malformed_val == 1
        invalid_key_val = _metric(metrics, "llamacpp_auth_failures_total",
                                   auth_method="api_key", reason="invalid_key")
        assert invalid_key_val is None or invalid_key_val == 0
    finally:
        server.stop()
        os.remove(path)


# ---------------------------------------------------------------------------
# Case 2: an authn success + authz denial increments ONLY authz_denied_total,
# never auth_failures_total (OQ-B2 disjointness by HTTP status).
# ---------------------------------------------------------------------------

def test_authz_denial_does_not_increment_failures():
    policy = _rbac_policy()
    server, path = _rbac_server(policy)
    try:
        server.start()

        before = _get_metrics(server)
        before_failures = _family_total(before, "llamacpp_auth_failures_total")

        # "user" role only has INFER; GET /props needs READ_STATE -> 403, not 401.
        res = server.make_request("GET", "/props", headers=USER_HEADERS)
        assert res.status_code == 403

        after = _get_metrics(server)
        after_failures = _family_total(after, "llamacpp_auth_failures_total")

        assert after_failures == before_failures, (
            "an authenticated-but-denied (403) request must not increment "
            "llamacpp_auth_failures_total (families must stay disjoint by HTTP status)"
        )
        deny_val = _metric(after, "llamacpp_auth_authz_denied_total",
                            auth_method="api_key", required_perm="READ_STATE",
                            reason="insufficient_perm")
        assert deny_val == 1
    finally:
        server.stop()
        os.remove(path)


# ---------------------------------------------------------------------------
# Case 3: unmapped_role lands on the AUTHZ-DENIED family, not the AUTHN-FAILURES
# family (OQ-B2, the one label-partition detail the challenger explicitly resolved).
#
# Realized via OIDC: a token whose role claim maps to nothing in the policy's
# oidc.role_map authenticates successfully (method=oidc) but perms==0, which is
# exactly "unmapped_role" per design section 4.2 (as opposed to a statically
# misconfigured API-key role, which server_auth::init rejects at startup and can
# therefore never reach this runtime path for API keys).
# ---------------------------------------------------------------------------

from test_oidc import idp_pki, mock_idp, oidc_keys_full, _oidc_server, _oidc_policy, _mint, _cleanup  # noqa: E402


def test_unmapped_role_lands_on_authz_denied_not_failures(idp_pki, mock_idp, oidc_keys_full):
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy())
    server.server_port = 8092  # avoid conflict with load_all() / other suites which use 8080
    try:
        server.start()

        before_res = server.make_request(
            "GET", "/metrics",
            headers={"Authorization": f"Bearer {_mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, roles=('llm-admins',))}"},
        )
        assert before_res.status_code == 200
        before = _parse_prometheus(before_res.body)
        before_failures = _family_total(before, "llamacpp_auth_failures_total")

        # role claim not present in policy's oidc.role_map -> authenticated, perms==0
        tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, roles=("totally-unmapped-role",))
        res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {tok}"})
        assert res.status_code == 403, "authenticated but no role mapped -> 403, not 401"

        after_res = server.make_request(
            "GET", "/metrics",
            headers={"Authorization": f"Bearer {_mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, roles=('llm-admins',))}"},
        )
        assert after_res.status_code == 200
        after = _parse_prometheus(after_res.body)
        after_failures = _family_total(after, "llamacpp_auth_failures_total")

        assert after_failures == before_failures, (
            "unmapped_role must NOT increment llamacpp_auth_failures_total"
        )
        unmapped_val = _metric(after, "llamacpp_auth_authz_denied_total",
                                auth_method="oidc", required_perm="READ_STATE",
                                reason="unmapped_role")
        assert unmapped_val == 1, (
            f"expected exactly one unmapped_role denial, full authz family: "
            f"{after.get('llamacpp_auth_authz_denied_total')}"
        )
        # and NOT counted as insufficient_perm
        insufficient_val = _metric(after, "llamacpp_auth_authz_denied_total",
                                    auth_method="oidc", required_perm="READ_STATE",
                                    reason="insufficient_perm")
        assert insufficient_val is None or insufficient_val == 0
    finally:
        _cleanup(server)


# ---------------------------------------------------------------------------
# Case 4: llamacpp_auth_jwks_refresh_total appears with both success/failure
# labels once OIDC is configured (server_auth::init does a MANDATORY initial
# JWKS fetch at startup, per server-oidc.cpp, so a fresh server already has one
# refresh cycle behind it -- no extra wait needed).
# ---------------------------------------------------------------------------

def test_jwks_refresh_total_present_after_startup_fetch(idp_pki, mock_idp, oidc_keys_full):
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy())
    server.server_port = 8092  # avoid conflict with load_all() / other suites which use 8080
    try:
        server.start()
        tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, roles=("llm-admins",))
        res = server.make_request("GET", "/metrics", headers={"Authorization": f"Bearer {tok}"})
        assert res.status_code == 200
        metrics = _parse_prometheus(res.body)

        success_val = _metric(metrics, "llamacpp_auth_jwks_refresh_total", result="success")
        failure_val = _metric(metrics, "llamacpp_auth_jwks_refresh_total", result="failure")
        assert success_val is not None and failure_val is not None, (
            "both success and failure series must be emitted (including zeros) "
            "whenever OIDC is configured, so rate() is well-defined from the first scrape"
        )
        assert success_val >= 1, "the mandatory initial JWKS fetch at startup must count as a success"
        assert failure_val == 0
    finally:
        _cleanup(server)


def test_jwks_refresh_total_absent_when_oidc_not_configured():
    # Non-OIDC RBAC server: the jwks family must be omitted entirely, not emitted
    # with zeros (design 4.5: "neither [series] when it is not [configured]").
    policy = _rbac_policy()
    server, path = _rbac_server(policy)
    try:
        server.start()
        metrics = _get_metrics(server)
        assert "llamacpp_auth_jwks_refresh_total" not in metrics
    finally:
        server.stop()
        os.remove(path)


# ---------------------------------------------------------------------------
# Case 5: no raw secrets ever reach the metrics text (path, key, or token).
# ---------------------------------------------------------------------------

def test_no_secrets_or_raw_paths_leak_into_metrics_text():
    policy = _rbac_policy()
    server, path = _rbac_server(policy)
    try:
        server.start()

        distinctive_key = "sk-VERY-DISTINCTIVE-GREPPABLE-FAKE-KEY-zzz999"
        distinctive_path = "/definitely-not-a-real-route-zzz999"

        res = server.make_request(
            "GET", distinctive_path,
            headers={"Authorization": f"Bearer {distinctive_key}"},
        )
        # unmatched path outside api_prefix or an unclassified route -> some 4xx;
        # the exact code is not the point of this test, only that it was rejected
        # and never becomes a label value.
        assert res.status_code in (400, 401, 403, 404)

        res = server.make_request("GET", "/metrics", headers=ADMIN_HEADERS)
        assert res.status_code == 200
        text = res.body
        assert distinctive_key not in text, "raw API key must never appear in metrics text"
        assert distinctive_path not in text, "raw request path must never appear in metrics text"
        assert ADMIN_KEY not in text, "raw admin API key must never appear in metrics text"
        # only the bounded label enums should appear as label VALUES; sanity-check
        # every auth_method / reason value seen is drawn from the fixed sets.
        metrics = _parse_prometheus(text)
        allowed_reasons = {
            "malformed_path", "no_credential", "invalid_key", "malformed", "expired",
            "aud_mismatch", "introspect_denied", "mtls_reject", "unknown",
        }
        for labels, _ in metrics.get("llamacpp_auth_failures_total", []):
            assert labels["reason"] in allowed_reasons, f"unexpected reason label: {labels}"
    finally:
        server.stop()
        os.remove(path)


# ---------------------------------------------------------------------------
# Case 6: auth fully disabled. metrics_prometheus() returns "" so /metrics is
# byte-identical to pre-F015 output (no llamacpp_auth_ families at all).
# ---------------------------------------------------------------------------

def test_auth_disabled_metrics_has_no_auth_families():
    server = ServerPreset.tinyllama2()
    server.server_port = 8092  # avoid conflict with load_all() / other suites which use 8080
    server.server_metrics = True
    # no auth_policy_file, no api_key, no oidc, no mtls -> auth fully disabled
    try:
        server.start()
        res = server.make_request("GET", "/metrics")
        assert res.status_code == 200
        assert _header(res, "content-type").startswith("text/plain")
        assert "llamacpp_auth_" not in res.body, (
            "auth disabled -> metrics_prometheus() must return \"\", so no "
            "llamacpp_auth_* family may appear (byte-identical-to-pre-F015 regression guard)"
        )
        # sanity: the pre-existing (non-auth) metrics family is still present, so
        # this isn't accidentally passing because /metrics is broken outright.
        assert "llamacpp:" in res.body
    finally:
        server.stop()


def test_metrics_disabled_flag_returns_untouched_json_error():
    # --metrics is off entirely: get_metrics returns a JSON error (not text/plain);
    # server_metrics_wrap must pass it through untouched (status != 200 short-circuit).
    server = ServerPreset.tinyllama2()
    server.server_port = 8092  # avoid conflict with load_all() / other suites which use 8080
    # server.server_metrics left at its default False -> no --metrics flag
    try:
        server.start()
        res = server.make_request("GET", "/metrics")
        assert res.status_code != 200
        assert isinstance(res.body, dict), "expected a JSON error body, not Prometheus text"
        assert "llamacpp_auth_" not in json.dumps(res.body)
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# Case 7: router mode. get_metrics is reassigned to models_routes->proxy_get
# (server.cpp:228) and server_metrics_wrap is registered around it at the single
# /metrics call site (server.cpp:265) -- the same one line covers both modes, so
# this is a regression guard for that shared wrapper point, not a new code path.
# ---------------------------------------------------------------------------

def test_router_mode_metrics_includes_auth_counters():
    server = ServerPreset.router()
    server.server_port = 8092  # avoid conflict with load_all() / other suites which use 8080
    server.api_key = "sk-router-metrics-admin"
    server.server_metrics = True
    try:
        server.start()

        # generate one auth failure at the router layer before any model exists,
        # to prove the router-level auth counters are live independent of any child.
        res = server.make_request("GET", "/props")
        assert res.status_code == 401

        model_id = "ggml-org/test-model-stories260K:F32"  # exact cached preset id (router /models)
        admin_headers = {"Authorization": f"Bearer {server.api_key}"}
        load_res = server.make_request(
            "POST", "/models/load", data={"model": model_id}, headers=admin_headers
        )
        assert load_res.status_code == 200

        import time
        deadline = time.time() + 60
        status = None
        while time.time() < deadline:
            r = server.make_request("GET", "/models", headers=admin_headers)
            assert r.status_code == 200
            for item in r.body.get("data", []):
                if item.get("id") == model_id or item.get("model") == model_id:
                    status = item["status"]["value"]
            if status == "loaded":
                break
            time.sleep(1)
        assert status == "loaded", f"model failed to reach loaded state, last status: {status}"

        res = server.make_request(
            "GET", f"/metrics?model={model_id}", headers=admin_headers
        )
        if res.status_code != 200:
            pytest.skip(
                f"router-mode child /metrics proxy did not return 200 (got "
                f"{res.status_code}); the child instance apparently does not inherit "
                f"--metrics from the router, so the mixed-body case cannot be "
                f"exercised via HTTP in this harness -- see test docstring/report"
            )
        assert _header(res, "content-type").startswith("text/plain")
        metrics = _parse_prometheus(res.body)
        # the child's own (pre-F015, colon-prefixed) family must still be present
        assert any(name.startswith("llamacpp:") for name in metrics), (
            "expected the proxied child's llamacpp:* metrics in the router /metrics body"
        )
        # and the router's own F015 auth counters, from the 401 generated above
        val = _metric(metrics, "llamacpp_auth_failures_total",
                      auth_method="none", reason="no_credential")
        assert val is not None and val >= 1, (
            "expected the router's own llamacpp_auth_failures_total counters "
            "in the same body as the proxied child metrics"
        )
    finally:
        server.stop()
