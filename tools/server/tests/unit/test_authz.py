import hashlib
import json
import os
import tempfile

import pytest
from utils import ServerPreset

# F002 RBAC init tests (docs/design/pr1-rbac-core.md section 4.3 mode 3, Q2).
# In RBAC mode the policy file is the single source of truth for valid keys:
# an --api-key not listed in policy.api_keys must abort startup (fail closed),
# even when the policy omits the api_keys field entirely.


def _write_policy(policy: dict) -> str:
    fd, path = tempfile.mkstemp(suffix=".json", prefix="authz_policy_")
    with os.fdopen(fd, "w") as f:
        json.dump(policy, f)
    return path


def test_rbac_policy_without_api_keys_rejects_api_key():
    """--auth-policy-file (no api_keys field) + --api-key must fail to start.

    Regression: a policy that omits api_keys must NOT degrade to legacy
    super-user (PERM_ALL); the unlisted --api-key is a startup error.
    """
    policy_path = _write_policy({
        "roles": {"user": ["INFER"]},
        "default_role": None,
    })
    server = ServerPreset.tinyllama2()
    server.auth_policy_file = policy_path
    server.api_key = "sk-secret"
    try:
        with pytest.raises((RuntimeError, TimeoutError)):
            server.start(timeout_seconds=15)
    finally:
        server.stop()
        os.remove(policy_path)


# F011: policy public_endpoints opens listed routes to unauthenticated access,
# opens only (never restricts), fails closed on malformed values, and warns
# (does not abort) on entries that match no registered route.

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _rbac_admin_policy(extra: dict | None = None) -> dict:
    policy = {
        "roles": {
            "admin": ["INFER", "READ_STATE", "METRICS", "ADMIN_STATE", "ADMIN_MODELS"],
            "user": ["INFER"],
        },
        "api_keys": {_sha256_hex("sk-admin"): "admin"},
        "default_role": None,
    }
    if extra:
        policy.update(extra)
    return policy


def test_public_endpoints_opens_listed_route_only():
    policy_path = _write_policy(_rbac_admin_policy({"public_endpoints": ["/props"]}))
    server = ServerPreset.tinyllama2()
    server.auth_policy_file = policy_path
    try:
        server.start()
        # /props is public via public_endpoints -> no key needed
        assert server.make_request("GET", "/props").status_code == 200
        # /slots is NOT listed -> still protected
        assert server.make_request("GET", "/slots").status_code == 401
    finally:
        server.stop()
        os.remove(policy_path)


def test_public_endpoints_unknown_route_starts_with_warning():
    # an entry matching no registered route is advisory: server still starts
    policy_path = _write_policy(_rbac_admin_policy({"public_endpoints": ["/nonexistent-route"]}))
    server = ServerPreset.tinyllama2()
    server.auth_policy_file = policy_path
    try:
        server.start()  # must not raise
        assert server.make_request("GET", "/health").status_code == 200
    finally:
        server.stop()
        os.remove(policy_path)


def test_public_endpoints_malformed_aborts_startup():
    # non-array public_endpoints is a fail-closed config error
    policy_path = _write_policy(_rbac_admin_policy({"public_endpoints": "/props"}))
    server = ServerPreset.tinyllama2()
    server.auth_policy_file = policy_path
    try:
        with pytest.raises((RuntimeError, TimeoutError)):
            server.start(timeout_seconds=15)
    finally:
        server.stop()
        os.remove(policy_path)
