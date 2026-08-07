import pytest
from utils import *

# PR2 F007: trusted-proxy mode. Identity headers (X-Auth-Subject / X-Auth-Roles)
# are honored only from a peer inside --auth-trusted-proxies, and ignored/stripped
# otherwise. The pytest client connects over 127.0.0.1, so 127.0.0.1/32 makes the
# loopback a trusted peer and 10.0.0.0/8 makes it untrusted (the rebase tripwire).
# NOTE: the harness stops every server after each test (conftest autouse), so each
# test starts its own server rather than sharing one.


def _tp_server(trusted_proxies=None, api_key=None, policy_file=None):
    server = ServerPreset.tinyllama2()
    server.auth_trusted_proxies = trusted_proxies
    server.api_key = api_key
    server.auth_policy_file = policy_file
    return server


@pytest.fixture
def tp_only_server():
    # trusted-proxy-only mode: loopback is a trusted peer, no api key
    server = _tp_server(trusted_proxies="127.0.0.1/32")
    server.start()
    yield server


# --- negative first: malformed / all-peers CIDR must abort startup (fail closed) ---
@pytest.mark.parametrize("cidr", ["0.0.0.0/0", "::/0", "127.0.0.1/8x", "not-a-cidr"])
def test_invalid_trusted_proxy_aborts_startup(cidr: str):
    server = _tp_server(trusted_proxies=cidr)
    with pytest.raises((RuntimeError, TimeoutError)):
        server.start(timeout_seconds=20)


# --- REQUIRED rebase tripwire: spoofed identity from an untrusted peer is ignored ---
def test_rebase_tripwire_untrusted_peer_cannot_spoof_identity():
    # loopback is NOT within 10.0.0.0/8, so its X-Auth-* headers must be ignored
    server = _tp_server(trusted_proxies="10.0.0.0/8")
    server.start()
    res = server.make_request("GET", "/props", headers={
        "X-Auth-Subject": "alice",
        "X-Auth-Roles": "admin",
    })
    assert res.status_code == 401, "spoofed X-Auth from an untrusted peer must be denied"


# --- trusted-proxy-only mode: role -> perms differentiation ---
def test_no_identity_headers_denied(tp_only_server):
    assert tp_only_server.make_request("GET", "/props").status_code == 401


def test_roles_without_subject_denied(tp_only_server):
    res = tp_only_server.make_request("GET", "/props", headers={"X-Auth-Roles": "admin"})
    assert res.status_code == 401, "X-Auth-Roles without X-Auth-Subject is not authenticated"


def test_unknown_role_forbidden(tp_only_server):
    res = tp_only_server.make_request("GET", "/props", headers={
        "X-Auth-Subject": "bob", "X-Auth-Roles": "wizard"})
    assert res.status_code == 403, "unknown role -> perms 0 -> 403 on protected route"


def test_user_role_forbidden_on_read_state(tp_only_server):
    res = tp_only_server.make_request("GET", "/props", headers={
        "X-Auth-Subject": "bob", "X-Auth-Roles": "user"})
    assert res.status_code == 403, "user lacks READ_STATE"


def test_admin_role_allowed_on_read_state(tp_only_server):
    res = tp_only_server.make_request("GET", "/props", headers={
        "X-Auth-Subject": "alice", "X-Auth-Roles": "admin"})
    assert res.status_code == 200


def test_user_role_allowed_on_infer(tp_only_server):
    res = tp_only_server.make_request("POST", "/completions", data={
        "prompt": "hi", "n_predict": 1}, headers={
        "X-Auth-Subject": "bob", "X-Auth-Roles": "user"})
    assert res.status_code == 200, "user has INFER"


def test_public_route_no_identity(tp_only_server):
    assert tp_only_server.make_request("GET", "/health").status_code == 200


# --- precedence: trusted-proxy identity wins over a valid api key ---
def test_trusted_proxy_precedence_over_api_key():
    # legacy api key would grant PERM_ALL; a trusted-peer X-Auth identity must win,
    # so a "user" proxy identity is restricted to INFER even with the all-powerful key.
    server = _tp_server(trusted_proxies="127.0.0.1/32", api_key="sk-super")
    server.start()
    # api key alone: legacy PERM_ALL -> /props allowed
    res_key = server.make_request("GET", "/props", headers={"Authorization": "Bearer sk-super"})
    assert res_key.status_code == 200
    # trusted-peer proxy identity "user" takes precedence -> 403 on READ_STATE
    res_proxy = server.make_request("GET", "/props", headers={
        "Authorization": "Bearer sk-super",
        "X-Auth-Subject": "bob",
        "X-Auth-Roles": "user",
    })
    assert res_proxy.status_code == 403, "trusted-proxy identity must take precedence over the api key"
