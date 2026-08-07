import base64
import hashlib
import hmac
import json
import os
import ssl
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import jwt as pyjwt
import pytest
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from utils import ServerPreset, ServerProcess
# Reuse the openssl-CLI PKI helpers from test_mtls.py for the mock IdP's own HTTPS
# server certificate (not the JWT signing keys - those are separate RSA keys built
# with `cryptography` per the mock-JWKS design below).
from test_mtls import _gen_ca, _gen_leaf

# PR4 F009a-d: OIDC (local JWT access-token) validation.
#
# Feature -> acceptance criterion -> test mapping is recorded in features.json
# test_refs (all of F009a/b/c/d point at this file); each test below carries a
# comment naming the criterion/design-doc case it exercises.
#
# NOTE: the harness stops every server after each test (conftest autouse), so
# each test starts its own server, per the test_mtls.py / test_authz.py convention.
#
# Mock IdP: a python http.server (ThreadingHTTPServer) wrapped in TLS, serving
# `/.well-known/openid-configuration` and `/jwks.json` over HTTPS on 127.0.0.1,
# with a self-signed cert (SAN 127.0.0.1) whose CA is passed to llama-server via
# --oidc-ca-file. Token minting uses PyJWT for RS256; the HS256-with-RSA-public-
# key-as-HMAC-secret "confusion" token is hand-built (PyJWT's HMACAlgorithm
# refuses to treat a PEM-shaped key as an HMAC secret, which is exactly the
# footgun we need to construct on purpose to prove the *server* rejects it).


# ---------------------------------------------------------------------------
# PKI for the mock IdP's own HTTPS listener (openssl CLI, reused from test_mtls).
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def idp_pki():
    tmpdir = tempfile.mkdtemp(prefix="oidc_idp_pki_")
    ca_crt, ca_key = _gen_ca(tmpdir, "idp_ca", "Test IdP CA")
    server_crt, server_key = _gen_leaf(
        tmpdir, "idp_server", "127.0.0.1",
        "DNS:localhost,IP:127.0.0.1", "serverAuth",
        ca_crt, ca_key,
    )
    yield SimpleNamespace(ca_crt=ca_crt, server_crt=server_crt, server_key=server_key)
    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# RSA signing keys + bare (no x5c) JWKS entries for the mock IdP's token keys.
# ---------------------------------------------------------------------------

def _gen_rsa():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub, priv_pem, pub_pem


def _b64url_uint(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _rsa_jwk(pub, kid: str) -> dict:
    numbers = pub.public_numbers()
    # Bare n/e, no x5c - per the design's "bare JWK" test posture.
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": _b64url_uint(numbers.n),
        "e": _b64url_uint(numbers.e),
    }


def _oct_jwk(kid: str) -> dict:
    # A symmetric (HMAC) JWK - must never be reachable by any verifier (S2).
    secret = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
    return {"kty": "oct", "kid": kid, "use": "sig", "alg": "HS256", "k": secret}


@pytest.fixture(scope="session")
def oidc_keys_full():
    priv1, pub1, priv1_pem, pub1_pem = _gen_rsa()
    priv2, pub2, priv2_pem, pub2_pem = _gen_rsa()
    return SimpleNamespace(
        kid1_priv_pem=priv1_pem, kid1_pub_pem=pub1_pem, kid1_jwk=_rsa_jwk(pub1, "kid1"),
        kid2_priv_pem=priv2_pem, kid2_pub_pem=pub2_pem, kid2_jwk=_rsa_jwk(pub2, "kid2"),
    )


# ---------------------------------------------------------------------------
# Mock IdP: HTTPS http.server exposing discovery + JWKS, with switchable modes.
# ---------------------------------------------------------------------------

class _IdPState:
    def __init__(self, jwks_body: bytes):
        self.mode = "normal"  # normal | down | redirect_http | redirect_host
        self.jwks_body = jwks_body
        self.cache_control = None
        self.jwks_hits = 0
        self.discovery_issuer_override = None  # C-2: lie about "issuer" in discovery doc
        self.lock = threading.Lock()
        # F010b: RFC 7662 introspection mock state.
        self.introspect_mode = "normal"  # normal | down | redirect
        self.introspect_response = {"active": False}
        self.introspect_hits = 0
        self.introspect_last_auth_header = None  # last received Authorization header (Basic)


class _IdPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _write(self, code, body: bytes, headers: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        state: _IdPState = self.server.idp_state
        if self.path == "/.well-known/openid-configuration":
            with state.lock:
                mode = state.mode
                issuer_override = state.discovery_issuer_override
            if mode == "down":
                self.send_response(503)
                self.end_headers()
                return
            body = json.dumps({
                "issuer": issuer_override if issuer_override is not None else self.server.idp_issuer,
                "jwks_uri": f"{self.server.idp_issuer}/jwks.json",
            }).encode()
            self._write(200, body)
            return
        if self.path == "/jwks.json":
            with state.lock:
                state.jwks_hits += 1
                mode = state.mode
                body = state.jwks_body
                cc = state.cache_control
            if mode == "down":
                self.send_response(503)
                self.end_headers()
                return
            if mode == "redirect_http":
                self.send_response(302)
                self.send_header("Location", "http://169.254.169.254/secret-jwks")
                self.end_headers()
                return
            if mode == "redirect_host":
                self.send_response(302)
                self.send_header("Location", "https://example.invalid/jwks.json")
                self.end_headers()
                return
            headers = {"Cache-Control": cc} if cc else None
            self._write(200, body, headers)
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        # F010b: RFC 7662 introspection endpoint mock.
        state: _IdPState = self.server.idp_state
        if self.path == "/introspect":
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)  # body (token=...&token_type_hint=...) - not parsed, not needed
            with state.lock:
                state.introspect_hits += 1
                state.introspect_last_auth_header = self.headers.get("Authorization")
                mode = state.introspect_mode
                response = state.introspect_response
            if mode == "down":
                self.send_response(503)
                self.end_headers()
                return
            if mode == "redirect":
                self.send_response(302)
                self.send_header("Location", f"{self.server.idp_issuer}/introspect")
                self.end_headers()
                return
            self._write(200, json.dumps(response).encode())
            return
        self.send_response(404)
        self.end_headers()


class MockIdP:
    def __init__(self, cert: str, key: str, jwks: dict):
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), _IdPHandler)
        httpd.daemon_threads = True
        self.state = _IdPState(json.dumps(jwks).encode())
        httpd.idp_state = self.state
        self.port = httpd.server_address[1]
        self.issuer = f"https://127.0.0.1:{self.port}"
        httpd.idp_issuer = self.issuer
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert, keyfile=key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        self.httpd = httpd
        self.thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def jwks_url(self) -> str:
        return f"{self.issuer}/jwks.json"

    def set_jwks(self, jwks: dict, cache_control: str | None = None):
        with self.state.lock:
            self.state.jwks_body = json.dumps(jwks).encode()
            self.state.cache_control = cache_control

    def set_mode(self, mode: str):
        with self.state.lock:
            self.state.mode = mode

    def set_discovery_issuer_override(self, issuer: str | None):
        with self.state.lock:
            self.state.discovery_issuer_override = issuer

    def jwks_hits(self) -> int:
        with self.state.lock:
            return self.state.jwks_hits

    # F010b: introspection mock controls.
    @property
    def introspect_url(self) -> str:
        return f"{self.issuer}/introspect"

    def set_introspect_response(self, response: dict):
        with self.state.lock:
            self.state.introspect_response = response

    def set_introspect_mode(self, mode: str):
        with self.state.lock:
            self.state.introspect_mode = mode

    def introspect_hits(self) -> int:
        with self.state.lock:
            return self.state.introspect_hits

    def introspect_last_auth_header(self) -> str | None:
        with self.state.lock:
            return self.state.introspect_last_auth_header

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture()
def mock_idp(idp_pki, oidc_keys_full):
    idp = MockIdP(idp_pki.server_crt, idp_pki.server_key, {"keys": [oidc_keys_full.kid1_jwk]})
    try:
        yield idp
    finally:
        idp.stop()


# ---------------------------------------------------------------------------
# Token minting.
# ---------------------------------------------------------------------------

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _mint(issuer, priv_pem, *, kid="kid1", alg="RS256", aud="test-aud", iss=None,
          sub="user-123", roles=("llm-admins",), exp_delta=300, nbf_delta=-10,
          iat_delta=-10, no_sub=False, no_exp=False, extra_claims=None, headers_extra=None):
    now = int(time.time())
    payload = {
        "iss": iss if iss is not None else issuer,
        "aud": aud,
        "exp": now + exp_delta,
        "nbf": now + nbf_delta,
        "iat": now + iat_delta,
        "realm_access": {"roles": list(roles)},
    }
    if not no_sub:
        payload["sub"] = sub
    if no_exp:
        payload.pop("exp", None)
    if extra_claims:
        payload.update(extra_claims)
    headers = {"kid": kid}
    if headers_extra:
        headers.update(headers_extra)
    return pyjwt.encode(payload, priv_pem, algorithm=alg, headers=headers)


def _mint_none(issuer, **kwargs):
    now = int(time.time())
    payload = {"iss": issuer, "aud": "test-aud", "sub": "user-123",
               "exp": now + 300, "nbf": now - 10, "iat": now - 10,
               "realm_access": {"roles": ["llm-admins"]}}
    payload.update(kwargs)
    return pyjwt.encode(payload, key="", algorithm="none", headers={"kid": "kid1"})


def _mint_hs256_confusion(issuer, pub_pem_bytes, kid="kid1"):
    # PyJWT's HMACAlgorithm.prepare_key refuses PEM-shaped keys (it detects and
    # blocks exactly this attack), so the confusion token must be hand-built:
    # HS256-sign with the RSA JWKS PUBLIC key bytes used verbatim as the HMAC
    # secret. This is the single most important negative test in the suite.
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT", "kid": kid}
    payload = {"iss": issuer, "aud": "test-aud", "sub": "user-123",
               "exp": now + 300, "nbf": now - 10, "iat": now - 10,
               "realm_access": {"roles": ["llm-admins"]}}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(pub_pem_bytes, signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


# ---------------------------------------------------------------------------
# Policy + server-start helpers.
# ---------------------------------------------------------------------------

def _write_policy(policy: dict) -> str:
    fd, path = tempfile.mkstemp(suffix=".json", prefix="oidc_policy_")
    with os.fdopen(fd, "w") as f:
        json.dump(policy, f)
    return path


def _oidc_policy(extra: dict | None = None) -> dict:
    policy = {
        "roles": {
            "admin": ["INFER", "READ_STATE", "METRICS", "ADMIN_STATE", "ADMIN_MODELS"],
            "user": ["INFER"],
        },
        "default_role": None,
        "oidc": {
            "roles_claim": "realm_access.roles",
            "role_map": {"llm-admins": "admin", "llm-users": "user"},
        },
    }
    if extra:
        policy.update(extra)
    return policy


def _oidc_server(idp_pki, idp: MockIdP, *, use_discovery=False, audience="test-aud",
                  algs=None, clock_skew=None, policy: dict | None = None,
                  api_key=None, metrics=True) -> ServerProcess:
    server = ServerPreset.tinyllama2()
    server.oidc_issuer = idp.issuer          # C1: always required
    if not use_discovery:
        server.oidc_jwks_url = idp.jwks_url
    server.oidc_audience = audience
    server.oidc_ca_file = idp_pki.ca_crt
    if algs:
        server.oidc_algs = algs
    if clock_skew is not None:
        server.oidc_clock_skew = clock_skew
    if policy is not None:
        path = _write_policy(policy)
        server.auth_policy_file = path
        server._policy_path = path
    if api_key:
        server.api_key = api_key
    server.server_metrics = metrics
    return server


def _cleanup(server):
    server.stop()
    if hasattr(server, "_policy_path"):
        os.remove(server._policy_path)


# ---------------------------------------------------------------------------
# F010b: RFC 7662 introspection response + server-start helpers.
# ---------------------------------------------------------------------------

def _introspect_resp(active=True, aud="test-aud", iss=None, sub="user-123",
                      exp_delta=300, nbf_delta=None, roles=("llm-admins",),
                      no_aud=False, no_sub=False, extra: dict | None = None) -> dict:
    now = int(time.time())
    resp: dict = {"active": active}
    if active:
        if not no_aud and aud is not None:
            resp["aud"] = aud
        if iss is not None:
            resp["iss"] = iss
        if not no_sub and sub is not None:
            resp["sub"] = sub
        if exp_delta is not None:
            resp["exp"] = now + exp_delta
        if nbf_delta is not None:
            resp["nbf"] = now + nbf_delta
        if roles is not None:
            resp["realm_access"] = {"roles": list(roles)}
    if extra:
        resp.update(extra)
    return resp


def _write_secret(content: str) -> str:
    fd, path = tempfile.mkstemp(prefix="oidc_secret_")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


def _introspect_server(idp_pki, idp: MockIdP, *, audience="test-aud", issuer=None,
                        with_jwks=None, client_id="llama-server", secret="s3cr3t-value",
                        secret_file=None, policy: dict | None = None,
                        api_key=None) -> ServerProcess:
    """Build a ServerProcess with --oidc-introspection-url (+client auth) configured.
    issuer=None -> introspection-only mode (no --oidc-issuer/--oidc-jwks-url at all).
    issuer=<url> -> also turns on the full JWKS path (server-oidc.cpp section 8.0 note
    2), so with_jwks defaults to idp.jwks_url whenever issuer is given."""
    server = ServerPreset.tinyllama2()
    if issuer is not None:
        server.oidc_issuer = issuer
        server.oidc_jwks_url = with_jwks if with_jwks is not None else idp.jwks_url
    if audience is not None:
        server.oidc_audience = audience
    server.oidc_ca_file = idp_pki.ca_crt
    server.oidc_introspection_url = idp.introspect_url
    server.oidc_client_id = client_id
    if secret_file is None:
        secret_file = _write_secret(secret)
        server._secret_path = secret_file
    server.oidc_client_secret_file = secret_file
    if policy is not None:
        path = _write_policy(policy)
        server.auth_policy_file = path
        server._policy_path = path
    if api_key:
        server.api_key = api_key
    return server


def _cleanup_introspect(server):
    server.stop()
    if hasattr(server, "_policy_path"):
        os.remove(server._policy_path)
    if hasattr(server, "_secret_path"):
        os.remove(server._secret_path)


# ---------------------------------------------------------------------------
# Negative first: malformed/adversarial tokens (F009c).
# ---------------------------------------------------------------------------

def test_no_authorization_header_denied(idp_pki, mock_idp, oidc_keys_full):
    # F009d criterion 6: OIDC-only mode, anonymous request to a protected route -> 401
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()
        res = server.make_request("GET", "/props")
        assert res.status_code == 401
    finally:
        _cleanup(server)


def test_alg_none_rejected(idp_pki, mock_idp, oidc_keys_full):
    # F009c criterion 1: alg "none" is rejected, never a role.
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()
        tok = _mint_none(mock_idp.issuer)
        res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {tok}"})
        assert res.status_code == 401
    finally:
        _cleanup(server)


def test_hs256_confusion_with_rsa_public_key_rejected(idp_pki, mock_idp, oidc_keys_full):
    # F009c criterion 1 (THE most important case): an HS256 token signed using the
    # JWKS RSA public key bytes as the HMAC secret must be rejected. validate() must
    # never construct an HMAC verifier from a JWKS asymmetric key.
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()
        tok = _mint_hs256_confusion(mock_idp.issuer, oidc_keys_full.kid1_pub_pem)
        res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {tok}"})
        assert res.status_code == 401
    finally:
        _cleanup(server)


def test_wrong_audience_rejected(idp_pki, mock_idp, oidc_keys_full):
    # F009c criterion 6: token aud not among configured audiences -> deny.
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()
        tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, aud="some-other-aud")
        res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {tok}"})
        assert res.status_code == 401
    finally:
        _cleanup(server)


def test_wrong_issuer_rejected(idp_pki, mock_idp, oidc_keys_full):
    # F009c criterion 5: wrong iss -> deny (jwt-cpp with_issuer).
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()
        tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, iss="https://not-the-idp.invalid")
        res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {tok}"})
        assert res.status_code == 401
    finally:
        _cleanup(server)


def test_expired_token_rejected(idp_pki, mock_idp, oidc_keys_full):
    # F009c criterion 5: exp well beyond clock-skew in the past -> deny.
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy(), clock_skew=60)
    try:
        server.start()
        tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, exp_delta=-120)
        res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {tok}"})
        assert res.status_code == 401
    finally:
        _cleanup(server)


def test_future_nbf_rejected(idp_pki, mock_idp, oidc_keys_full):
    # F009c criterion 5: nbf well beyond clock-skew in the future -> deny.
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy(), clock_skew=60)
    try:
        server.start()
        tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, nbf_delta=120)
        res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {tok}"})
        assert res.status_code == 401
    finally:
        _cleanup(server)


def test_token_within_clock_skew_accepted(idp_pki, mock_idp, oidc_keys_full):
    # F009c criterion 5 (second half): a token exactly within clock-skew of
    # exp/nbf is accepted (leeway applied uniformly to exp AND nbf).
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy(), clock_skew=60)
    try:
        server.start()
        # exp already "passed" by 30s and nbf "not yet valid" until 30s ago - both
        # within the 60s leeway, so verification should still succeed.
        tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, exp_delta=-30, nbf_delta=-30)
        res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {tok}"})
        assert res.status_code == 200
    finally:
        _cleanup(server)


def test_unknown_kid_rejected(idp_pki, mock_idp, oidc_keys_full):
    # F009c criterion 4: a kid that never appears in the JWKS -> deny, even after
    # the rate-limited refresh attempt (the IdP genuinely has no such key).
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()
        tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, kid="kid-does-not-exist")
        res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {tok}"})
        assert res.status_code == 401
    finally:
        _cleanup(server)


@pytest.mark.parametrize("bad_token", [
    "onlytwo.segments",
    "a..c",              # empty middle segment
    "a.b!.c",             # non-base64url char
    "",
])
def test_malformed_tokens_rejected(idp_pki, mock_idp, oidc_keys_full, bad_token):
    # F009a criterion (looks_like_jwt) + F009c step 1 (shape check before any parse).
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()
        headers = {"Authorization": f"Bearer {bad_token}"} if bad_token else None
        res = server.make_request("GET", "/props", headers=headers)
        assert res.status_code == 401
    finally:
        _cleanup(server)


def test_missing_sub_rejected(idp_pki, mock_idp, oidc_keys_full):
    # F009c criterion 6: token missing sub -> deny.
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()
        tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, no_sub=True)
        res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {tok}"})
        assert res.status_code == 401
    finally:
        _cleanup(server)


def test_missing_exp_rejected(idp_pki, mock_idp, oidc_keys_full):
    # F009c criterion 6: token missing exp -> deny (an access token with no
    # expiry is not acceptable).
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()
        tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, no_exp=True)
        res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {tok}"})
        assert res.status_code == 401
    finally:
        _cleanup(server)


# ---------------------------------------------------------------------------
# S2: JWK type-mismatch is fail-closed (design doc case 18) - bonus coverage
# beyond the requested matrix, since it is an explicit F009c acceptance criterion.
# ---------------------------------------------------------------------------

def test_s2_oct_symmetric_jwk_never_reaches_hmac_path(idp_pki, oidc_keys_full):
    # F009c criterion 3: a kid resolving to an oct (symmetric) JWK is rejected -
    # no HMAC verifier is ever constructed, so this must fail closed (401), not 200.
    idp = MockIdP(idp_pki.server_crt, idp_pki.server_key,
                  {"keys": [oidc_keys_full.kid1_jwk, _oct_jwk("kid-oct")]})
    server = _oidc_server(idp_pki, idp, policy=_oidc_policy())
    try:
        server.start()
        # Sign normally with kid1's RSA key but claim kid "kid-oct" in the header,
        # forcing the server to resolve the oct JWK for verification.
        tok = _mint(idp.issuer, oidc_keys_full.kid1_priv_pem, kid="kid-oct")
        res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {tok}"})
        assert res.status_code == 401
    finally:
        _cleanup(server)
        idp.stop()


def test_s2_rsa_jwk_used_with_es_alg_rejected(idp_pki, oidc_keys_full):
    # F009c criterion 3: an RSA JWK used with an ES* alg header must fail (key
    # family mismatch), never silently coerced into a working verifier.
    idp = MockIdP(idp_pki.server_crt, idp_pki.server_key, {"keys": [oidc_keys_full.kid1_jwk]})
    server = _oidc_server(idp_pki, idp, policy=_oidc_policy(), algs="RS256,ES256")
    try:
        server.start()
        tok = _mint(idp.issuer, oidc_keys_full.kid1_priv_pem, alg="RS256", headers_extra={})
        # Tamper the header alg to ES256 after signing so the RS256 signature
        # bytes are presented under an ES256 header (this must fail: either the
        # PEM->EC-key build fails or the ES256 verify throws on RS256 bytes).
        h_b64, p_b64, s_b64 = tok.split(".")
        header = json.loads(base64.urlsafe_b64decode(h_b64 + "=="))
        header["alg"] = "ES256"
        new_h_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode())
        tampered = f"{new_h_b64}.{p_b64}.{s_b64}"
        res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {tampered}"})
        assert res.status_code == 401
    finally:
        _cleanup(server)
        idp.stop()


# ---------------------------------------------------------------------------
# S1: JWKS/discovery redirects are not followed (design doc case 17) - bonus
# coverage beyond the requested matrix, since it is an explicit F009b criterion.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mode", ["redirect_http", "redirect_host"])
def test_s1_jwks_redirect_not_followed_refuses_start(idp_pki, oidc_keys_full, mode):
    # F009b criterion 4 (S1): a JWKS endpoint that 302-redirects (to http:// or to
    # another host) is NOT followed and is treated as a fetch failure at boot.
    idp = MockIdP(idp_pki.server_crt, idp_pki.server_key, {"keys": [oidc_keys_full.kid1_jwk]})
    idp.set_mode(mode)
    server = _oidc_server(idp_pki, idp, policy=_oidc_policy())
    try:
        with pytest.raises((RuntimeError, TimeoutError)):
            server.start(timeout_seconds=15)
    finally:
        server.stop()
        if hasattr(server, "_policy_path"):
            os.remove(server._policy_path)
        idp.stop()


# ---------------------------------------------------------------------------
# Positive cases (F009d).
# ---------------------------------------------------------------------------

def test_valid_admin_jwt_authorizes_props_metrics_and_slots(idp_pki, mock_idp, oidc_keys_full):
    # F009d criterion 1: admin-mapped JWT can POST /slots/0 (ADMIN_STATE), and can
    # GET /props (READ_STATE) / GET /metrics (METRICS); audit shows auth_method=oidc
    # and a non-anonymous subject_hash (never the raw sub).
    fd, audit_path = tempfile.mkstemp(suffix=".jsonl", prefix="oidc_audit_")
    os.close(fd)
    os.unlink(audit_path)
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy())
    server.auth_audit_log = audit_path
    try:
        server.start()
        tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, roles=("llm-admins",), sub="admin-subject-1")
        headers = {"Authorization": f"Bearer {tok}"}
        assert server.make_request("GET", "/props", headers=headers).status_code == 200
        assert server.make_request("GET", "/metrics", headers=headers).status_code == 200
        res = server.make_request("POST", "/slots/0", headers=headers, data=None)
        # ADMIN_STATE is authorized (not 401/403); the handler's own response for a
        # bare POST with no ?action= may itself be an error status, but never an
        # authz denial.
        assert res.status_code not in (401, 403)
    finally:
        _cleanup(server)
    with open(audit_path) as f:
        lines = [json.loads(ln) for ln in f if ln.strip()]
    props_lines = [r for r in lines if r["path"] == "/props"]
    assert props_lines, "expected an audit line for /props"
    assert props_lines[0]["auth_method"] == "oidc"
    assert props_lines[0]["subject_hash"] != "anonymous"
    assert "admin-subject-1" not in json.dumps(props_lines[0]), "raw sub must never be logged"
    os.unlink(audit_path)


def test_valid_user_jwt_infer_ok_admin_forbidden(idp_pki, mock_idp, oidc_keys_full):
    # F009d criterion 2: user-mapped JWT succeeds on POST /completions (INFER) and
    # gets 403 on a READ_STATE route (probed via /props, cheaper than ADMIN_STATE).
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()
        tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, roles=("llm-users",), alg="RS256")
        headers = {"Authorization": f"Bearer {tok}"}
        res = server.make_request("GET", "/props", headers=headers)
        assert res.status_code == 403, "user lacks READ_STATE"
        res = server.make_request("POST", "/completions", headers=headers,
                                   data={"prompt": "hi", "n_predict": 1})
        assert res.status_code == 200, "user has INFER"
    finally:
        _cleanup(server)


def test_unmapped_role_authenticated_but_forbidden(idp_pki, mock_idp, oidc_keys_full):
    # F009d criterion 3: roles claim present but maps to no known role -> authenticated,
    # perms=0 -> 403 (no default role, no fallback to API-key).
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()
        tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, roles=("some-unmapped-role",))
        res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {tok}"})
        assert res.status_code == 403
    finally:
        _cleanup(server)


def test_missing_roles_claim_authenticated_but_forbidden(idp_pki, mock_idp, oidc_keys_full):
    # F009d criterion 3 (absent roles claim variant): claims_json has no
    # realm_access.roles at all -> empty roles -> perms=0 -> 403.
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()
        now = int(time.time())
        payload = {"iss": mock_idp.issuer, "aud": "test-aud", "sub": "user-123",
                   "exp": now + 300, "nbf": now - 10, "iat": now - 10}
        tok = pyjwt.encode(payload, oidc_keys_full.kid1_priv_pem, algorithm="RS256", headers={"kid": "kid1"})
        res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {tok}"})
        assert res.status_code == 403
    finally:
        _cleanup(server)


# ---------------------------------------------------------------------------
# Bearer disambiguation (F009d criterion 4 / design C2/OQ3).
# ---------------------------------------------------------------------------

def test_opaque_api_key_falls_through_when_oidc_also_enabled(idp_pki, mock_idp, oidc_keys_full):
    # F009d criterion 4: a non-JWT (opaque) Bearer still authenticates via the
    # API-key path when a key is configured, even with OIDC enabled.
    policy = _oidc_policy({"api_keys": {hashlib.sha256(b"sk-user").hexdigest(): "user"}})
    server = _oidc_server(idp_pki, mock_idp, policy=policy)
    try:
        server.start()
        res = server.make_request("POST", "/completions",
                                   headers={"Authorization": "Bearer sk-user"},
                                   data={"prompt": "hi", "n_predict": 1})
        assert res.status_code == 200
        # a wrong opaque key still falls through to the (rejecting) api-key path
        res = server.make_request("GET", "/props", headers={"Authorization": "Bearer sk-wrong"})
        assert res.status_code == 401
    finally:
        _cleanup(server)


def test_jwt_shaped_invalid_bearer_not_retried_as_api_key(idp_pki, mock_idp, oidc_keys_full):
    # F009d criterion 4: a JWT-shaped but invalid Bearer returns 401 and is NOT
    # retried as an API key - confirmed via audit auth_method (must be "none",
    # never "api_key", proving resolve_principal's OIDC branch returned early
    # instead of falling through).
    fd, audit_path = tempfile.mkstemp(suffix=".jsonl", prefix="oidc_audit_")
    os.close(fd)
    os.unlink(audit_path)
    policy = _oidc_policy({"api_keys": {hashlib.sha256(b"sk-user").hexdigest(): "user"}})
    server = _oidc_server(idp_pki, mock_idp, policy=policy)
    server.auth_audit_log = audit_path
    try:
        server.start()
        # wrong aud -> JWT-shaped but cryptographically/semantically invalid
        tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, aud="wrong-aud")
        res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {tok}"})
        assert res.status_code == 401
    finally:
        _cleanup(server)
    with open(audit_path) as f:
        lines = [json.loads(ln) for ln in f if ln.strip()]
    props_lines = [r for r in lines if r["path"] == "/props"]
    assert props_lines
    assert props_lines[-1]["auth_method"] != "api_key", (
        "JWT-shaped-but-invalid Bearer must not be retried as an API key"
    )
    os.unlink(audit_path)


# ---------------------------------------------------------------------------
# Key rotation + JWKS DoS/rate-limit guard (F009b).
# ---------------------------------------------------------------------------

def test_key_rotation_new_kid_validates_after_refresh(idp_pki, mock_idp, oidc_keys_full, monkeypatch):
    # F009b: server boots with kid1 only; the IdP rotates in kid2; a token signed
    # with kid2 validates once the (rate-limited) unknown-kid refresh runs. Uses
    # the S4 test-only env var to shrink the unknown-kid window so this is not
    # tied to the 5-minute production default.
    #
    # Timing note: last_unknown_kid_refresh starts at 0 (unix epoch), so the
    # VERY FIRST unknown kid ever seen always clears "now - last >= window +
    # jitter(0..30s)" trivially and triggers an immediate refresh - no sleep
    # needed. This test deliberately does not present any unknown kid BEFORE
    # rotating the IdP, so the kid2 lookup below is that first-ever attempt.
    # (A *second* unknown kid within the window would need to wait out up to
    # window+30s of jitter; that budget-vs-jitter interaction is covered by
    # test_unknown_kid_burst_does_not_hammer_idp instead of a real-time sleep
    # here, to keep this test fast and deterministic.)
    monkeypatch.setenv("LLAMA_OIDC_UNKNOWN_KID_WINDOW_SECONDS", "1")
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()
        # IdP rotates: publish both kid1 and kid2 BEFORE any kid2 token is ever
        # presented to the server (keeps last_unknown_kid_refresh untouched).
        mock_idp.set_jwks({"keys": [oidc_keys_full.kid1_jwk, oidc_keys_full.kid2_jwk]})

        tok2 = _mint(mock_idp.issuer, oidc_keys_full.kid2_priv_pem, kid="kid2")
        res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {tok2}"})
        assert res.status_code == 200
    finally:
        _cleanup(server)


def test_unknown_kid_burst_does_not_hammer_idp(idp_pki, mock_idp, oidc_keys_full):
    # F009b criterion 10: a burst of distinct unknown kids triggers at most one
    # JWKS refetch within the rate-limit window (DoS-amplification guard).
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()
        hits_before = mock_idp.jwks_hits()
        for i in range(5):
            tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, kid=f"forged-kid-{i}")
            res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {tok}"})
            assert res.status_code == 401
        hits_after = mock_idp.jwks_hits()
        assert hits_after - hits_before <= 1, (
            f"expected at most 1 refetch for a burst of 5 unknown kids, got {hits_after - hits_before}"
        )
    finally:
        _cleanup(server)


def test_jwks_down_at_runtime_fail_static_then_new_kid_denied(idp_pki, mock_idp, oidc_keys_full, monkeypatch):
    # F009b criterion 7: IdP unreachable at runtime keeps last-known keys
    # (fail-static): a token with the already-cached kid still validates. A
    # brand-new unknown kid, however, must still be denied - fail-static must
    # never become fail-open.
    monkeypatch.setenv("LLAMA_OIDC_JWKS_TTL_SECONDS", "1")
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()
        mock_idp.set_mode("down")
        time.sleep(1.5)  # let the (short) cache TTL expire
        tok_cached = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, kid="kid1")
        res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {tok_cached}"})
        assert res.status_code == 200, "fail-static: a known kid must still validate while the IdP is down"

        tok_new = _mint(mock_idp.issuer, oidc_keys_full.kid2_priv_pem, kid="kid-brand-new")
        res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {tok_new}"})
        assert res.status_code == 401, "fail-static must never become fail-open for a genuinely new kid"
    finally:
        _cleanup(server)


def test_same_kid_key_material_rotation_old_key_rejected(idp_pki, mock_idp, oidc_keys_full, monkeypatch):
    # Performance fix: derived PEM cache must not serve a stale key when key
    # material rotates under the SAME kid. Verify that when keypair A is
    # replaced with keypair B under the same kid, a token signed with A is
    # rejected after the JWKS refresh.
    monkeypatch.setenv("LLAMA_OIDC_JWKS_TTL_SECONDS", "1")
    monkeypatch.setenv("LLAMA_OIDC_JWKS_REFRESH_MIN_INTERVAL_SECONDS", "0")
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()
        # Token signed with kid1's original keypair should validate initially
        tok_original = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, kid="kid1")
        res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {tok_original}"})
        assert res.status_code == 200, "initial token with kid1 original keypair must validate"

        # IdP rotates: kid1 keeps its name but carries FRESH key material
        priv_new, pub_new, priv_new_pem, _ = _gen_rsa()
        rotated_jwk = _rsa_jwk(pub_new, "kid1")
        mock_idp.set_jwks({"keys": [rotated_jwk]})
        time.sleep(1.5)  # let cache TTL expire to force refresh

        # Token signed with kid1's old keypair must now be rejected
        # (the PEM cache must have been replaced atomically with the new JWKS)
        res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {tok_original}"})
        assert res.status_code == 401, "token signed with rotated-out keypair must be rejected"

        # POSITIVE CONTROL: without this, any bug leaving the PEM cache EMPTY
        # also yields 401 above, so the test would pass while all OIDC auth is
        # dead. A token signed with the rotated-IN keypair must still validate.
        tok_new = _mint(mock_idp.issuer, priv_new_pem, kid="kid1")
        res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {tok_new}"})
        assert res.status_code == 200, "token signed with the rotated-in keypair must validate"
    finally:
        _cleanup(server)


# ---------------------------------------------------------------------------
# Startup fail-closed matrix (F009b).
# ---------------------------------------------------------------------------

def test_startup_fails_when_jwks_unreachable(idp_pki, oidc_keys_full):
    # F009b criterion 6 (PLAN 4.2c): the mandatory initial JWKS fetch fails at
    # startup -> server does not start.
    idp = MockIdP(idp_pki.server_crt, idp_pki.server_key, {"keys": [oidc_keys_full.kid1_jwk]})
    jwks_url = idp.jwks_url
    issuer = idp.issuer
    idp.stop()  # port now unreachable
    server = ServerPreset.tinyllama2()
    server.oidc_issuer = issuer
    server.oidc_jwks_url = jwks_url
    server.oidc_audience = "test-aud"
    server.oidc_ca_file = idp_pki.ca_crt
    policy_path = _write_policy(_oidc_policy())
    server.auth_policy_file = policy_path
    try:
        with pytest.raises((RuntimeError, TimeoutError)):
            server.start(timeout_seconds=15)
    finally:
        server.stop()
        os.remove(policy_path)


def test_startup_fails_with_non_https_issuer(idp_pki):
    # F009b criterion 2: an http:// (non-https) issuer/discovery URL -> init
    # returns false -> server aborts.
    server = ServerPreset.tinyllama2()
    server.oidc_issuer = "http://127.0.0.1:1"  # plain http, deliberately unreachable too
    server.oidc_audience = "test-aud"
    policy_path = _write_policy(_oidc_policy())
    server.auth_policy_file = policy_path
    try:
        with pytest.raises((RuntimeError, TimeoutError)):
            server.start(timeout_seconds=15)
    finally:
        server.stop()
        os.remove(policy_path)


def test_startup_fails_jwks_url_without_issuer_c1(idp_pki, mock_idp):
    # C1: --oidc-jwks-url set but NO --oidc-issuer -> server refuses to start
    # (an empty issuer would skip iss verification entirely).
    server = ServerPreset.tinyllama2()
    server.oidc_jwks_url = mock_idp.jwks_url
    server.oidc_audience = "test-aud"
    server.oidc_ca_file = idp_pki.ca_crt
    policy_path = _write_policy(_oidc_policy())
    server.auth_policy_file = policy_path
    try:
        with pytest.raises((RuntimeError, TimeoutError)):
            server.start(timeout_seconds=15)
    finally:
        server.stop()
        os.remove(policy_path)


def test_startup_fails_with_empty_audience(idp_pki, mock_idp):
    # F009b criterion 2: empty --oidc-audience -> init fails (audience checking
    # is mandatory).
    server = ServerPreset.tinyllama2()
    server.oidc_issuer = mock_idp.issuer
    server.oidc_jwks_url = mock_idp.jwks_url
    server.oidc_ca_file = idp_pki.ca_crt
    policy_path = _write_policy(_oidc_policy())
    server.auth_policy_file = policy_path
    try:
        with pytest.raises((RuntimeError, TimeoutError)):
            server.start(timeout_seconds=15)
    finally:
        server.stop()
        os.remove(policy_path)


def test_startup_fails_with_bad_alg_in_list(idp_pki, mock_idp):
    # F009b criterion 2: a bad/symmetric alg in --oidc-algs -> init fails.
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy(), algs="RS256,HS256")
    try:
        with pytest.raises((RuntimeError, TimeoutError)):
            server.start(timeout_seconds=15)
    finally:
        server.stop()
        if hasattr(server, "_policy_path"):
            os.remove(server._policy_path)


def test_startup_fails_with_clock_skew_over_300(idp_pki, mock_idp):
    # F009b criterion 2: clock-skew > 300 -> init fails.
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy(), clock_skew=301)
    try:
        with pytest.raises((RuntimeError, TimeoutError)):
            server.start(timeout_seconds=15)
    finally:
        server.stop()
        if hasattr(server, "_policy_path"):
            os.remove(server._policy_path)


# ---------------------------------------------------------------------------
# Discovery mode (F009b criterion 1) - the positive half; the negative half
# (issuer required even with an explicit jwks-url) is C1 above.
# ---------------------------------------------------------------------------

def test_discovery_mode_resolves_jwks_and_admin_authorizes(idp_pki, mock_idp, oidc_keys_full):
    # F009b criterion 1: with only --oidc-issuer set (no --oidc-jwks-url), init
    # discovers the JWKS endpoint from /.well-known/openid-configuration.
    server = _oidc_server(idp_pki, mock_idp, use_discovery=True, policy=_oidc_policy())
    try:
        server.start()
        tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, roles=("llm-admins",))
        res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {tok}"})
        assert res.status_code == 200
    finally:
        _cleanup(server)


# ---------------------------------------------------------------------------
# Hardening regression tests (challenger findings S-1/S-2/C-1/C-2 - NO blocker
# verdict on the crypto/identity boundary; these close four non-blocking gaps
# in the shared JWKS-cache/discovery code, all fixed in server-oidc.cpp).
# ---------------------------------------------------------------------------

def test_s1_expiry_refresh_bounded_hits_against_down_idp(idp_pki, mock_idp, oidc_keys_full, monkeypatch):
    # S-1: once the TTL expires against a DOWN IdP, refresh ATTEMPTS (not just
    # successes) must be rate-limited - a burst of validate() calls past expiry
    # must not turn into one outbound JWKS GET per inbound request (self-DoS /
    # IdP-hammering guard). Fail-static must still serve the cached kid1 the
    # whole time. LLAMA_OIDC_JWKS_REFRESH_MIN_INTERVAL_SECONDS is the S4-style
    # test-only override for the new min-interval anchor.
    monkeypatch.setenv("LLAMA_OIDC_JWKS_TTL_SECONDS", "1")
    monkeypatch.setenv("LLAMA_OIDC_JWKS_REFRESH_MIN_INTERVAL_SECONDS", "1")
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()
        mock_idp.set_mode("down")
        time.sleep(2.0)  # past both the 1s TTL and the 1s refresh-attempt interval
        hits_before = mock_idp.jwks_hits()
        tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, kid="kid1")
        for _ in range(6):
            res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {tok}"})
            assert res.status_code == 200, "fail-static: cached kid1 must still validate while IdP is down"
        hits_after = mock_idp.jwks_hits()
        assert hits_after - hits_before <= 1, (
            f"expected at most 1 refresh attempt across a burst of 6 requests past TTL "
            f"expiry, got {hits_after - hits_before} (expiry-refresh attempts are not rate-limited)"
        )
    finally:
        _cleanup(server)


def test_s2_oversized_jwks_response_fails_closed_at_boot(idp_pki, oidc_keys_full):
    # S-2: the 1 MiB body cap must be enforced DURING the read, not only after
    # the whole body is buffered. An oversized JWKS response at boot is treated
    # as a fetch failure - the mandatory initial fetch aborts startup
    # (fail-closed); the process must not OOM/crash while reading it.
    huge_jwks = {
        "keys": [oidc_keys_full.kid1_jwk],
        "padding": "A" * (2 * 1024 * 1024),  # 2 MiB, over the 1 MiB cap
    }
    idp = MockIdP(idp_pki.server_crt, idp_pki.server_key, huge_jwks)
    server = ServerPreset.tinyllama2()
    server.oidc_issuer = idp.issuer
    server.oidc_jwks_url = idp.jwks_url
    server.oidc_audience = "test-aud"
    server.oidc_ca_file = idp_pki.ca_crt
    policy_path = _write_policy(_oidc_policy())
    server.auth_policy_file = policy_path
    try:
        with pytest.raises((RuntimeError, TimeoutError)):
            server.start(timeout_seconds=15)
    finally:
        server.stop()
        os.remove(policy_path)
        idp.stop()


def test_c1_max_age_ceiling_clamps_runaway_cache_control(idp_pki, mock_idp, oidc_keys_full, monkeypatch):
    # C-1: a Cache-Control: max-age=999999999 (~31 years) from the IdP must be
    # clamped to a ceiling, not honored verbatim - otherwise a compromised IdP
    # could pin stale keys near-forever. Proven by shrinking the ceiling (S4-style
    # env override) to 1s and showing a rotated key becomes reachable via the
    # ordinary TTL-expiry refresh path shortly after, not ~31 years later.
    #
    # The unknown-kid refresh path (a SEPARATE rate-limited mechanism, see
    # test_key_rotation_new_kid_validates_after_refresh) would also happily pick
    # up a rotated key on its own and must not be allowed to confound this test.
    # It is deliberately "burned" on a throwaway bogus kid right after boot - the
    # very first unknown kid ever seen always triggers an immediate refresh
    # (last_unknown_kid_refresh starts at unix epoch 0), which then anchors
    # last_unknown_kid_refresh to "now" with the default 300s+jitter window -
    # long enough that it cannot fire again inside this test. Whatever picks up
    # kid2 below is therefore attributable ONLY to the TTL-expiry path, i.e. to
    # the max-age ceiling clamp actually working.
    monkeypatch.setenv("LLAMA_OIDC_JWKS_TTL_CEILING_SECONDS", "1")
    monkeypatch.setenv("LLAMA_OIDC_JWKS_REFRESH_MIN_INTERVAL_SECONDS", "0")
    mock_idp.set_jwks({"keys": [oidc_keys_full.kid1_jwk]}, cache_control="max-age=999999999")
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()

        # Burn the unknown-kid refresh budget on a throwaway kid.
        burn_tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, kid="burn-kid")
        res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {burn_tok}"})
        assert res.status_code == 401

        # Rotate in kid2 and wait past the CLAMPED ttl (not the advertised one).
        mock_idp.set_jwks({"keys": [oidc_keys_full.kid1_jwk, oidc_keys_full.kid2_jwk]})
        tok2 = _mint(mock_idp.issuer, oidc_keys_full.kid2_priv_pem, kid="kid2")
        time.sleep(1.5)
        res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {tok2}"})
        assert res.status_code == 200, (
            "kid2 should validate once the CLAMPED ttl elapses - a 401 here means "
            "max-age=999999999 was honored verbatim instead of being clamped"
        )
    finally:
        _cleanup(server)


def test_c2_discovery_issuer_mismatch_fails_startup(idp_pki, mock_idp, oidc_keys_full):
    # C-2: OIDC Discovery mandates the discovery document's "issuer" match the
    # configured --oidc-issuer exactly. A discovery response advertising a
    # different issuer must fail server startup (fail-closed), never be trusted.
    mock_idp.set_discovery_issuer_override("https://not-the-configured-issuer.invalid")
    server = _oidc_server(idp_pki, mock_idp, use_discovery=True, policy=_oidc_policy())
    try:
        with pytest.raises((RuntimeError, TimeoutError)):
            server.start(timeout_seconds=15)
    finally:
        server.stop()
        if hasattr(server, "_policy_path"):
            os.remove(server._policy_path)


# ---------------------------------------------------------------------------
# F010b: OIDC RFC-7662 opaque-token introspection.
#
# Feature -> acceptance criterion -> test mapping recorded in features.json
# test_refs. Design doc: docs/design/pr5-optional.md section 3, BINDING
# blockers B1/B2 in section 8.1/8.2, R6-R14 in section 8.4, precedence answer
# OQ-B1 in section 8.5, test-plan corrections in section 8.6.
#
# Negative first. mock_idp's new /introspect endpoint (added above) returns a
# configurable JSON body and counts hits, mirroring the existing jwks_hits
# pattern, so every "must not reach the IdP" assertion is a real counter check,
# not an inference from timing.
# ---------------------------------------------------------------------------

def test_introspection_inactive_denied(idp_pki, mock_idp):
    # F010b: "introspection returning active:false ... yields 401"
    mock_idp.set_introspect_response({"active": False})
    server = _introspect_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()
        res = server.make_request("GET", "/props", headers={"Authorization": "Bearer opaque-token-1"})
        assert res.status_code == 401
    finally:
        _cleanup_introspect(server)


def test_introspection_missing_aud_denied(idp_pki, mock_idp):
    # BLOCKER B1 (the single most important test in this file): an introspection
    # response with active:true but NO aud field at all must be denied. Without
    # this check, any active token from the same IdP realm issued to a DIFFERENT
    # client would be accepted here (cross-service token replay -> privilege
    # escalation - see design section 8.1 for the full attack scenario).
    mock_idp.set_introspect_response(_introspect_resp(active=True, no_aud=True, roles=("llm-admins",)))
    server = _introspect_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()
        res = server.make_request("GET", "/props", headers={"Authorization": "Bearer opaque-token-2"})
        assert res.status_code == 401
    finally:
        _cleanup_introspect(server)


def test_introspection_non_intersecting_audience_denied(idp_pki, mock_idp):
    # BLOCKER B1: aud present but does not intersect the configured --oidc-audience.
    mock_idp.set_introspect_response(_introspect_resp(active=True, aud="some-other-service", roles=("llm-admins",)))
    server = _introspect_server(idp_pki, mock_idp, audience="test-aud", policy=_oidc_policy())
    try:
        server.start()
        res = server.make_request("GET", "/props", headers={"Authorization": "Bearer opaque-token-3"})
        assert res.status_code == 401
    finally:
        _cleanup_introspect(server)


def test_introspection_audience_array_intersection_accepted(idp_pki, mock_idp):
    # BLOCKER B1 (positive half): aud MAY be a JSON array; a match anywhere in
    # the array is sufficient, matching "accept a JSON string or a JSON array".
    mock_idp.set_introspect_response(
        _introspect_resp(active=True, extra={"aud": ["other-service", "test-aud"]}, roles=("llm-admins",))
    )
    server = _introspect_server(idp_pki, mock_idp, audience="test-aud", policy=_oidc_policy())
    try:
        server.start()
        res = server.make_request("GET", "/props", headers={"Authorization": "Bearer opaque-token-array-aud"})
        assert res.status_code == 200
    finally:
        _cleanup_introspect(server)


def test_introspection_wrong_issuer_denied(idp_pki, mock_idp):
    # BLOCKER B1 (cont.): when --oidc-issuer is ALSO configured (turning on the
    # full JWKS path per section 8.0 note 2), the introspection response's iss
    # must equal it; absent or mismatched -> deny.
    mock_idp.set_introspect_response(
        _introspect_resp(active=True, iss="https://not-the-configured-issuer.invalid", roles=("llm-admins",))
    )
    server = _introspect_server(idp_pki, mock_idp, issuer=mock_idp.issuer, policy=_oidc_policy())
    try:
        server.start()
        res = server.make_request("GET", "/props", headers={"Authorization": "Bearer opaque-token-4"})
        assert res.status_code == 401
    finally:
        _cleanup_introspect(server)


def test_introspection_expired_exp_denied(idp_pki, mock_idp):
    # BLOCKER B1 (cont.): exp already past (+ clock skew) -> deny, even though
    # active:true was returned (not every IdP time-checks on introspection).
    mock_idp.set_introspect_response(_introspect_resp(active=True, exp_delta=-120, roles=("llm-admins",)))
    server = _introspect_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()
        res = server.make_request("GET", "/props", headers={"Authorization": "Bearer opaque-token-5"})
        assert res.status_code == 401
    finally:
        _cleanup_introspect(server)


def test_introspection_future_nbf_denied(idp_pki, mock_idp):
    # BLOCKER B1 (cont.): nbf in the future -> deny.
    mock_idp.set_introspect_response(_introspect_resp(active=True, nbf_delta=120, roles=("llm-admins",)))
    server = _introspect_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()
        res = server.make_request("GET", "/props", headers={"Authorization": "Bearer opaque-token-6"})
        assert res.status_code == 401
    finally:
        _cleanup_introspect(server)


def test_introspection_active_without_sub_denied(idp_pki, mock_idp):
    # F010b: "active:true without sub" -> denied (a principal with no subject is
    # not usable).
    mock_idp.set_introspect_response(_introspect_resp(active=True, no_sub=True, roles=("llm-admins",)))
    server = _introspect_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()
        res = server.make_request("GET", "/props", headers={"Authorization": "Bearer opaque-token-7"})
        assert res.status_code == 401
    finally:
        _cleanup_introspect(server)


@pytest.mark.parametrize("mode", ["down", "redirect"])
def test_introspection_endpoint_failure_denied_and_not_valid_as_api_key(idp_pki, mock_idp, mode):
    # F010b: "a network/HTTP error, a redirect, or a non-200 yields 401" - and,
    # per OQ-B1, an opaque value that fails introspection is NOT retried against
    # the api-key table unless it actually matches a configured key (api-key is
    # checked BEFORE introspection, so a mismatching opaque value simply denies).
    mock_idp.set_introspect_mode(mode)
    policy = _oidc_policy({"api_keys": {hashlib.sha256(b"sk-real-key").hexdigest(): "admin"}})
    server = _introspect_server(idp_pki, mock_idp, policy=policy, api_key="sk-real-key")
    try:
        server.start()
        res = server.make_request("GET", "/props", headers={"Authorization": "Bearer not-the-real-key"})
        assert res.status_code == 401
        # the ACTUAL api key still works independently of the broken introspection endpoint
        res = server.make_request("GET", "/props", headers={"Authorization": "Bearer sk-real-key"})
        assert res.status_code == 200
    finally:
        _cleanup_introspect(server)
        mock_idp.set_introspect_mode("normal")


@pytest.mark.parametrize("mapped_role,expect_props,expect_completions", [
    ("llm-admins", 200, 200),
    ("llm-users", 403, 200),
])
def test_introspection_valid_token_authorizes_per_role(idp_pki, mock_idp, mapped_role, expect_props, expect_completions):
    # F010b: "a valid opaque bearer token (active:true, matching aud, mapped
    # role) is authorized per its mapped permissions" - admin maps to READ_STATE
    # (/props) and INFER (/completions); user maps to INFER only.
    mock_idp.set_introspect_response(_introspect_resp(active=True, roles=(mapped_role,)))
    server = _introspect_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()
        headers = {"Authorization": "Bearer opaque-role-token"}
        res = server.make_request("GET", "/props", headers=headers)
        assert res.status_code == expect_props
        res = server.make_request("POST", "/completions", headers=headers,
                                   data={"prompt": "hi", "n_predict": 1})
        assert res.status_code == expect_completions
    finally:
        _cleanup_introspect(server)


def test_introspection_unmapped_role_authenticated_but_forbidden(idp_pki, mock_idp):
    # F010b: "unmapped/absent roles -> authenticated with perms=0 -> 403 (never a
    # default role)".
    mock_idp.set_introspect_response(_introspect_resp(active=True, roles=("some-unmapped-role",)))
    server = _introspect_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()
        res = server.make_request("GET", "/props", headers={"Authorization": "Bearer opaque-unmapped"})
        assert res.status_code == 403
    finally:
        _cleanup_introspect(server)


def test_introspection_client_secret_sent_as_basic_auth(idp_pki, mock_idp):
    # F010b: "assert the received Authorization: Basic header decodes to the
    # configured client id and the secret read from the file" - the only direct
    # test that the secret-from-file plumbing actually reaches the wire.
    mock_idp.set_introspect_response(_introspect_resp(active=True, roles=("llm-admins",)))
    server = _introspect_server(idp_pki, mock_idp, client_id="my-client-id",
                                 secret="my-s3cret-value", policy=_oidc_policy())
    try:
        server.start()
        res = server.make_request("GET", "/props", headers={"Authorization": "Bearer opaque-basic-auth-check"})
        assert res.status_code == 200
        auth_header = mock_idp.introspect_last_auth_header()
        assert auth_header is not None and auth_header.startswith("Basic ")
        decoded = base64.b64decode(auth_header[len("Basic "):]).decode()
        assert decoded == "my-client-id:my-s3cret-value"
    finally:
        _cleanup_introspect(server)


def test_introspection_positive_cache_single_hit(idp_pki, mock_idp):
    # F010b: "repeated identical requests within the positive window do not
    # re-hit the endpoint" - two identical opaque tokens back to back cause
    # exactly ONE outbound introspection POST.
    mock_idp.set_introspect_response(_introspect_resp(active=True, roles=("llm-admins",)))
    server = _introspect_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()
        hits_before = mock_idp.introspect_hits()
        headers = {"Authorization": "Bearer opaque-cache-token"}
        res1 = server.make_request("GET", "/props", headers=headers)
        res2 = server.make_request("GET", "/props", headers=headers)
        assert res1.status_code == 200
        assert res2.status_code == 200
        assert mock_idp.introspect_hits() - hits_before == 1, (
            "identical token within the positive TTL must be served from cache"
        )
    finally:
        _cleanup_introspect(server)


def test_introspection_negative_cache_expires(idp_pki, mock_idp, monkeypatch):
    # F010b / R8: negative results are cached only a FEW seconds, not forever -
    # shrink the negative TTL via the test-only env override (mirrors the
    # existing LLAMA_OIDC_JWKS_TTL_SECONDS pattern) so this is fast and
    # deterministic instead of a real 5s sleep against the production default.
    monkeypatch.setenv("LLAMA_OIDC_INTROSPECT_NEG_TTL_SECONDS", "1")
    mock_idp.set_introspect_response({"active": False})
    server = _introspect_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()
        headers = {"Authorization": "Bearer opaque-neg-cache-token"}
        hits_before = mock_idp.introspect_hits()
        res = server.make_request("GET", "/props", headers=headers)
        assert res.status_code == 401
        assert mock_idp.introspect_hits() - hits_before == 1

        time.sleep(1.5)  # past the 1s negative TTL
        res = server.make_request("GET", "/props", headers=headers)
        assert res.status_code == 401
        assert mock_idp.introspect_hits() - hits_before == 2, (
            "a negative cache entry must expire (not be cached forever)"
        )
    finally:
        _cleanup_introspect(server)


def test_introspection_rate_limit_denies_without_hitting_idp(idp_pki, mock_idp, monkeypatch):
    # BLOCKER B2: introspection POSTs are globally rate-limited. With the limit
    # shrunk to 1/sec (LLAMA_OIDC_INTROSPECT_MAX_PER_SECOND, R8 env override),
    # two DISTINCT opaque tokens fired back to back must cause at most one
    # outbound POST - the second is denied fail-fast, WITHOUT reaching the mock.
    monkeypatch.setenv("LLAMA_OIDC_INTROSPECT_MAX_PER_SECOND", "1")
    mock_idp.set_introspect_response(_introspect_resp(active=True, roles=("llm-admins",)))
    server = _introspect_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()
        hits_before = mock_idp.introspect_hits()
        res1 = server.make_request("GET", "/props", headers={"Authorization": "Bearer rl-token-one"})
        res2 = server.make_request("GET", "/props", headers={"Authorization": "Bearer rl-token-two"})
        hits_after = mock_idp.introspect_hits()
        assert res1.status_code == 200
        assert res2.status_code == 401
        assert hits_after - hits_before == 1, (
            f"rate-limited request must not reach the mock IdP (got {hits_after - hits_before} hits)"
        )
    finally:
        _cleanup_introspect(server)


@pytest.mark.parametrize("bad_token", [
    "x" * 4097,               # over the 4096-byte length cap
    "abc def!not-b64token",   # contains a space and '!' - outside RFC 6750 b64token charset
])
def test_introspection_preflight_rejects_without_network_call(idp_pki, mock_idp, bad_token):
    # F010b / BLOCKER B2: "tokens >4096 bytes or outside the RFC 6750 b64token
    # charset are denied with no network call" - the cheap pre-flight filter.
    mock_idp.set_introspect_response(_introspect_resp(active=True, roles=("llm-admins",)))
    server = _introspect_server(idp_pki, mock_idp, policy=_oidc_policy())
    try:
        server.start()
        hits_before = mock_idp.introspect_hits()
        res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {bad_token}"})
        assert res.status_code == 401
        assert mock_idp.introspect_hits() == hits_before, "oversized/invalid-charset token must never reach the IdP"
    finally:
        _cleanup_introspect(server)


def test_api_key_precedes_introspection_zero_introspect_hits(idp_pki, mock_idp):
    # OQ-B1 (design section 8.5, binding): with BOTH --api-key (via policy
    # api_keys) and introspection configured, "Authorization: Bearer <valid-api-
    # key>" still authenticates as auth_method=api_key with ZERO hits on the
    # mock introspection endpoint - the local hash lookup runs first and costs
    # nothing, so a valid key never reaches the network.
    mock_idp.set_introspect_response(_introspect_resp(active=True, roles=("llm-admins",)))
    policy = _oidc_policy({"api_keys": {hashlib.sha256(b"sk-admin-key").hexdigest(): "admin"}})
    server = _introspect_server(idp_pki, mock_idp, policy=policy, api_key="sk-admin-key")
    try:
        server.start()
        hits_before = mock_idp.introspect_hits()
        res = server.make_request("GET", "/props", headers={"Authorization": "Bearer sk-admin-key"})
        assert res.status_code == 200
        assert mock_idp.introspect_hits() == hits_before, "a valid API key must never reach introspection"
    finally:
        _cleanup_introspect(server)


def test_jwt_shaped_token_validated_locally_not_introspected(idp_pki, mock_idp, oidc_keys_full):
    # F010b: "Disambiguation: with BOTH JWT-OIDC and introspection configured, a
    # JWT-shaped token is validated locally (no introspection POST is made -
    # assert the mock is not called), an opaque token is introspected."
    server = _introspect_server(idp_pki, mock_idp, issuer=mock_idp.issuer, policy=_oidc_policy())
    try:
        server.start()
        hits_before = mock_idp.introspect_hits()
        tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, roles=("llm-admins",))
        res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {tok}"})
        assert res.status_code == 200
        assert mock_idp.introspect_hits() == hits_before, (
            "a JWT-shaped bearer must be validated locally, never introspected"
        )

        # and an opaque (non-JWT-shaped) token from the same server DOES reach
        # introspection - iss must match the configured --oidc-issuer (BLOCKER B1),
        # since this server also has the full JWKS path (and its issuer check) on.
        mock_idp.set_introspect_response(_introspect_resp(active=True, iss=mock_idp.issuer, roles=("llm-admins",)))
        res = server.make_request("GET", "/props", headers={"Authorization": "Bearer opaque-not-a-jwt"})
        assert res.status_code == 200
        assert mock_idp.introspect_hits() == hits_before + 1
    finally:
        _cleanup_introspect(server)


def test_introspection_only_mode_introspects_jwt_shaped_bearer(idp_pki, mock_idp, oidc_keys_full):
    # F010b: "introspection-only mode (no --oidc-issuer, no --oidc-jwks-url)
    # enforces auth, introspects ANY Bearer including a JWT-shaped one" - this
    # is the looks_like_jwt-guard-removal regression test (design section 8.5:
    # the section-3.4 `!looks_like_jwt(token)` condition was wrong and removed).
    server = _introspect_server(idp_pki, mock_idp, issuer=None, policy=_oidc_policy())
    try:
        server.start()
        # enforcement is ON even with no issuer/jwks configured at all
        res = server.make_request("GET", "/props")
        assert res.status_code == 401

        mock_idp.set_introspect_response(_introspect_resp(active=True, roles=("llm-admins",)))
        hits_before = mock_idp.introspect_hits()
        # a JWT-SHAPED token (3 dot-separated segments) - would be skipped by the
        # old looks_like_jwt guard; must now reach introspect() and authorize.
        jwt_shaped_tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, roles=("llm-admins",))
        res = server.make_request("GET", "/props", headers={"Authorization": f"Bearer {jwt_shaped_tok}"})
        assert res.status_code == 200
        assert mock_idp.introspect_hits() == hits_before + 1, (
            "a JWT-shaped bearer in introspection-only mode must reach introspect(), "
            "not be skipped by a stale looks_like_jwt guard"
        )
    finally:
        _cleanup_introspect(server)


# ---------------------------------------------------------------------------
# F010b startup fail-closed matrix.
# ---------------------------------------------------------------------------

def test_introspection_url_without_audience_aborts_startup(idp_pki, mock_idp):
    # BLOCKER B1: "--oidc-audience is REQUIRED when introspection is configured"
    server = _introspect_server(idp_pki, mock_idp, audience=None, policy=_oidc_policy())
    try:
        with pytest.raises((RuntimeError, TimeoutError)):
            server.start(timeout_seconds=15)
    finally:
        _cleanup_introspect(server)


def test_introspection_with_default_role_aborts_startup(idp_pki, mock_idp):
    # R12 item 6: "a policy default_role combined with --oidc-introspection-url
    # aborts startup" - otherwise the api-key branch authorizes every unknown
    # bearer with the default role and introspection is never reached (total
    # bypass).
    server = _introspect_server(idp_pki, mock_idp, policy=_oidc_policy({"default_role": "user"}))
    try:
        with pytest.raises((RuntimeError, TimeoutError)):
            server.start(timeout_seconds=15)
    finally:
        _cleanup_introspect(server)


def test_introspection_client_secret_interior_newline_aborts_startup(idp_pki, mock_idp):
    # F010b / R9: "a URL containing userinfo ... aborts startup; client_id
    # containing ':' or non-printable bytes aborts startup" section's secret
    # counterpart: the secret file is read in BINARY, all TRAILING CR/LF are
    # stripped, and an INTERIOR newline after stripping is fail-closed (wrong
    # file, e.g. a PEM) rather than silently truncated at the first line.
    secret_path = _write_secret("first-half\nsecond-half\n")
    server = _introspect_server(idp_pki, mock_idp, secret_file=secret_path, policy=_oidc_policy())
    try:
        with pytest.raises((RuntimeError, TimeoutError)):
            server.start(timeout_seconds=15)
    finally:
        server.stop()
        if hasattr(server, "_policy_path"):
            os.remove(server._policy_path)
        os.remove(secret_path)


def test_introspection_url_with_userinfo_aborts_startup(idp_pki, mock_idp):
    # R9: userinfo ('@' in the authority) in --oidc-introspection-url is a
    # secret-leak vector (common_http_client would pull it into Basic auth) and
    # must abort startup rather than silently using it.
    server = _introspect_server(idp_pki, mock_idp, policy=_oidc_policy())
    server.oidc_introspection_url = mock_idp.issuer.replace("https://", "https://user:pass@") + "/introspect"
    try:
        with pytest.raises((RuntimeError, TimeoutError)):
            server.start(timeout_seconds=15)
    finally:
        _cleanup_introspect(server)


def test_introspection_client_id_with_colon_aborts_startup(idp_pki, mock_idp):
    # R9: a client_id containing ':' would silently corrupt the Basic-auth
    # user:pass split at the IdP - reject at startup instead.
    server = _introspect_server(idp_pki, mock_idp, client_id="bad:client:id", policy=_oidc_policy())
    try:
        with pytest.raises((RuntimeError, TimeoutError)):
            server.start(timeout_seconds=15)
    finally:
        _cleanup_introspect(server)


def test_introspection_non_https_url_aborts_startup(idp_pki, mock_idp):
    # F010b: introspection requests are POST over HTTPS only - a plain http://
    # --oidc-introspection-url must abort startup (mirrors the JWKS https-only
    # rule; deliberately unreachable too, doesn't matter, rejected before any
    # connection attempt).
    server = _introspect_server(idp_pki, mock_idp, policy=_oidc_policy())
    server.oidc_introspection_url = "http://127.0.0.1:1/introspect"
    try:
        with pytest.raises((RuntimeError, TimeoutError)):
            server.start(timeout_seconds=15)
    finally:
        _cleanup_introspect(server)


# NOTE on criteria not covered by a dedicated test here (flagged, not silently
# skipped):
# - "OIDC configured for JWKS-only (no introspection flags) behaves identically
#   to pre-F010b" is verified by NOT modifying any pre-existing test in this
#   file and running the full test_oidc.py suite together with the new F010b
#   cases above (all F009 tests configure no introspection flags at all).
# - The 4096-entry cache hard cap (BLOCKER B2) is explicitly flagged as NOT
#   practically testable through this pytest harness per design section 8.6
#   ("4096 distinct tokens per test is too slow; state that explicitly rather
#   than writing a flaky test - it is covered by code review").
# - The defensive S1 invariant "has_introspect && !g_auth_enabled -> abort" has
#   no reachable black-box trigger: every code path that sets has_introspect
#   also ORs it into g_auth_enabled in the same init() call, so this is a
#   code-review-verified dead-path guard (reviewer_notes in features.json),
#   like its mTLS/OIDC counterparts elsewhere in server-auth.cpp.


# ---------------------------------------------------------------------------
# F013: mid-stream access-token expiry during long SSE streams.
#
# Feature -> acceptance criterion -> test mapping recorded in features.json
# test_refs. Design doc: docs/design/pr5-f013-sse-expiry.md, section 11
# (challenger revisions) is BINDING. Negative/regression cases first.
#
# Timing note (read before touching exp_delta/filler counts below): the
# tinyllama2 preset model (stories260K) evaluates at >1000 tok/s, so no
# n_predict/max_tokens value can make a SINGLE request's own generation span
# multiple seconds within its n_ctx=512 - per-token latency is sub-
# millisecond. There is therefore no way to black-box-observe "some real
# content chunks delivered, then a cut mid-generation" (true B1 timing
# precision) with this model/harness; the design's own test strategy
# (section 9) hits the same wall and does not attempt it either. The cases
# below instead queue the target request behind a burst of filler streaming
# completions on the server's single slot (--parallel 1), so the DEADLINE is
# already in the past by the time the target reaches the front of the queue
# and the gate's checks run for the first time. This exercises the exact same
# gate code on both sides of next() (B1's pre-check and post-check) and
# proves the identical security property - "no content is ever written at or
# after the deadline" - just via "zero content chunks delivered before the
# cut" rather than "some chunks, then a cut mid-stream". Genuine sub-second
# B1 timing precision (a real chunk mid-generation, immediately followed by a
# cut) is flagged here as NOT black-box-testable with this model/harness; it
# is covered by the reviewer's line-by-line code-inspection pass instead
# (features.json reviewer_notes: "B1 confirmed live in server-http.cpp...").
# ---------------------------------------------------------------------------

_F013_FILLER_COUNT = 25
_F013_FILLER_MAX_TOKENS = 500


def _f013_queue_fillers(server, headers, n=_F013_FILLER_COUNT, max_tokens=_F013_FILLER_MAX_TOKENS):
    """Fire n background streaming completions to occupy the server's single slot
    (n_slots=1) so a request submitted right after this call sits queued long enough
    to cross a short exp_delta deadline before its own first token is produced."""
    url = f"http://{server.server_host}:{server.server_port}/v1/chat/completions"
    payload = {
        "model": "test",
        "messages": [{"role": "user", "content": "Once upon a time"}],
        "max_tokens": max_tokens,
        "stream": True,
    }

    def _filler():
        try:
            r = requests.post(url, headers=headers, json=payload, stream=True, timeout=60)
            for _ in r.iter_lines():
                pass  # drain fully so the connection (and the slot) stays held for the whole generation
        except requests.exceptions.RequestException:
            pass

    threads = []
    for _ in range(n):
        t = threading.Thread(target=_filler, daemon=True)
        threads.append(t)
        t.start()
        time.sleep(0.01)  # stagger submission so fillers queue in a stable, predictable order
    return threads


def _f013_raw_stream_post(server, path, headers, data, timeout=60):
    """POST a streaming request with the raw requests library (not make_stream_request,
    which special-cases 'data: ' lines and stops at [DONE]) so the exact SSE bytes of a
    cut - including the absence of [DONE] - can be asserted verbatim."""
    url = f"http://{server.server_host}:{server.server_port}{path}"
    resp = requests.post(url, headers=headers, json=data, stream=True, timeout=timeout)
    body = resp.text  # blocks until the server closes the connection (sink.done())
    return resp.status_code, body


def test_f013_sse_stream_cut_on_token_expiry_oai_dialect(idp_pki, mock_idp, oidc_keys_full):
    # F013 acceptance criteria 2 (B1: checked before AND after next()), 7 (deadline =
    # expires_at + clamp(skew,0,300)), 9 (exact OAI cut bytes, no [DONE]), 15 (empty
    # sse_expired_chunk falls back to the OAI helper - default dialect here).
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy(), clock_skew=0)
    server.n_slots = 1
    try:
        server.start()
        filler_tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, exp_delta=300)
        _f013_queue_fillers(server, {"Authorization": f"Bearer {filler_tok}"})

        target_tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, exp_delta=4)
        status, body = _f013_raw_stream_post(
            server, "/v1/chat/completions",
            headers={"Authorization": f"Bearer {target_tok}"},
            data={
                "model": "test",
                "messages": [{"role": "user", "content": "hello"}],
                "max_tokens": 500,
                "stream": True,
            },
        )
        assert status == 200, "headers are already flushed before the cut, status stays 200"
        expected = ('data: {"error":{"code":401,"message":"access token expired",'
                    '"type":"authentication_error"}}\n\n')
        assert expected in body, f"expected the exact OAI expiry chunk, got: {body!r}"
        assert "data: [DONE]" not in body, "a cut stream must never reach normal [DONE] termination"
    finally:
        _cleanup(server)


def test_f013_sse_stream_no_false_positive_long_lived_token(idp_pki, mock_idp, oidc_keys_full):
    # F013 acceptance criterion 10 ("no false positive"): the SAME server config but a
    # token comfortably inside its expiry (exp_delta=300) streams to a normal
    # 'data: [DONE]' termination with no error chunk - the gate is not a trap that fires
    # on every stream regardless of expiry.
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy(), clock_skew=0)
    try:
        server.start()
        tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, exp_delta=300)
        chunks = list(server.make_stream_request(
            "POST", "/v1/chat/completions",
            data={"model": "test", "messages": [{"role": "user", "content": "hello"}],
                  "max_tokens": 16, "stream": True},
            headers={"Authorization": f"Bearer {tok}"},
        ))
        assert chunks, "expected at least one real content chunk"
        assert not any("error" in c for c in chunks), f"unexpected error chunk: {chunks}"
    finally:
        _cleanup(server)


def test_f013_expires_at_zero_never_cut_regression():
    # F013 acceptance criterion 4 (REQUIRED regression guard): expires_at == 0 principals
    # (API-key, mTLS, trusted-proxy, auth-disabled) are NEVER cut - stream_deadline()
    # returns 0 for them and stream_expired(0) is always false. An API-key-ONLY server (no
    # OIDC configured at all) streams a completion to normal 'data: [DONE]' termination.
    server = ServerPreset.tinyllama2()
    server.api_key = "sk-f013-regression"
    try:
        server.start()
        chunks = list(server.make_stream_request(
            "POST", "/v1/chat/completions",
            data={"model": "test", "messages": [{"role": "user", "content": "hello"}],
                  "max_tokens": 400, "stream": True},
            headers={"Authorization": "Bearer sk-f013-regression"},
        ))
        assert chunks, "expected real content chunks"
        assert not any("error" in c for c in chunks), f"unexpected error chunk: {chunks}"
    finally:
        server.stop()


def test_f013_already_expired_token_at_stream_start_gets_401(idp_pki, mock_idp, oidc_keys_full):
    # F013: no regression to the EXISTING pre-stream auth check - a token already expired
    # (well beyond clock-skew) when a streaming request arrives is denied at
    # authorize_request exactly like any non-streaming request. F013 only governs bytes
    # written AFTER a stream has already been admitted, never initial admission.
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy(), clock_skew=0)
    try:
        server.start()
        tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, exp_delta=-120)
        res = server.make_request("POST", "/v1/chat/completions",
                                   data={"model": "test", "messages": [{"role": "user", "content": "hello"}],
                                         "max_tokens": 16, "stream": True},
                                   headers={"Authorization": f"Bearer {tok}"})
        assert res.status_code == 401
    finally:
        _cleanup(server)


def test_f013_skew_consistency_token_within_leeway_not_cut_immediately(idp_pki, mock_idp, oidc_keys_full):
    # F013 acceptance criterion 11 / design 11.9 directed check 4: the grace equals the
    # SAME --oidc-clock-skew leeway that accepted the token, so a token minted comfortably
    # inside that window (exp_delta=-5 with skew=60) is not cut on the first provider
    # invocation and yields at least one real content chunk.
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy(), clock_skew=60)
    try:
        server.start()
        tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, exp_delta=-5)
        chunks = list(server.make_stream_request(
            "POST", "/v1/chat/completions",
            data={"model": "test", "messages": [{"role": "user", "content": "hello"}],
                  "max_tokens": 16, "stream": True},
            headers={"Authorization": f"Bearer {tok}"},
        ))
        assert chunks, "expected at least one real content chunk despite exp already in the past"
        assert not any("error" in c for c in chunks), f"unexpected error chunk: {chunks}"
    finally:
        _cleanup(server)


def test_f013_sse_stream_cut_anthropic_dialect(idp_pki, mock_idp, oidc_keys_full):
    # F013 acceptance criterion 12: streaming POST /v1/messages (Anthropic) gets the
    # 'event: error' dialect chunk, not the bare OAI 'data:' form (S3: built inline in
    # server-context.cpp using format_anthropic_sse, no server_auth:: symbol crosses into
    # the server-context static lib - see reviewer_notes for the code-inspection half).
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy(), clock_skew=0)
    server.n_slots = 1
    try:
        server.start()
        filler_tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, exp_delta=300)
        _f013_queue_fillers(server, {"Authorization": f"Bearer {filler_tok}"})

        target_tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, exp_delta=4)
        status, body = _f013_raw_stream_post(
            server, "/v1/messages",
            headers={"Authorization": f"Bearer {target_tok}"},
            data={"model": "test", "max_tokens": 500, "stream": True,
                  "messages": [{"role": "user", "content": "hello"}]},
        )
        assert status == 200
        expected = ('event: error\ndata: {"code":401,"message":"access token expired",'
                    '"type":"authentication_error"}\n\n')
        assert expected in body, f"expected the exact Anthropic expiry chunk, got: {body!r}"
    finally:
        _cleanup(server)


def test_f013_sse_stream_cut_responses_dialect_oq1(idp_pki, mock_idp, oidc_keys_full):
    # F013 CHALLENGER OQ1 (binding fix): /v1/responses gets format_oai_resp_sse's
    # 'event:'/'data:' framing, NOT the bare OAI 'data:'-only form - a data-only frame has
    # SSE event type 'message' and a Responses-API client silently drops it, which would
    # degrade the cut into exactly the silent truncation the design forbids.
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy(), clock_skew=0)
    server.n_slots = 1
    try:
        server.start()
        filler_tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, exp_delta=300)
        _f013_queue_fillers(server, {"Authorization": f"Bearer {filler_tok}"})

        target_tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, exp_delta=4)
        status, body = _f013_raw_stream_post(
            server, "/v1/responses",
            headers={"Authorization": f"Bearer {target_tok}"},
            data={"model": "test", "max_output_tokens": 500, "stream": True,
                  "input": [{"role": "user", "content": "hello"}]},
        )
        assert status == 200
        assert "event: error" in body, f"expected an 'event: error' frame, got: {body!r}"
        assert '"message":"access token expired"' in body
    finally:
        _cleanup(server)


def test_f013_non_streaming_single_server_unaffected_by_mid_gen_expiry(idp_pki, mock_idp, oidc_keys_full):
    # F013 acceptance criterion 19 (single-server half) / design section 7 scope decision:
    # non-streaming responses never enter the gated branch at all (the gate only lives
    # inside chunked_content_provider). A stream:false request whose token expires WHILE
    # queued/generating still returns a normal 200 with the full, parseable body.
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy(), clock_skew=0)
    server.n_slots = 1
    try:
        server.start()
        filler_tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, exp_delta=300)
        _f013_queue_fillers(server, {"Authorization": f"Bearer {filler_tok}"})

        target_tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, exp_delta=4)
        res = server.make_request("POST", "/v1/chat/completions",
                                   headers={"Authorization": f"Bearer {target_tok}"},
                                   data={"model": "test", "messages": [{"role": "user", "content": "hello"}],
                                         "max_tokens": 16, "stream": False},
                                   timeout=60)
        assert res.status_code == 200
        assert isinstance(res.body, dict), f"body must be parseable JSON: {res.body!r}"
        assert res.body.get("choices"), f"expected a real completion body, got: {res.body}"
    finally:
        _cleanup(server)


def test_f013_router_mode_non_streaming_unaffected_by_gate_b2(idp_pki, mock_idp, oidc_keys_full):
    # F013 CHALLENGER B2 (blocker): server_http_proxy sets next() unconditionally in
    # router mode, so a non-streaming JSON response is ALSO is_stream() there. The gate
    # must be inert unless content_type starts with 'text/event-stream' - a router-mode
    # stream:false chat/completions whose token expires during the child's compute must
    # still come back as a well-formed JSON body with no SSE 'data:' bytes glued onto it.
    server = ServerPreset.router()
    server.oidc_issuer = mock_idp.issuer
    server.oidc_jwks_url = mock_idp.jwks_url
    server.oidc_audience = "test-aud"
    server.oidc_ca_file = idp_pki.ca_crt
    server.oidc_clock_skew = 0
    policy_path = _write_policy(_oidc_policy())
    server.auth_policy_file = policy_path
    try:
        server.start()
        admin_tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, exp_delta=300)
        headers = {"Authorization": f"Bearer {admin_tok}"}
        # warm the model up first (on-demand autoload can take several seconds) outside the
        # timing-sensitive part of the test, so only the child's compute time below has to
        # outlast the short-lived token.
        server.make_request("POST", "/v1/chat/completions", headers=headers, data={
            "model": "ggml-org/tinygemma3-GGUF:Q8_0",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 4,
        })

        target_tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, exp_delta=2)
        res = server.make_request("POST", "/v1/chat/completions",
                                   headers={"Authorization": f"Bearer {target_tok}"},
                                   data={
                                       "model": "ggml-org/tinygemma3-GGUF:Q8_0",
                                       "messages": [{"role": "user", "content": "Once upon a time"}],
                                       "max_tokens": 1000,
                                       "stream": False,
                                   })
        assert res.status_code == 200, f"expected a normal 200 JSON response, got {res.status_code}: {res.body}"
        assert isinstance(res.body, dict), f"body must be parseable JSON, not SSE-corrupted text: {res.body!r}"
        assert "data:" not in json.dumps(res.body)
        assert res.body.get("choices"), f"expected a real completion body, got: {res.body}"
    finally:
        server.stop()
        os.remove(policy_path)


def test_f013_cut_stream_evicts_replay_session_oq3(idp_pki, mock_idp, oidc_keys_full):
    # F013 CHALLENGER OQ3 (binding fix, the answer to "should the spipe drain be gated"):
    # on cut, server_res_spipe::on_complete() evicts the replay session via the SAME
    # g_stream_sessions.evict_and_cancel() path DELETE /v1/stream already uses, instead of
    # draining the rest of the generation into the replay buffer on behalf of an expired
    # principal. A subsequent GET /v1/stream for the same conv_id must be 404 (not a
    # still-live/replayable session), and the freed slot must serve a fresh request promptly.
    server = _oidc_server(idp_pki, mock_idp, policy=_oidc_policy(), clock_skew=0)
    server.n_slots = 1
    try:
        server.start()
        filler_tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, exp_delta=300)
        _f013_queue_fillers(server, {"Authorization": f"Bearer {filler_tok}"})

        conv_id = "f013-oq3-conv"
        target_tok = _mint(mock_idp.issuer, oidc_keys_full.kid1_priv_pem, exp_delta=4)
        status, body = _f013_raw_stream_post(
            server, "/v1/chat/completions",
            headers={"Authorization": f"Bearer {target_tok}", "X-Conversation-Id": conv_id},
            data={"model": "test", "messages": [{"role": "user", "content": "hello"}],
                  "max_tokens": 500, "stream": True},
        )
        assert status == 200
        assert "access token expired" in body

        res = server.make_request("GET", f"/v1/stream?conv_id={conv_id}&from=0",
                                   headers={"Authorization": f"Bearer {filler_tok}"})
        assert res.status_code == 404, (
            "the replay session must be evicted on cut, not left live for an expired principal"
        )

        # the slot itself is released promptly: a fresh request completes without hanging
        # behind whatever was left of the cut generation.
        res = server.make_request("POST", "/completions",
                                   headers={"Authorization": f"Bearer {filler_tok}"},
                                   data={"prompt": "hi", "n_predict": 1}, timeout=15)
        assert res.status_code == 200, "the slot was not released promptly after the cut"
    finally:
        _cleanup(server)


# NOTE on F013 criteria not covered by a dedicated test here (flagged, not silently
# skipped - matches the F010b convention above):
# - Criterion 1 ("the gate lives in server-http.cpp::process_handler_response and
#   nowhere else; server-models.cpp, server-tools.cpp, server.cpp, common/arg.cpp and
#   common/common.h are unmodified") is a diff-shape property, not observable over HTTP.
#   Verified by the reviewer's grep-based pass (features.json reviewer_notes: "single
#   deadline-compute site (server-http.cpp only)...").
# - Criterion 5 (S2: stream_deadline() saturates to INT64_MAX instead of wrapping for a
#   principal with expires_at near INT64_MAX) cannot be reached black-box: no real JWT
#   library will mint an 'exp' claim anywhere near INT64_MAX, and OIDC init would treat a
#   non-integral/absurd exp as invalid before it ever reaches this arithmetic. Verified by
#   the reviewer's code-inspection pass, not a pytest here.
# - Criterion 6 (auth-method-agnostic: no AUTH_OIDC/p.method reference in the F013 code
#   path in server-auth.cpp) is a grep-based source property, not an HTTP-observable one.
#   Verified by reviewer_notes; F010b's introspection tests above already prove the
#   *effect* (expires_at gates streams regardless of how it was populated) is consistent,
#   even though F010b introspection responses in this suite always set a far-future exp,
#   so they never actually trigger a cut - that would be redundant with the OIDC-JWT cut
#   tests above, since the gate keys off expires_at only, never off method.
# - Criterion 14 (S3: server-context.cpp contains ZERO server_auth:: references) is a
#   grep-based static-lib-boundary property (verified against tests/CMakeLists.txt's
#   test-chat target linking server-context standalone). Not HTTP-observable.
# - Criterion 17 (SRV_WRN log line, no subject/path/token/DN/Authorization value, no
#   audit_emit line added) would require capturing and parsing the server's own log
#   stream for a negative property (absence of a raw token/secret substring). This
#   suite does not currently assert against server log output for any other feature
#   either; flagged here as reviewer-verified (features.json reviewer_notes confirms
#   SRV_WRN is used, not SRV_INF, and no audit_emit was added) rather than re-verified
#   by a pytest.
