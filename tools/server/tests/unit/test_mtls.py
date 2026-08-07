import datetime
import json
import os
import shutil
import subprocess
import tempfile
import time
from types import SimpleNamespace

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from utils import ServerPreset

# PR3 F008a-d: mTLS client-certificate authentication.
#
# Feature -> acceptance criterion -> test mapping is recorded in features.json test_refs
# (all of F008a/b/c/d point at this file); each test below carries a comment naming the
# criterion it exercises.
#
# NOTE: the harness stops every server after each test (conftest autouse), so each test
# starts its own server rather than sharing one, per the existing test_trusted_proxy.py /
# test_authz.py convention.
#
# PKI: a throwaway CA + server cert + several client certs are generated once per test
# session with the `openssl` CLI (no dependency on the `cryptography` python package -
# not confirmed present in the test venv). See the `mtls_pki` fixture below.


def _run_openssl(args, cwd):
    proc = subprocess.run(
        ["openssl", *args], cwd=cwd, capture_output=True, text=True
    )
    assert proc.returncode == 0, (
        f"openssl {' '.join(args)} failed:\nstdout={proc.stdout}\nstderr={proc.stderr}"
    )
    return proc


def _gen_ca(cwd, name, cn):
    key = f"{name}.key"
    crt = f"{name}.crt"
    _run_openssl(["genrsa", "-out", key, "2048"], cwd)
    _run_openssl(
        [
            "req", "-x509", "-new", "-nodes", "-key", key, "-sha256", "-days", "3",
            "-out", crt, "-subj", f"/CN={cn}",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ],
        cwd,
    )
    return os.path.join(cwd, crt), os.path.join(cwd, key)


def _gen_leaf(cwd, name, cn, san_ext, eku, ca_crt, ca_key, not_before=None, not_after=None):
    key = f"{name}.key"
    csr = f"{name}.csr"
    crt = f"{name}.crt"
    extfile = f"{name}_ext.cnf"
    with open(os.path.join(cwd, extfile), "w") as f:
        f.write(f"subjectAltName={san_ext}\nextendedKeyUsage={eku}\n")
    _run_openssl(["genrsa", "-out", key, "2048"], cwd)
    _run_openssl(["req", "-new", "-key", key, "-out", csr, "-subj", f"/CN={cn}"], cwd)
    sign_args = [
        "x509", "-req", "-in", csr,
        "-CA", ca_crt, "-CAkey", ca_key, "-CAcreateserial",
        "-out", crt, "-days", "3", "-sha256",
        "-extfile", os.path.join(cwd, extfile),
    ]
    if not_before:
        sign_args += ["-not_before", not_before]
    if not_after:
        sign_args += ["-not_after", not_after]
    _run_openssl(sign_args, cwd)
    return os.path.join(cwd, crt), os.path.join(cwd, key)


# ---------------------------------------------------------------------------
# F010a: CRL generation helpers.
#
# The `cryptography` library's CertificateRevocationListBuilder is used for every
# CRL EXCEPT the "no nextUpdate field at all" case: that builder actively REFUSES
# to sign a CRL missing nextUpdate ("A CRL must have a next update time", verified
# empirically against cryptography 50.0.0) - correct RFC 5280 hygiene on its part,
# but it means the one malformed-CRL case F010a's R1 check exists to catch cannot
# be produced through the normal builder. `_gen_crl_no_next_update` falls back to
# asn1crypto's lower-level TbsCertList (where next_update really is OPTIONAL) to
# hand-build and RSA-sign a minimal CRL with the field omitted on purpose.
# ---------------------------------------------------------------------------

def _load_cert(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def _load_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _gen_crl(cwd, name, ca_crt_path, ca_key_path, revoked_cert_paths=(), next_update=None,
             out_path=None):
    """Build and sign a PEM CRL (nextUpdate always present) via `cryptography`.

    F016: out_path lets a caller pin the output to a FIXED path (rather than a
    name-derived one under `cwd`) so a test can rewrite the exact file the CRL
    reload thread is watching, in place, across multiple calls.
    """
    ca_cert = _load_cert(ca_crt_path)
    ca_key = _load_key(ca_key_path)
    now = datetime.datetime.now(datetime.timezone.utc)
    nu = next_update if next_update is not None else now + datetime.timedelta(days=1)
    # last_update must be strictly before next_update (enforced by the builder);
    # for an already-past nextUpdate, anchor last_update further back still.
    last_update = min(now - datetime.timedelta(minutes=1), nu - datetime.timedelta(minutes=1))
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.last_update(last_update)
    builder = builder.next_update(nu)
    for crt_path in revoked_cert_paths:
        cert = _load_cert(crt_path)
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(cert.serial_number)
            .revocation_date(now)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)
    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    path = out_path if out_path else os.path.join(cwd, f"{name}.crl")
    with open(path, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))
    return path


def _gen_crl_no_next_update(cwd, name, ca_crt_path, ca_key_path):
    """R1: a syntactically-valid, correctly-signed PEM CRL with nextUpdate OMITTED
    entirely (a "silent forever-CRL" - see the module comment above for why the
    `cryptography` builder cannot produce this on purpose)."""
    from asn1crypto import core as acore
    from asn1crypto import crl as acrl
    from asn1crypto import pem as apem
    from asn1crypto import x509 as ax509
    from cryptography.hazmat.primitives.asymmetric import padding

    with open(ca_crt_path, "rb") as f:
        ca_cert_asn1 = ax509.Certificate.load(apem.unarmor(f.read())[2])
    ca_key = _load_key(ca_key_path)

    now = datetime.datetime.now(datetime.timezone.utc)
    this_update = ax509.Time(name="utc_time", value=acore.UTCTime(now - datetime.timedelta(minutes=1)))
    tbs = acrl.TbsCertList({
        "version": "v2",
        "signature": {"algorithm": "sha256_rsa"},
        "issuer": ca_cert_asn1.subject,
        "this_update": this_update,
        # "next_update" deliberately omitted - this is the case under test.
    })
    tbs_der = tbs.dump()
    signature = ca_key.sign(tbs_der, padding.PKCS1v15(), hashes.SHA256())
    cert_list = acrl.CertificateList({
        "tbs_cert_list": tbs,
        "signature_algorithm": {"algorithm": "sha256_rsa"},
        "signature": signature,
    })
    path = os.path.join(cwd, f"{name}.crl")
    with open(path, "wb") as f:
        f.write(apem.armor("X509 CRL", cert_list.dump()))
    return path


@pytest.fixture(scope="session")
def mtls_pki():
    """Generate a throwaway PKI (CA + server cert + client certs) with the openssl CLI.

    Session-scoped: certs are immutable inputs, cheap to generate once and reuse across
    the many per-test servers in this file (each test still starts its own server).
    """
    tmpdir = tempfile.mkdtemp(prefix="mtls_pki_")
    try:
        ca_crt, ca_key = _gen_ca(tmpdir, "ca", "Test Good CA")
        wrong_ca_crt, wrong_ca_key = _gen_ca(tmpdir, "wrong_ca", "Test Wrong CA")

        server_crt, server_key = _gen_leaf(
            tmpdir, "server", "localhost",
            "DNS:localhost,IP:127.0.0.1", "serverAuth",
            ca_crt, ca_key,
        )

        # admin: exact-match role_map entry -> admin
        admin_crt, admin_key = _gen_leaf(
            tmpdir, "admin", "admin",
            "URI:spiffe://corp/admin", "clientAuth",
            ca_crt, ca_key,
        )
        # user: matches the spiffe://corp/ns/* wildcard -> user
        user_crt, user_key = _gen_leaf(
            tmpdir, "user", "user",
            "URI:spiffe://corp/ns/svc1", "clientAuth",
            ca_crt, ca_key,
        )
        # unmapped: valid, good-CA cert, but no role_map entry matches
        unmapped_crt, unmapped_key = _gen_leaf(
            tmpdir, "unmapped", "unmapped",
            "URI:spiffe://corp/other", "clientAuth",
            ca_crt, ca_key,
        )
        # wrong-CA: same admin-mapped SAN, but signed by a CA the server does not trust
        wrongca_crt, wrongca_key = _gen_leaf(
            tmpdir, "wrongca", "wrongca",
            "URI:spiffe://corp/admin", "clientAuth",
            wrong_ca_crt, wrong_ca_key,
        )
        # expired: good CA, but notBefore/notAfter both in the past
        expired_crt, expired_key = _gen_leaf(
            tmpdir, "expired", "expired",
            "URI:spiffe://corp/admin", "clientAuth",
            ca_crt, ca_key,
            not_before="20200101000000Z", not_after="20200102000000Z",
        )
        # C1: two URI SANs, one of which would map to admin if "first wins" were used
        twouri_crt, twouri_key = _gen_leaf(
            tmpdir, "twouri", "twouri",
            "URI:spiffe://corp/admin,URI:spiffe://corp/extra", "clientAuth",
            ca_crt, ca_key,
        )

        yield SimpleNamespace(
            dir=tmpdir,
            ca_crt=ca_crt, ca_key=ca_key,
            wrong_ca_crt=wrong_ca_crt, wrong_ca_key=wrong_ca_key,
            server_crt=server_crt, server_key=server_key,
            admin_crt=admin_crt, admin_key=admin_key,
            user_crt=user_crt, user_key=user_key,
            unmapped_crt=unmapped_crt, unmapped_key=unmapped_key,
            wrongca_crt=wrongca_crt, wrongca_key=wrongca_key,
            expired_crt=expired_crt, expired_key=expired_key,
            twouri_crt=twouri_crt, twouri_key=twouri_key,
        )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture(scope="session")
def crl_pki(mtls_pki):
    """F010a fixture: a dedicated client cert (same CA, same admin-mapped SAN as
    `mtls_pki.admin_crt`, but never used outside CRL tests) plus a handful of
    PEM CRL files exercising the R1 fail-closed matrix. Session-scoped: all
    inputs are immutable, and revocation status lives in the CRL FILE, not the
    cert, so `mtls_pki.admin_crt`/`user_crt` remain usable as "not on this CRL"
    positive cases elsewhere in this fixture set."""
    tmpdir = tempfile.mkdtemp(prefix="mtls_crl_")
    try:
        revoked_crt, revoked_key = _gen_leaf(
            tmpdir, "revoked", "revoked",
            "URI:spiffe://corp/admin", "clientAuth",
            mtls_pki.ca_crt, mtls_pki.ca_key,
        )
        good_crl = _gen_crl(
            tmpdir, "good", mtls_pki.ca_crt, mtls_pki.ca_key,
            revoked_cert_paths=[revoked_crt],
        )
        expired_crl = _gen_crl(
            tmpdir, "expired", mtls_pki.ca_crt, mtls_pki.ca_key,
            next_update=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1),
        )
        no_next_update_crl = _gen_crl_no_next_update(
            tmpdir, "no_next_update", mtls_pki.ca_crt, mtls_pki.ca_key,
        )
        yield SimpleNamespace(
            dir=tmpdir,
            revoked_crt=revoked_crt, revoked_key=revoked_key,
            good_crl=good_crl,
            expired_crl=expired_crl,
            no_next_update_crl=no_next_update_crl,
        )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _write_policy(policy: dict) -> str:
    fd, path = tempfile.mkstemp(suffix=".json", prefix="mtls_policy_")
    with os.fdopen(fd, "w") as f:
        json.dump(policy, f)
    return path


def _rbac_mtls_policy(extra: dict | None = None) -> dict:
    policy = {
        "roles": {
            "admin": ["INFER", "READ_STATE", "METRICS", "ADMIN_STATE", "ADMIN_MODELS"],
            "user": ["INFER"],
        },
        "default_role": None,
        "mtls": {
            "identity_source": "san_uri",
            "role_map": {
                "spiffe://corp/admin": "admin",
                "spiffe://corp/ns/*": "user",
            },
        },
    }
    if extra:
        policy.update(extra)
    return policy


def _mtls_server(pki, mtls_required, policy_path=None, api_key=None,
                  client_ca_file=True, probe_cert=None, crl_file=None,
                  crl_reload_interval=None):
    """Build a ServerProcess with HTTPS + mTLS flags. probe_cert=(crt,key) is used only
    for the start() readiness poll (set as the initial client_cert/key); tests then swap
    server.client_cert/client_key to whatever cert is actually under test before making
    their real request(s). This is necessary because required-mode negative tests (no
    cert / wrong CA / expired cert) would otherwise never let the server become ready.
    crl_file (F010a) threads --mtls-crl-file when set.
    crl_reload_interval (F016) threads --mtls-crl-reload-interval when set."""
    server = ServerPreset.tinyllama2()
    server.ssl_file_cert = pki.server_crt
    server.ssl_file_key = pki.server_key
    if client_ca_file:
        server.mtls_client_ca_file = pki.ca_crt
    server.mtls_required = mtls_required
    server.auth_policy_file = policy_path
    server.api_key = api_key
    server.ca_cert = pki.ca_crt  # test client verifies the server's cert
    if crl_file:
        server.mtls_crl_file = crl_file
    if crl_reload_interval is not None:
        server.mtls_crl_reload_interval = crl_reload_interval
    if probe_cert:
        server.client_cert, server.client_key = probe_cert
    return server


# ---------------------------------------------------------------------------
# Negative first: TLS-handshake-level rejections (F008b acceptance criteria 1, 2).
# These never reach HTTP; assert an exception, not a status code.
# ---------------------------------------------------------------------------

def test_required_mode_no_client_cert_rejected_at_handshake(mtls_pki):
    # F008b: "required mode: a client presenting no cert is rejected at the TLS
    # handshake (transport error), not with an HTTP status" (case 1)
    policy_path = _write_policy(_rbac_mtls_policy())
    server = _mtls_server(mtls_pki, "required", policy_path,
                           probe_cert=(mtls_pki.admin_crt, mtls_pki.admin_key))
    try:
        server.start()
        server.client_cert = None
        server.client_key = None
        with pytest.raises((requests.exceptions.SSLError, requests.exceptions.ConnectionError)):
            server.make_request("GET", "/props")
    finally:
        server.stop()
        os.remove(policy_path)


def test_wrong_ca_client_cert_rejected_at_handshake(mtls_pki):
    # F008b: "a client cert from a different CA ... rejected at the handshake in BOTH
    # optional and required mode" (case 2)
    policy_path = _write_policy(_rbac_mtls_policy())
    server = _mtls_server(mtls_pki, "required", policy_path,
                           probe_cert=(mtls_pki.admin_crt, mtls_pki.admin_key))
    try:
        server.start()
        server.client_cert = mtls_pki.wrongca_crt
        server.client_key = mtls_pki.wrongca_key
        with pytest.raises((requests.exceptions.SSLError, requests.exceptions.ConnectionError)):
            server.make_request("GET", "/props")
    finally:
        server.stop()
        os.remove(policy_path)


def test_expired_client_cert_rejected_at_handshake(mtls_pki):
    # F008b: "... and an expired cert signed by the good CA, are rejected at the
    # handshake in BOTH optional and required mode" (case 3)
    policy_path = _write_policy(_rbac_mtls_policy())
    server = _mtls_server(mtls_pki, "required", policy_path,
                           probe_cert=(mtls_pki.admin_crt, mtls_pki.admin_key))
    try:
        server.start()
        server.client_cert = mtls_pki.expired_crt
        server.client_key = mtls_pki.expired_key
        with pytest.raises((requests.exceptions.SSLError, requests.exceptions.ConnectionError)):
            server.make_request("GET", "/props")
    finally:
        server.stop()
        os.remove(policy_path)


# ---------------------------------------------------------------------------
# C1: ambiguous multi-SAN identity must be denied, not resolved to the first SAN.
# ---------------------------------------------------------------------------

def test_two_uri_sans_ambiguous_identity_denied(mtls_pki):
    # F008c/F008d: "a cert carrying two or more URI SANs ... leaves that identity field
    # EMPTY" -> authenticated, perms=0 -> 403, NOT 200 (case 12)
    policy_path = _write_policy(_rbac_mtls_policy())
    server = _mtls_server(mtls_pki, "required", policy_path,
                           probe_cert=(mtls_pki.twouri_crt, mtls_pki.twouri_key))
    try:
        server.start()
        res = server.make_request("GET", "/props")
        assert res.status_code == 403, (
            "ambiguous multi-URI-SAN cert must be denied (403), not first-wins-200"
        )
    finally:
        server.stop()
        os.remove(policy_path)


# ---------------------------------------------------------------------------
# SAN -> role mapping (F008d acceptance criteria).
# ---------------------------------------------------------------------------

def test_admin_san_authorized_on_read_state_and_metrics(mtls_pki):
    # F008d: "a valid client cert whose SAN maps to admin can POST /slots/0 (ADMIN_STATE)
    # with no API key" - probed here via READ_STATE (/props) and METRICS (/metrics),
    # which are simpler to assert without a loaded slot.
    policy_path = _write_policy(_rbac_mtls_policy())
    server = _mtls_server(mtls_pki, "required", policy_path,
                           probe_cert=(mtls_pki.admin_crt, mtls_pki.admin_key))
    server.server_metrics = True  # /metrics 501s without --metrics, independent of authz
    try:
        server.start()
        res = server.make_request("GET", "/props")
        assert res.status_code == 200
        res = server.make_request("GET", "/metrics")
        assert res.status_code == 200
    finally:
        server.stop()
        os.remove(policy_path)


def test_user_san_wildcard_infer_ok_read_state_forbidden(mtls_pki):
    # F008d: "a valid client cert whose SAN maps to user succeeds on POST /completions
    # (INFER) and gets 403 on POST /slots/0 (ADMIN_STATE)" - probed via READ_STATE
    # (/props) for the negative half, which does not require a loaded slot.
    policy_path = _write_policy(_rbac_mtls_policy())
    server = _mtls_server(mtls_pki, "required", policy_path,
                           probe_cert=(mtls_pki.user_crt, mtls_pki.user_key))
    try:
        server.start()
        res = server.make_request("GET", "/props")
        assert res.status_code == 403, "user lacks READ_STATE"
        res = server.make_request("POST", "/completions", data={"prompt": "hi", "n_predict": 1})
        assert res.status_code == 200, "user has INFER"
    finally:
        server.stop()
        os.remove(policy_path)


def test_unmapped_san_authenticated_but_forbidden(mtls_pki):
    # F008d: "a valid client cert with an UNMAPPED SAN is authenticated but perms=0 ->
    # 403 on any protected route (no default role, no fallback to API-key auth)"
    policy_path = _write_policy(_rbac_mtls_policy())
    server = _mtls_server(mtls_pki, "required", policy_path,
                           probe_cert=(mtls_pki.unmapped_crt, mtls_pki.unmapped_key))
    try:
        server.start()
        res = server.make_request("GET", "/props")
        assert res.status_code == 403
    finally:
        server.stop()
        os.remove(policy_path)


# ---------------------------------------------------------------------------
# Optional mode: falls through to API-key auth when no cert is presented.
# ---------------------------------------------------------------------------

def test_optional_mode_no_cert_falls_through_to_api_key(mtls_pki):
    # F008d: "optional mode with no cert but a valid API key falls through to API-key
    # auth (POST /completions succeeds); optional mode with no cert and no key -> 401
    # on a protected route" (cases 7, 8)
    policy_path = _write_policy(_rbac_mtls_policy({
        "api_keys": {
            __import__("hashlib").sha256(b"sk-user").hexdigest(): "user",
        },
    }))
    # optional mode: the readiness probe itself does not need a client cert (the TLS
    # handshake completes without one), so no probe_cert workaround is needed here.
    server = _mtls_server(mtls_pki, "optional", policy_path, api_key="sk-user")
    try:
        server.start()
        # no cert, valid api key -> falls through to api-key auth -> INFER allowed
        res = server.make_request(
            "POST", "/completions",
            data={"prompt": "hi", "n_predict": 1},
            headers={"Authorization": "Bearer sk-user"},
        )
        assert res.status_code == 200
        # no cert, no key -> anonymous -> 401 (enforcement is on)
        res = server.make_request("GET", "/props")
        assert res.status_code == 401
    finally:
        server.stop()
        os.remove(policy_path)


# ---------------------------------------------------------------------------
# S1 regression: mTLS-only mode (no policy/keys/proxies) must never allow-all.
# ---------------------------------------------------------------------------

def test_s1_mtls_only_mode_no_cert_no_key_denied(mtls_pki):
    # F008d: "S1 regression: mTLS-only mode (--mtls-required optional, no --api-key,
    # no --auth-policy-file, no --auth-trusted-proxies), a request with NO client cert
    # and NO key to a protected route returns 401, never 200 (server must not silently
    # allow-all)" (case 13). Also asserts the server actually STARTS in this mode.
    server = _mtls_server(mtls_pki, "optional", policy_path=None, api_key=None)
    try:
        server.start()  # must not raise: mTLS-only mode is a valid, supported config
        res = server.make_request("GET", "/props")
        assert res.status_code == 401
    finally:
        server.stop()


def test_s1_mtls_only_mode_any_valid_cert_never_200(mtls_pki):
    # F008d S1 regression, restated with a client cert present: mTLS required, no
    # policy/keys/proxies -> even a valid CA-signed cert (any SAN) must not be granted
    # access, because there is no role_map to authorize it against (empty map -> every
    # cert unmapped -> 403/401, never 200).
    server = _mtls_server(mtls_pki, "required", policy_path=None, api_key=None,
                           probe_cert=(mtls_pki.admin_crt, mtls_pki.admin_key))
    try:
        server.start()  # must not raise
        res = server.make_request("GET", "/props")
        assert res.status_code != 200
        assert res.status_code in (401, 403)
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# Startup fail-closed matrix (F008a/F008b acceptance criteria).
# ---------------------------------------------------------------------------

def test_required_mode_without_server_cert_aborts_startup(mtls_pki):
    # F008b: "--mtls-required optional/required without --ssl-cert-file/--ssl-key-file
    # aborts startup"
    server = ServerPreset.tinyllama2()
    server.mtls_client_ca_file = mtls_pki.ca_crt
    server.mtls_required = "required"
    with pytest.raises((RuntimeError, TimeoutError)):
        server.start(timeout_seconds=15)


def test_required_mode_without_ca_aborts_startup(mtls_pki):
    # F008b: "... without a client CA file or dir aborts startup"
    server = ServerPreset.tinyllama2()
    server.ssl_file_cert = mtls_pki.server_crt
    server.ssl_file_key = mtls_pki.server_key
    server.mtls_required = "required"
    with pytest.raises((RuntimeError, TimeoutError)):
        server.start(timeout_seconds=15)


def test_unknown_mtls_required_value_aborts_startup(mtls_pki):
    # F008b: "an unknown --mtls-required or --tls-min-version value ... aborts startup"
    server = ServerPreset.tinyllama2()
    server.ssl_file_cert = mtls_pki.server_crt
    server.ssl_file_key = mtls_pki.server_key
    server.mtls_client_ca_file = mtls_pki.ca_crt
    server.mtls_required = "bogus"
    with pytest.raises((RuntimeError, TimeoutError)):
        server.start(timeout_seconds=15)


def test_unknown_tls_min_version_aborts_startup(mtls_pki):
    server = ServerPreset.tinyllama2()
    server.ssl_file_cert = mtls_pki.server_crt
    server.ssl_file_key = mtls_pki.server_key
    server.tls_min_version = "1.4"
    with pytest.raises((RuntimeError, TimeoutError)):
        server.start(timeout_seconds=15)


def test_negative_verify_depth_aborts_startup(mtls_pki):
    # F008b: "a negative --mtls-verify-depth ... aborts startup"
    server = ServerPreset.tinyllama2()
    server.ssl_file_cert = mtls_pki.server_crt
    server.ssl_file_key = mtls_pki.server_key
    server.mtls_client_ca_file = mtls_pki.ca_crt
    server.mtls_required = "optional"
    server.mtls_verify_depth = -1
    with pytest.raises((RuntimeError, TimeoutError)):
        server.start(timeout_seconds=15)


def test_bare_star_role_map_pattern_aborts_startup(mtls_pki):
    # F008d: "... or a misplaced '*' aborts startup" - a bare '*' role_map pattern is
    # explicitly rejected (server-auth.cpp: "not a catch-all"), not silently treated as
    # match-everything.
    policy_path = _write_policy(_rbac_mtls_policy({
        "mtls": {
            "identity_source": "san_uri",
            "role_map": {"*": "user"},
        },
    }))
    server = _mtls_server(mtls_pki, "optional", policy_path)
    try:
        with pytest.raises((RuntimeError, TimeoutError)):
            server.start(timeout_seconds=15)
    finally:
        server.stop()
        os.remove(policy_path)


def test_role_map_unknown_role_aborts_startup(mtls_pki):
    # F008d: "a role_map entry naming a nonexistent role ... aborts startup"
    policy_path = _write_policy(_rbac_mtls_policy({
        "mtls": {
            "identity_source": "san_uri",
            "role_map": {"spiffe://corp/admin": "superuser"},
        },
    }))
    server = _mtls_server(mtls_pki, "optional", policy_path)
    try:
        with pytest.raises((RuntimeError, TimeoutError)):
            server.start(timeout_seconds=15)
    finally:
        server.stop()
        os.remove(policy_path)


def test_bad_identity_source_aborts_startup(mtls_pki):
    # F008d: "... or a bad identity_source ... aborts startup"
    policy_path = _write_policy(_rbac_mtls_policy({
        "mtls": {
            "identity_source": "san_email",
            "role_map": {"spiffe://corp/admin": "admin"},
        },
    }))
    server = _mtls_server(mtls_pki, "optional", policy_path)
    try:
        with pytest.raises((RuntimeError, TimeoutError)):
            server.start(timeout_seconds=15)
    finally:
        server.stop()
        os.remove(policy_path)


# ---------------------------------------------------------------------------
# F010a: mTLS CRL (certificate revocation).
#
# Feature -> acceptance criterion -> test mapping recorded in features.json
# test_refs. Design doc: docs/design/pr5-optional.md section 2, binding
# revisions in section 8.3, test-plan corrections in section 8.6.
#
# Negative first (startup fail-closed matrix, R1), then the handshake-level
# revocation checks, then the positive/no-regression cases.
# ---------------------------------------------------------------------------

def test_crl_no_next_update_aborts_startup(mtls_pki, crl_pki):
    # F010a / R1: a CRL with NO nextUpdate field at all is a silent forever-CRL
    # (no runtime reload means it never expires) - must abort at startup, not
    # boot and silently pin revocation state.
    server = ServerPreset.tinyllama2()
    server.ssl_file_cert = mtls_pki.server_crt
    server.ssl_file_key = mtls_pki.server_key
    server.mtls_client_ca_file = mtls_pki.ca_crt
    server.mtls_required = "required"
    server.mtls_crl_file = crl_pki.no_next_update_crl
    with pytest.raises((RuntimeError, TimeoutError)):
        server.start(timeout_seconds=15)


def test_crl_past_next_update_aborts_startup(mtls_pki, crl_pki):
    # F010a / R1 (design section 8.6 case: replaces the old handshake-timing
    # variant with a deterministic startup test): a CRL whose nextUpdate has
    # already passed rejects EVERY client at handshake time - fail at startup
    # with a clear message instead of booting 100%-broken.
    server = ServerPreset.tinyllama2()
    server.ssl_file_cert = mtls_pki.server_crt
    server.ssl_file_key = mtls_pki.server_key
    server.mtls_client_ca_file = mtls_pki.ca_crt
    server.mtls_required = "required"
    server.mtls_crl_file = crl_pki.expired_crl
    with pytest.raises((RuntimeError, TimeoutError)):
        server.start(timeout_seconds=15)


def test_crl_file_missing_aborts_startup(mtls_pki):
    # F010a: "--mtls-crl-file pointing at a missing ... file ... aborts startup"
    server = ServerPreset.tinyllama2()
    server.ssl_file_cert = mtls_pki.server_crt
    server.ssl_file_key = mtls_pki.server_key
    server.mtls_client_ca_file = mtls_pki.ca_crt
    server.mtls_required = "required"
    server.mtls_crl_file = "/nonexistent/path/does-not-exist.crl"
    with pytest.raises((RuntimeError, TimeoutError)):
        server.start(timeout_seconds=15)


def test_crl_file_with_zero_crls_aborts_startup(mtls_pki):
    # F010a: "... or a file that parses but contains zero CRLs, aborts startup."
    # A cert PEM is syntactically valid PEM but contains no "X509 CRL" block, so
    # PEM_read_bio_X509_CRL never matches anything -> count==0 -> fail closed.
    server = ServerPreset.tinyllama2()
    server.ssl_file_cert = mtls_pki.server_crt
    server.ssl_file_key = mtls_pki.server_key
    server.mtls_client_ca_file = mtls_pki.ca_crt
    server.mtls_required = "required"
    server.mtls_crl_file = mtls_pki.ca_crt  # a cert, not a CRL
    with pytest.raises((RuntimeError, TimeoutError)):
        server.start(timeout_seconds=15)


def test_crl_file_with_mtls_required_off_aborts_startup(mtls_pki, crl_pki):
    # F010a: "--mtls-crl-file set while --mtls-required is off aborts startup"
    server = ServerPreset.tinyllama2()
    server.ssl_file_cert = mtls_pki.server_crt
    server.ssl_file_key = mtls_pki.server_key
    server.mtls_required = "off"
    server.mtls_crl_file = crl_pki.good_crl
    with pytest.raises((RuntimeError, TimeoutError)):
        server.start(timeout_seconds=15)


@pytest.mark.parametrize("mode", ["optional", "required"])
def test_revoked_client_cert_rejected_at_handshake(mtls_pki, crl_pki, mode):
    # F010a: "a client cert revoked by the configured CRL fails the TLS handshake
    # in both optional and required mTLS mode" - per R4/section 8.6, assert ONLY
    # that the connection PRESENTING the revoked cert fails (transport/SSL error,
    # never an HTTP status); do not also assert anything about a later anonymous
    # reconnect (see the R4 test right below for that, on its own connection).
    policy_path = _write_policy(_rbac_mtls_policy())
    probe = (mtls_pki.admin_crt, mtls_pki.admin_key) if mode == "required" else None
    server = _mtls_server(mtls_pki, mode, policy_path, crl_file=crl_pki.good_crl,
                           probe_cert=probe)
    try:
        server.start()
        server.client_cert = crl_pki.revoked_crt
        server.client_key = crl_pki.revoked_key
        with pytest.raises((requests.exceptions.SSLError, requests.exceptions.ConnectionError)):
            server.make_request("GET", "/props")
    finally:
        server.stop()
        os.remove(policy_path)


def test_optional_mode_revoked_cert_then_anonymous_reconnect_is_401_not_blocked(mtls_pki, crl_pki):
    # F010a / R4: "in optional mode a CRL revokes the mTLS IDENTITY, it does not
    # blocklist the client" - a client whose revoked-cert handshake was rejected
    # may still reconnect presenting NO cert and is treated as ordinary anonymous
    # (401 without any other credential, exactly like any other anonymous
    # request - never specially blocked because it once presented a revoked cert).
    # Two separate connections/assertions, per the R4 test-plan note.
    policy_path = _write_policy(_rbac_mtls_policy())
    server = _mtls_server(mtls_pki, "optional", policy_path, crl_file=crl_pki.good_crl)
    try:
        server.start()
        server.client_cert = crl_pki.revoked_crt
        server.client_key = crl_pki.revoked_key
        with pytest.raises((requests.exceptions.SSLError, requests.exceptions.ConnectionError)):
            server.make_request("GET", "/props")

        server.client_cert = None
        server.client_key = None
        res = server.make_request("GET", "/props")
        assert res.status_code == 401
    finally:
        server.stop()
        os.remove(policy_path)


def test_unrevoked_cert_same_ca_succeeds_with_crl_configured(mtls_pki, crl_pki):
    # F010a: "an unrevoked cert from the same issuer still succeeds and the PR3
    # SAN->role authz is unchanged" - admin cert (not on the CRL) is authorized
    # on READ_STATE; user cert (also not on the CRL) still gets 403 on it.
    policy_path = _write_policy(_rbac_mtls_policy())
    server = _mtls_server(mtls_pki, "required", policy_path, crl_file=crl_pki.good_crl,
                           probe_cert=(mtls_pki.admin_crt, mtls_pki.admin_key))
    try:
        server.start()
        res = server.make_request("GET", "/props")
        assert res.status_code == 200

        server.client_cert, server.client_key = mtls_pki.user_crt, mtls_pki.user_key
        res = server.make_request("GET", "/props")
        assert res.status_code == 403
    finally:
        server.stop()
        os.remove(policy_path)


# NOTE on criteria not covered by a dedicated test here (flagged, not silently
# skipped):
# - "both X509_V_FLAG_CRL_CHECK and X509_V_FLAG_CRL_CHECK_ALL are set" is an
#   OpenSSL-internal flag-state fact. At the default --mtls-verify-depth 1 the
#   two flags are behaviourally identical (OQ-A1), so the handshake-level tests
#   above cannot distinguish "both flags set" from "only CRL_CHECK set" without
#   an intermediate-CA chain (depth > 1) fixture, which this suite does not
#   build. Verified by code review (reviewer_notes in features.json) instead.
# - Flag help-text wording (R2's "no CRL needed for a self-signed root",
#   R3's X509_V_ERR_UNABLE_TO_GET_CRL diagnostic hint) is not exercised by any
#   test in this file; `--help` output is not asserted anywhere in this suite.
# - "no --mtls-crl-file set: behavior identical to pre-F010a" is verified by
#   NOT modifying any pre-existing test in this file and running the full
#   suite together with the new F010a cases above.


# ---------------------------------------------------------------------------
# F016: Runtime CRL reload (poll-based, last-known-good on failure).
#
# Feature -> acceptance criterion -> test mapping recorded in features.json
# test_refs. Design doc: docs/design/pr7-additional-hardening.md section 5,
# binding revisions in section 7.2 (B2) and 7.4 (R-C1..R-C7).
#
# Negative first (flag validation), then the load-bearing reload-callback
# test, then the fail-safe (bad-reload) test, then a positive smoke test for
# the session-resumption-disable criterion that this black-box harness
# cannot fully verify (flagged below rather than silently skipped).
#
# NOTE: "no regression when reload is off" (features.json F016 criterion 2)
# is verified by NOT modifying any pre-existing F010a test above and running
# this whole file, unmodified tests included, in the same suite run as these
# new F016 cases - exactly the same convention used for F010a's own
# no-regression criterion just above.
# ---------------------------------------------------------------------------

def test_crl_reload_interval_without_crl_file_aborts_startup(mtls_pki):
    # F016 flag validation: "--mtls-crl-reload-interval ... non-zero with an
    # empty --mtls-crl-file" is rejected at startup with SRV_ERR (fail closed):
    # a reload interval with nothing to reload is a meaningless, and silently
    # ignorable, configuration.
    server = ServerPreset.tinyllama2()
    server.ssl_file_cert = mtls_pki.server_crt
    server.ssl_file_key = mtls_pki.server_key
    server.mtls_client_ca_file = mtls_pki.ca_crt
    server.mtls_required = "required"
    server.mtls_crl_reload_interval = 5  # valid magnitude; the missing crl_file is the point
    with pytest.raises((RuntimeError, TimeoutError)):
        server.start(timeout_seconds=15)


@pytest.mark.parametrize("bad_interval", [1, 2, 3, 4])
def test_crl_reload_interval_too_small_aborts_startup(mtls_pki, crl_pki, bad_interval):
    # F016 flag validation: a value in 1..4 is rejected - the minimum is 5, to
    # prevent a hot stat loop on a shared filesystem (server-mtls.cpp checks
    # `interval > 0 && interval < 5`).
    server = ServerPreset.tinyllama2()
    server.ssl_file_cert = mtls_pki.server_crt
    server.ssl_file_key = mtls_pki.server_key
    server.mtls_client_ca_file = mtls_pki.ca_crt
    server.mtls_required = "required"
    server.mtls_crl_file = crl_pki.good_crl
    server.mtls_crl_reload_interval = bad_interval
    with pytest.raises((RuntimeError, TimeoutError)):
        server.start(timeout_seconds=15)


def test_crl_reload_interval_negative_aborts_startup(mtls_pki, crl_pki):
    # F016 flag validation: a negative --mtls-crl-reload-interval aborts startup.
    server = ServerPreset.tinyllama2()
    server.ssl_file_cert = mtls_pki.server_crt
    server.ssl_file_key = mtls_pki.server_key
    server.mtls_client_ca_file = mtls_pki.ca_crt
    server.mtls_required = "required"
    server.mtls_crl_file = crl_pki.good_crl
    server.mtls_crl_reload_interval = -1
    with pytest.raises((RuntimeError, TimeoutError)):
        server.start(timeout_seconds=15)


def test_crl_reload_interval_valid_with_crl_file_starts(mtls_pki, crl_pki):
    # F016: "--mtls-crl-reload-interval set with a valid --mtls-crl-file: server
    # starts successfully" - the positive counterpart to the three abort cases
    # above. crl_pki.good_crl revokes only crl_pki.revoked_crt, so the admin
    # probe cert is unaffected and the readiness poll succeeds normally.
    policy_path = _write_policy(_rbac_mtls_policy())
    server = _mtls_server(mtls_pki, "required", policy_path, crl_file=crl_pki.good_crl,
                           crl_reload_interval=5,
                           probe_cert=(mtls_pki.admin_crt, mtls_pki.admin_key))
    try:
        server.start()  # must not raise
        res = server.make_request("GET", "/props")
        assert res.status_code == 200
    finally:
        server.stop()
        os.remove(policy_path)


def _poll_until_rejected(server, cert, key, timeout=40, poll_interval=1.0):
    """Bounded retry loop (not a single fixed sleep, to avoid flakiness under
    CI load): repeatedly attempt a fresh TLS handshake with `cert`/`key` until
    it fails at the transport level, or fail the test if it never does within
    `timeout` seconds. Every attempt opens a brand-new connection (ServerProcess
    .make_request uses plain requests.get/post, no session/connection reuse),
    so each retry is an independent, fresh handshake against the CURRENT CRL
    snapshot the server holds at that moment - exactly what the reload thread
    is supposed to affect."""
    deadline = time.time() + timeout
    server.client_cert, server.client_key = cert, key
    while time.time() < deadline:
        try:
            server.make_request("GET", "/props")
        except (requests.exceptions.SSLError, requests.exceptions.ConnectionError):
            return
        time.sleep(poll_interval)
    pytest.fail(f"cert was not rejected at the TLS handshake within {timeout}s of the reload")


def test_crl_reload_callback_actually_consulted(mtls_pki, tmp_path):
    # F016 CORE / load-bearing test (design 5.8, features.json criterion 4):
    # start with a CRL that revokes NOTHING; a client cert C connects. Rewrite
    # the SAME on-disk file with a CRL that revokes C. After interval + slack,
    # C's TLS HANDSHAKE FAILS - with NO server restart. This is the only test
    # that distinguishes "the lookup_crls callback is actually consulted" from
    # "the store still holds the stale startup CRL" (design section 5.3/7.2).
    # An unrevoked cert D from the same CA still succeeds throughout.
    crl_path = str(tmp_path / "reload.crl")
    c_crt, c_key = mtls_pki.admin_crt, mtls_pki.admin_key   # to be revoked
    d_crt, d_key = mtls_pki.user_crt, mtls_pki.user_key     # never revoked

    # v1: revokes nothing.
    _gen_crl(str(tmp_path), "v1", mtls_pki.ca_crt, mtls_pki.ca_key,
             revoked_cert_paths=(), out_path=crl_path)

    policy_path = _write_policy(_rbac_mtls_policy())
    server = _mtls_server(mtls_pki, "required", policy_path, crl_file=crl_path,
                           crl_reload_interval=5, probe_cert=(c_crt, c_key))
    try:
        server.start()

        # Baseline: C (not yet revoked) connects fine.
        server.client_cert, server.client_key = c_crt, c_key
        res = server.make_request("GET", "/props")
        assert res.status_code == 200, "C must connect before any revocation"

        # D also connects fine (different role, but the TLS handshake itself
        # must succeed regardless of authz outcome).
        server.client_cert, server.client_key = d_crt, d_key
        res = server.make_request("GET", "/props")
        assert res.status_code in (200, 403)

        # Rewrite the SAME path in place with v2, which revokes C.
        _gen_crl(str(tmp_path), "v2", mtls_pki.ca_crt, mtls_pki.ca_key,
                 revoked_cert_paths=[c_crt], out_path=crl_path)

        # Poll (bounded) until C's handshake is rejected - proves the callback
        # is consulted, not just the frozen startup store contents.
        _poll_until_rejected(server, c_crt, c_key)

        # D, unrevoked, still succeeds after the reload - no server restart.
        server.client_cert, server.client_key = d_crt, d_key
        res = server.make_request("GET", "/props")
        assert res.status_code in (200, 403)
    finally:
        server.stop()
        os.remove(policy_path)


def test_crl_reload_bad_file_keeps_last_known_good(mtls_pki, tmp_path):
    # F016 fail-safe / B2 design intent (features.json criterion 5): a
    # malformed CRL written to disk mid-run does NOT bring down enforcement.
    # Start with a CRL that revokes C; confirm C is rejected (baseline, from
    # the startup parse). Corrupt the file. Wait past the reload interval and
    # confirm C is STILL rejected (the last-known-good snapshot is still being
    # enforced, not silently cleared) and that an unrelated, never-revoked
    # cert D still succeeds - i.e. the server is still up and functioning,
    # not just failing every handshake.
    crl_path = str(tmp_path / "reload.crl")
    c_crt, c_key = mtls_pki.admin_crt, mtls_pki.admin_key   # revoked from the start
    d_crt, d_key = mtls_pki.user_crt, mtls_pki.user_key     # never revoked, used as probe

    _gen_crl(str(tmp_path), "v1", mtls_pki.ca_crt, mtls_pki.ca_key,
             revoked_cert_paths=[c_crt], out_path=crl_path)

    policy_path = _write_policy(_rbac_mtls_policy())
    server = _mtls_server(mtls_pki, "required", policy_path, crl_file=crl_path,
                           crl_reload_interval=5, probe_cert=(d_crt, d_key))
    try:
        server.start()

        # Baseline: C is rejected by the CRL loaded at startup.
        server.client_cert, server.client_key = c_crt, c_key
        with pytest.raises((requests.exceptions.SSLError, requests.exceptions.ConnectionError)):
            server.make_request("GET", "/props")

        # Corrupt the file in place: not PEM, not a CRL at all.
        with open(crl_path, "wb") as f:
            f.write(b"this is not a valid PEM CRL\n\x00\x01\x02garbage")

        # Wait past (interval + slack) once: this is a STABLE negative
        # assertion (nothing should change), so a single bounded wait
        # followed by a check is appropriate here, unlike the positive
        # "wait for a state change" polling used above.
        time.sleep(5 + 5)

        # C is STILL rejected: the bad file never became the active CRL.
        server.client_cert, server.client_key = c_crt, c_key
        with pytest.raises((requests.exceptions.SSLError, requests.exceptions.ConnectionError)):
            server.make_request("GET", "/props")

        # The server is still running and D (unrevoked) still succeeds -
        # revocation enforcement was never silently disabled or the process
        # brought down.
        server.client_cert, server.client_key = d_crt, d_key
        res = server.make_request("GET", "/props")
        assert res.status_code in (200, 403)
    finally:
        server.stop()
        os.remove(policy_path)


def test_crl_reload_session_cache_off_does_not_break_normal_connections(mtls_pki, crl_pki):
    # F016 R-C1 (features.json criterion "SESSION RESUMPTION DISABLED"):
    # harden_context calls SSL_CTX_set_session_cache_mode(OFF) / SSL_OP_NO_TICKET
    # / SSL_CTX_set_num_tickets(0) whenever crl_reload_interval > 0, so that a
    # revoked client cannot keep connecting via a cached session/ticket.
    #
    # NOT BLACK-BOX VERIFIABLE HERE: ServerProcess.make_request (utils.py) issues
    # each call as a bare `requests.get/post(...)`, which opens a brand-new
    # connection and does not reuse a requests.Session, an SSLContext, or any
    # TLS session ticket across calls - so this harness cannot observe whether a
    # SECOND connection actually attempted resumption (there is no ticket cache
    # to present in the first place). Proving "a revoked client presenting a
    # cached ticket is still rejected" would require a raw ssl.SSLSocket/
    # SSLContext test client that explicitly saves and replays a session object
    # across two sockets, which this test file's PKI/harness (openssl-CLI +
    # requests) does not provide. Flagging per this suite's convention (see the
    # xfail below and the F008b case-10 xfail) rather than writing something
    # that cannot actually distinguish "resumption disabled" from "resumption
    # never attempted" and would therefore pass either way.
    #
    # What IS verified: turning session caching/tickets off does not itself
    # break normal mTLS operation - several independent (non-resumed, since the
    # test client never resumes anyway) handshakes against a reload-enabled
    # server all succeed.
    policy_path = _write_policy(_rbac_mtls_policy())
    server = _mtls_server(mtls_pki, "required", policy_path, crl_file=crl_pki.good_crl,
                           crl_reload_interval=5,
                           probe_cert=(mtls_pki.admin_crt, mtls_pki.admin_key))
    try:
        server.start()
        for _ in range(3):
            res = server.make_request("GET", "/props")
            assert res.status_code == 200
    finally:
        server.stop()
        os.remove(policy_path)


# ---------------------------------------------------------------------------
# Untestable / environment-dependent criteria (flagged, not silently skipped).
# ---------------------------------------------------------------------------

@pytest.mark.xfail(
    reason="F008b case 10: --tls-min-version 1.3 rejecting a TLS-1.2-only client "
           "requires a TEST CLIENT able to negotiate/be pinned to TLS 1.2 only. "
           "The venv's `requests`/urllib3 stack negotiates whatever the underlying "
           "OpenSSL offers and does not expose a simple max-version pin without a "
           "custom HTTPAdapter/SSLContext. Not exercised here; flagged per design "
           "doc section 10 case 10 rather than silently omitted.",
    strict=False,
    run=False,
)
def test_tls13_min_version_rejects_tls12_only_client():
    pass


def test_s2_tls_min_version_applies_to_plain_https_without_mtls(mtls_pki):
    # F008b S2: "--tls-min-version applies to a PLAIN HTTPS server too (no mTLS)".
    # We cannot force the python test client to speak TLS 1.2-only (see xfail above
    # for case 10), so this test only proves the POSITIVE half: a plain HTTPS server
    # (no mTLS) started with --tls-min-version 1.3 is reachable by a normal (TLS 1.3
    # capable) client, i.e. harden_context is actually invoked on the plain-TLS
    # SSLServer path and does not break normal HTTPS. It does not prove version
    # enforcement (case 11) end-to-end; see the xfail above for that gap.
    server = ServerPreset.tinyllama2()
    server.ssl_file_cert = mtls_pki.server_crt
    server.ssl_file_key = mtls_pki.server_key
    server.tls_min_version = "1.3"
    server.ca_cert = mtls_pki.ca_crt
    try:
        server.start()
        res = server.make_request("GET", "/health")
        assert res.status_code == 200
    finally:
        server.stop()
