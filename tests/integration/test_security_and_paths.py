"""Testy bezpieczeństwa i ścieżek (fixtury SYMULOWANE)."""

from __future__ import annotations

import os
import sys

import pytest

from ksef_cert_verify.core.report import VerifyOptions, build_json, verify_file
from ksef_cert_verify.core.trust_store import TrustStore
from ksef_cert_verify.ksef_api.ksef_client import KsefApiClient
from tests.conftest import NOW, pem, write_p12

pytestmark = pytest.mark.simulated


def test_p12_analysis_writes_no_files_and_leaks_no_key(tmp_path, auth_cert, ca):
    cert, key = auth_cert
    p = write_p12(tmp_path / "k.p12", cert, key, b"pw")
    before = {f for f in tmp_path.rglob("*")}
    t = TrustStore()
    t.add(ca.cert, "t")
    opts = VerifyOptions(trust=t, now=NOW)
    r = verify_file(p, opts, password="pw")
    doc = str(build_json([r], opts, "x"))
    assert {f for f in tmp_path.rglob("*")} == before
    priv = key.private_numbers().private_value
    assert str(priv) not in doc and format(priv, "x") not in doc.lower()


def test_trust_loading_does_not_follow_unreadable_or_garbage(tmp_path):
    d = tmp_path / "trust"
    d.mkdir()
    (d / "junk.pem").write_text("-----BEGIN CERTIFICATE-----\nZZZ\n-----END CERTIFICATE-----\n")
    (d / "empty.crt").write_bytes(b"")
    store = TrustStore()
    store.load_path(d)
    assert len(store) == 0 and len(store.warnings) == 2


def test_api_client_enforces_tls_and_no_redirects():
    c = KsefApiClient("TEST", "tok")
    try:
        assert c._client.follow_redirects is False
        assert c._client._transport._pool._ssl_context.verify_mode.name == "CERT_REQUIRED"
    finally:
        c.close()


def test_api_client_rejects_header_injection_token():
    with pytest.raises(ValueError):
        KsefApiClient("TEST", "tok\r\nX-Evil: 1")


def test_paths_with_spaces_unicode_and_native_separators(tmp_path, auth_cert, ca):
    d = tmp_path / "Mój folder z spacjami" / "żółć"
    d.mkdir(parents=True)
    f = d / "cert ąę.CER"
    f.write_bytes(pem(auth_cert[0]))
    t = TrustStore()
    t.add(ca.cert, "t")
    r = verify_file(type(f)(os.path.join(str(d), "cert ąę.CER")), VerifyOptions(trust=t, now=NOW))
    assert r.error is None and r.certificates


@pytest.mark.skipif(sys.platform != "win32", reason="ścieżki Windows: uruchamiane tylko na Windows (CI)")
def test_windows_drive_and_unc_style_paths(tmp_path, auth_cert):
    f = tmp_path / "c.pem"
    f.write_bytes(pem(auth_cert[0]))
    extended = "\\\\?\\" + str(f.resolve())
    r = verify_file(type(f)(extended), VerifyOptions(now=NOW))
    assert r.error is None


def test_directory_given_as_file_is_runtime_error(tmp_path):
    r = verify_file(tmp_path, VerifyOptions(now=NOW))
    assert r.error and r.error.code == "NOT_A_FILE" and r.verdict is None


def test_regression_valid_requires_all_mandatory_checks(auth_cert, ca):
    """Regresja: UNKNOWN/NOT_CHECKED nigdy nie daje VALID."""
    from ksef_cert_verify.core.certificate_validator import aggregate
    from ksef_cert_verify.core.models import Check, CheckStatus, Verdict

    names = [
        "parsing",
        "validity",
        "crypto",
        "trust",
        "classification",
        "profile",
        "inputs",
        "key_decrypt",
        "key_match",
        "signature_test",
        "online",
    ]
    base = {n: Check(n, CheckStatus.PASS, "") for n in names}
    assert aggregate(base, False) is Verdict.VALID
    for bad in (CheckStatus.UNKNOWN, CheckStatus.NOT_CHECKED):
        for n in names[:-1]:
            c = dict(base)
            c[n] = Check(n, bad, "")
            assert aggregate(c, False) is Verdict.INDETERMINATE, (n, bad)
    c = dict(base)
    c["online"] = Check("online", CheckStatus.NOT_CHECKED, "")
    assert aggregate(c, False) is Verdict.VALID  # offline: online nie jest obowiązkowy
    assert aggregate(c, True) is Verdict.INDETERMINATE  # zażądano online → obowiązkowy
    c["trust"] = Check("trust", CheckStatus.FAIL, "")
    c["profile"] = Check("profile", CheckStatus.UNKNOWN, "")
    assert aggregate(c, False) is Verdict.INVALID  # FAIL ma pierwszeństwo
