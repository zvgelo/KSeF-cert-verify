"""Loader + serwis na plikach (fixtury SYMULOWANE)."""

from __future__ import annotations

import pytest

from ksef_cert_verify.core.certificate_loader import MAX_FILE_BYTES, LoaderError, load_file
from ksef_cert_verify.core.models import Verdict
from ksef_cert_verify.core.report import (
    VerifyOptions,
    build_json,
    collect_files,
    exit_code,
    verify_file,
    verify_paths,
)
from ksef_cert_verify.core.trust_store import TrustStore
from tests.conftest import KEY_PASSWORD, NOW, der, make_ca, make_leaf, pem, write_key, write_p12

pytestmark = pytest.mark.simulated


@pytest.fixture
def opts(ca):
    t = TrustStore()
    t.add(ca.cert, "test")
    return VerifyOptions(trust=t, now=NOW)


def test_pem_der_p12_all_loadable_and_valid(tmp_path, ca, auth_cert, opts):
    cert, key = auth_cert
    (tmp_path / "a.pem").write_bytes(pem(cert))
    (tmp_path / "b.cer").write_bytes(der(cert))
    (tmp_path / "c.pfx").write_bytes(b"")
    write_p12(tmp_path / "c.pfx", cert, key, b"haslo")
    kp = write_key(tmp_path / "k.key", key)
    pw = lambda path, retry: KEY_PASSWORD  # noqa: E731
    assert verify_file(tmp_path / "a.pem", opts, pw, key_path=kp).verdict is Verdict.VALID
    assert verify_file(tmp_path / "b.cer", opts, pw, key_path=kp).verdict is Verdict.VALID
    # bez klucza: nigdy VALID
    assert verify_file(tmp_path / "a.pem", opts).verdict is Verdict.INDETERMINATE
    r = verify_file(tmp_path / "c.pfx", opts, password="haslo")
    assert r.verdict is Verdict.VALID and r.file_format == "PKCS12"


def test_pem_with_unusual_extension(tmp_path, auth_cert, opts):
    p = tmp_path / "cert.txt"
    p.write_bytes(pem(auth_cert[0]))
    assert verify_file(p, opts).file_format == "PEM"


def test_der_with_pem_extension_detected_by_content(tmp_path, auth_cert, opts):
    p = tmp_path / "cert.pem"
    p.write_bytes(der(auth_cert[0]))
    assert verify_file(p, opts).file_format == "DER"


def test_corrupted_pem_is_content_error(tmp_path, auth_cert, opts):
    data = pem(auth_cert[0]).replace(b"MII", b"M!I", 1)
    p = tmp_path / "bad.pem"
    p.write_bytes(data)
    r = verify_file(p, opts)
    assert r.error and r.error.kind == "content" and r.verdict is Verdict.INVALID


def test_corrupted_der(tmp_path, auth_cert, opts):
    raw = bytearray(der(auth_cert[0]))
    raw[20] ^= 0xFF
    raw = raw[:-10]
    p = tmp_path / "bad.der"
    p.write_bytes(bytes(raw))
    r = verify_file(p, opts)
    assert r.error and r.error.code in {"INVALID_DER", "NO_CERTIFICATE"} and r.verdict is Verdict.INVALID


def test_file_without_certificate(tmp_path, opts):
    p = tmp_path / "x.pem"
    p.write_text("to nie jest certyfikat\n", encoding="utf-8")
    r = verify_file(p, opts)
    assert r.error and r.error.code == "NO_CERTIFICATE" and r.verdict is Verdict.INVALID


def test_missing_file_is_runtime_error(tmp_path, opts):
    r = verify_file(tmp_path / "nie-ma.pem", opts)
    assert r.error and r.error.kind == "runtime" and r.verdict is None
    assert exit_code([r]) == 2


def test_oversize_file_rejected(tmp_path):
    p = tmp_path / "big.pem"
    p.write_bytes(b"A" * (MAX_FILE_BYTES + 1))
    with pytest.raises(LoaderError) as e:
        load_file(p)
    assert e.value.code == "TOO_LARGE"


def test_p12_wrong_password_and_missing_password(tmp_path, auth_cert, opts):
    cert, key = auth_cert
    p = write_p12(tmp_path / "k.p12", cert, key, b"dobre")
    r = verify_file(p, opts, password="zle")
    assert r.error.code == "WRONG_PASSWORD" and r.verdict is None
    r = verify_file(p, opts)
    assert r.error.code == "PASSWORD_REQUIRED"


def test_p12_password_provider_retry(tmp_path, auth_cert, opts):
    cert, key = auth_cert
    p = write_p12(tmp_path / "k.p12", cert, key, b"dobre")
    answers = iter(["zle", "dobre"])
    calls = []

    def provider(path, retry):
        calls.append(retry)
        return next(answers)

    r = verify_file(p, opts, provider)
    assert r.verdict is Verdict.VALID and calls == [False, True]


def test_p12_without_password(tmp_path, auth_cert, opts):
    cert, key = auth_cert
    p = write_p12(tmp_path / "np.p12", cert, key, None)
    assert verify_file(p, opts).verdict is Verdict.VALID


def test_p12_private_key_never_in_report(tmp_path, auth_cert, opts):
    cert, key = auth_cert
    p = write_p12(tmp_path / "k.p12", cert, key, b"sekret-haslo")
    r = verify_file(p, opts, password="sekret-haslo")
    text = str(build_json([r], opts, "x"))
    assert "sekret-haslo" not in text and "PRIVATE KEY-----" not in text
    assert any("klucz prywatny" in n for n in r.notes)


def test_pem_with_private_key_ignored(tmp_path, auth_cert, opts):
    from cryptography.hazmat.primitives import serialization as s

    cert, key = auth_cert
    blob = pem(cert) + key.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption())
    p = tmp_path / "both.pem"
    p.write_bytes(blob)
    # PEM zawierający i certyfikat, i niezaszyfrowany klucz: klucz czytany tylko jako źródło pary
    r_default = verify_file(p, opts, key_path=p)  # domyślnie: niezaszyfrowany klucz = problem bezpieczeństwa
    assert r_default.verdict is Verdict.INVALID
    assert r_default.certificates[0].checks["key_decrypt"].code == "KEY_UNENCRYPTED"
    opts.require_encrypted_key = False
    r = verify_file(p, opts, key_path=p)
    assert r.verdict is Verdict.VALID and "PRIVATE KEY-----" not in str(build_json([r], opts, "x"))
    assert r.certificates[0].checks["key_decrypt"].status.value == "WARNING"
    r2 = verify_file(p, opts)  # bez wskazania klucza: certyfikat jest analizowany, klucz ignorowany
    assert r2.verdict is Verdict.INDETERMINATE and r2.notes


def test_chain_file_leaf_plus_intermediate_missing_root(tmp_path, ca, opts):
    from tests.conftest import CA  # noqa: F401

    leaf, _ = make_leaf(ca)
    p = tmp_path / "chain.pem"
    p.write_bytes(pem(leaf, ca.cert))  # kotwica jest też w pliku, ale zaufanie wynika ze store
    kp = write_key(tmp_path / "leaf.key", _)
    r = verify_file(p, opts, lambda *_a: KEY_PASSWORD, key_path=kp)
    assert len(r.certificates) == 1  # CA nie jest analizowane jako liść
    assert r.verdict is Verdict.VALID


def test_chain_in_file_does_not_create_trust(tmp_path, ca):
    """Certyfikat CA dostarczony w pliku nie staje się kotwicą."""
    leaf, _ = make_leaf(ca)
    p = tmp_path / "chain.pem"
    p.write_bytes(pem(leaf, ca.cert))
    t = TrustStore()
    other = make_ca("Inny")
    t.add(other.cert, "x")
    r = verify_file(p, VerifyOptions(trust=t, now=NOW))
    assert r.verdict is Verdict.INVALID  # root z pliku jest niezaufany


def test_multi_leaf_file(tmp_path, ca, opts):
    a, _ = make_leaf(ca, kind="Authentication", serial=1)
    o, _ = make_leaf(ca, kind="Offline", serial=2)
    p = tmp_path / "two.pem"
    p.write_bytes(pem(a, o))
    r = verify_file(p, opts)
    assert [c.cert_type.value for c in r.certificates] == ["Authentication", "Offline"]


def test_polish_filenames_and_directory_recursion(tmp_path, auth_cert, opts):
    d = tmp_path / "zażółć" / "gęślą"
    d.mkdir(parents=True)
    f = d / "certyfikat_łódź.pem"
    f.write_bytes(pem(auth_cert[0]))
    (tmp_path / "top.pem").write_bytes(pem(auth_cert[0]))
    (tmp_path / "ignore.txt").write_text("x")
    assert len(collect_files([tmp_path], recursive=False)) == 1
    files = collect_files([tmp_path], recursive=True)
    assert len(files) == 2
    reports = verify_paths([tmp_path], opts, recursive=True)
    assert exit_code(reports) == 3  # bez klucza nie ma VALID
    assert (
        "certyfikat_łódź.pem"
        in build_json(reports, opts, "t")["files"][0]["file"]
        + build_json(reports, opts, "t")["files"][1]["file"]
    )


def test_exit_code_precedence(tmp_path, ca, auth_cert, opts):
    gk = write_key(tmp_path / "g.key", auth_cert[1])
    good = tmp_path / "g.pem"
    good.write_bytes(pem(auth_cert[0]))
    bad = tmp_path / "b.pem"
    bad.write_bytes(pem(make_leaf(ca, not_before=NOW.replace(year=2020))[0]))
    missing = tmp_path / "m.pem"

    def vf(path, o=opts):  # "dobry" certyfikat zawsze z poprawnym kluczem
        return verify_file(path, o, lambda *_x: KEY_PASSWORD, key_path=gk)

    assert exit_code([vf(good)]) == 0
    assert exit_code([vf(good), vf(bad)]) == 1
    assert exit_code([vf(bad), vf(missing)]) == 2
    assert exit_code([vf(good, VerifyOptions(now=NOW))]) == 3  # brak kotwic zaufania
    assert exit_code([verify_file(good, opts)]) == 3  # brak klucza


def test_json_schema_stable(tmp_path, auth_cert, opts):
    p = tmp_path / "a.pem"
    p.write_bytes(pem(auth_cert[0]))
    kp = write_key(tmp_path / "a.key", auth_cert[1])
    doc = build_json([verify_file(p, opts, lambda *_a: KEY_PASSWORD, key_path=kp)], opts, "1.0.0")
    assert doc["schema_version"] == "2"
    assert set(doc) == {"schema_version", "tool", "generated_at", "scope", "files", "exit_code", "disclaimer"}
    c = doc["files"][0]["certificates"][0]
    assert set(c["checks"]) == {
        "parsing",
        "validity",
        "crypto",
        "trust",
        "classification",
        "profile",
        "online",
        "inputs",
        "key_decrypt",
        "key_match",
        "signature_test",
    }
    assert c["checks"]["online"]["status"] == "NOT_CHECKED"
    assert c["result"] == "VALID" and c["type"] == "Authentication"
