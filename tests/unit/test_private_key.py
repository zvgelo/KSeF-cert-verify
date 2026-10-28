"""Kontrola pary certyfikat + klucz prywatny (fixtury SYMULOWANE; to test kryptografii, nie profilu MF)."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from ksef_cert_verify.core.models import CheckStatus as S
from ksef_cert_verify.core.private_key import match_check, read_private_key, spki_of_certificate
from tests.conftest import KEY_PASSWORD, make_ca, make_leaf, pem, write_key

pytestmark = pytest.mark.simulated


def provider(pw):
    calls = []

    def p(path, retry):
        calls.append(retry)
        return pw

    p.calls = calls
    return p


@pytest.mark.parametrize("kind", ["ec", "rsa"])
@pytest.mark.parametrize("fmt,enc", [("pkcs8", "pem"), ("traditional", "pem"), ("pkcs8", "der")])
def test_encrypted_key_matches_certificate(tmp_path, kind, fmt, enc):
    key = ec.generate_private_key(ec.SECP256R1()) if kind == "ec" else rsa.generate_private_key(65537, 2048)
    cert, _ = make_leaf(make_ca(), key=key)
    kp = write_key(tmp_path / "k.key", key, fmt=fmt, encoding=enc)
    out = read_private_key(kp, provider(KEY_PASSWORD))
    assert out.decrypt.status is S.PASS and out.spki == spki_of_certificate(cert)
    assert match_check(spki_of_certificate(cert), out.spki).status is S.PASS


def test_wrong_password_fails_without_leaking_it(tmp_path):
    kp = write_key(tmp_path / "k.key", ec.generate_private_key(ec.SECP256R1()))
    p = provider("zle-haslo-SEKRET")
    out = read_private_key(kp, p)
    assert out.decrypt.status is S.FAIL and out.spki is None
    assert "SEKRET" not in repr(out.decrypt.to_dict())
    assert "błędne hasło" in out.decrypt.summary
    assert p.calls[0] is False and all(p.calls[1:])  # kolejne próby oznaczone jako ponowne


def test_missing_or_empty_password_is_unknown(tmp_path):
    kp = write_key(tmp_path / "k.key", ec.generate_private_key(ec.SECP256R1()))
    for prov in (None, provider(None), provider("")):
        assert read_private_key(kp, prov).decrypt.status is S.UNKNOWN


def test_mismatched_key_pair(tmp_path):
    cert, _ = make_leaf(make_ca())
    other = ec.generate_private_key(ec.SECP256R1())
    out = read_private_key(write_key(tmp_path / "o.key", other), provider(KEY_PASSWORD))
    assert out.decrypt.status is S.PASS  # klucz poprawny...
    assert match_check(spki_of_certificate(cert), out.spki).status is S.FAIL  # ...ale nie ten


def test_rsa_key_vs_ec_certificate_mismatch(tmp_path):
    cert, _ = make_leaf(make_ca())
    rk = rsa.generate_private_key(65537, 2048)
    out = read_private_key(write_key(tmp_path / "r.key", rk), provider(KEY_PASSWORD))
    assert match_check(spki_of_certificate(cert), out.spki).status is S.FAIL


def test_missing_key_file_is_runtime_error(tmp_path):
    out = read_private_key(tmp_path / "brak.key", provider(KEY_PASSWORD))
    assert (
        out.runtime_error
        and out.runtime_error.code == "KEY_NOT_FOUND"
        and out.runtime_error.kind == "runtime"
    )


def test_corrupted_key(tmp_path):
    kp = write_key(tmp_path / "k.key", ec.generate_private_key(ec.SECP256R1()), password=None)
    lines = kp.read_text().splitlines()
    lines[2] = lines[2][::-1]
    kp.write_text("\n".join(lines) + "\n")
    assert read_private_key(kp, provider(KEY_PASSWORD)).decrypt.status is S.FAIL


def test_corrupted_encrypted_key_is_failure_not_valid(tmp_path):
    kp = write_key(tmp_path / "k.key", ec.generate_private_key(ec.SECP256R1()))
    data = bytearray(kp.read_bytes())
    data[100] = ord("A") if data[100] != ord("A") else ord("B")
    kp.write_bytes(bytes(data))
    assert read_private_key(kp, provider(KEY_PASSWORD)).decrypt.status is S.FAIL


@pytest.mark.parametrize(
    "content",
    [
        b"to nie jest klucz\n",
        b"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
        b"-----BEGIN DSA PRIVATE KEY-----\nAAAA\n-----END DSA PRIVATE KEY-----\n",
        b"\x00\x01\x02garbage",
        b"",
    ],
)
def test_unsupported_key_formats(tmp_path, content):
    kp = tmp_path / "x.key"
    kp.write_bytes(content)
    out = read_private_key(kp, provider(KEY_PASSWORD))
    assert out.decrypt.status is S.FAIL and out.decrypt.findings[0].code == "KEY_UNSUPPORTED_FORMAT"


def test_certificate_given_as_key_is_rejected(tmp_path):
    cert, _ = make_leaf(make_ca())
    kp = tmp_path / "c.key"
    kp.write_bytes(pem(cert))
    assert read_private_key(kp, provider(KEY_PASSWORD)).decrypt.status is S.FAIL


def test_unencrypted_key_is_a_security_problem_by_default(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    kp = write_key(tmp_path / "k.key", key, password=None)
    out = read_private_key(kp, None)  # tryb wymagający zabezpieczonego klucza (domyślny)
    assert out.decrypt.status is S.FAIL and out.decrypt.code == "KEY_UNENCRYPTED"
    assert "PROBLEM BEZPIECZEŃSTWA" in out.decrypt.summary
    assert out.spki is not None  # para nadal może być pokazana, ale wynik nie będzie VALID


def test_unencrypted_key_allowed_only_explicitly_gives_warning(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    out = read_private_key(write_key(tmp_path / "k.key", key, password=None), None, require_encrypted=False)
    assert out.decrypt.status is S.WARNING and out.spki is not None


def test_unencrypted_key_does_not_ask_for_password(tmp_path):
    p = provider("x")
    read_private_key(write_key(tmp_path / "k.key", ec.generate_private_key(ec.SECP256R1()), password=None), p)
    assert p.calls == []


def test_retry_then_success(tmp_path):
    kp = write_key(tmp_path / "k.key", ec.generate_private_key(ec.SECP256R1()))
    answers = iter(["zle", KEY_PASSWORD])
    assert read_private_key(kp, lambda path, retry: next(answers)).decrypt.status is S.PASS


def test_no_key_given_match_not_checked():
    assert match_check(b"x", None).status is S.NOT_CHECKED
