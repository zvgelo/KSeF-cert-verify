"""Podpis kryptograficzny (RSA 2048 / EC P-256), kody wyników testu podpisu i KOD II (dane SYNTETYCZNE)."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from ksef_cert_verify.core import kod2, signing
from ksef_cert_verify.core.models import Check, CheckStatus
from ksef_cert_verify.core.private_key import (
    SignatureEvidence,
    _active_signature_test,
    signature_check,
    spki_of_certificate,
)
from tests.conftest import make_ca, make_leaf

pytestmark = pytest.mark.simulated


@pytest.fixture(params=["rsa", "ec"])
def pair(request):
    key = (
        rsa.generate_private_key(65537, 2048)
        if request.param == "rsa"
        else ec.generate_private_key(ec.SECP256R1())
    )
    cert, _ = make_leaf(make_ca(), key=key)
    return request.param, key, cert


# --- 9/10: poprawny podpis RSA i EC ------------------------------------------------------------
def test_signature_valid_for_rsa_and_ec(pair):
    kind, key, cert = pair
    ev = _active_signature_test(key)
    assert ev.scheme == (signing.SCHEME_RSA_PSS if kind == "rsa" else signing.SCHEME_ECDSA)
    chk = signature_check(cert, spki_of_certificate(cert), ev, None)
    assert chk.status is CheckStatus.PASS and chk.code == "SIGNATURE_VALID"


def test_challenge_is_random_and_fresh(pair):
    _, key, _ = pair
    assert _active_signature_test(key).challenge != _active_signature_test(key).challenge
    assert len(_active_signature_test(key).challenge) == 32


# --- 11: podpis zmienionych danych -----------------------------------------------------------
@pytest.mark.parametrize("fmt", ["der", "p1363"])
def test_tampered_data_fails_verification(pair, fmt):
    kind, key, cert = pair
    if kind == "rsa" and fmt == "p1363":
        pytest.skip("format P1363 dotyczy tylko ECDSA")
    _, sig = signing.sign(key, b"dane oryginalne", fmt)
    pub = cert.public_key()
    assert signing.verify(pub, b"dane oryginalne", sig, fmt)
    assert not signing.verify(pub, b"dane zmienione!", sig, fmt)


# --- 12: podpis niezgodnym kluczem publicznym ------------------------------------------------
def test_signature_with_other_public_key_fails(pair):
    kind, key, cert = pair
    other = (
        rsa.generate_private_key(65537, 2048) if kind == "rsa" else ec.generate_private_key(ec.SECP256R1())
    )
    other_cert, _ = make_leaf(make_ca(), key=other)
    _, sig = signing.sign(key, b"x", "der")
    assert not signing.verify(other_cert.public_key(), b"x", sig, "der")


def test_signature_invalid_code_when_signature_tampered(pair):
    _, key, cert = pair
    ev = _active_signature_test(key)
    bad = SignatureEvidence(ev.challenge, bytes([ev.signature[0] ^ 1]) + ev.signature[1:], ev.scheme)
    chk = signature_check(cert, spki_of_certificate(cert), bad, None)
    assert chk.status is CheckStatus.FAIL and chk.code == "SIGNATURE_INVALID"


def test_key_cert_mismatch_code(pair):
    kind, key, cert = pair
    other = (
        ec.generate_private_key(ec.SECP256R1()) if kind == "rsa" else rsa.generate_private_key(65537, 2048)
    )
    ev = _active_signature_test(other)
    other_spki = other.public_key().public_bytes(
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.DER,
        __import__(
            "cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]
        ).PublicFormat.SubjectPublicKeyInfo,
    )
    chk = signature_check(cert, other_spki, ev, None)
    assert chk.code == "KEY_CERT_MISMATCH" and chk.status is CheckStatus.FAIL


@pytest.mark.parametrize(
    "key",
    [
        rsa.generate_private_key(65537, 1024),
        ec.generate_private_key(ec.SECP384R1()),
        ed25519.Ed25519PrivateKey.generate(),
    ],
    ids=["rsa1024", "p384", "ed25519"],
)
def test_unsupported_algorithm_code(key):
    cert, _ = make_leaf(make_ca(), key=key)
    ev = _active_signature_test(key)
    assert ev.error_code == "UNSUPPORTED_ALGORITHM"
    chk = signature_check(cert, spki_of_certificate(cert), ev, None)
    assert chk.code == "UNSUPPORTED_ALGORITHM" and chk.status is CheckStatus.FAIL


def test_key_decryption_failed_code(pair):
    _, _, cert = pair
    decrypt = Check("key_decrypt", CheckStatus.FAIL, "x", code="KEY_DECRYPTION_FAILED")
    chk = signature_check(cert, None, None, decrypt)
    assert chk.code == "KEY_DECRYPTION_FAILED" and chk.status is CheckStatus.FAIL


def test_signature_not_checked_without_key(pair):
    _, _, cert = pair
    assert signature_check(cert, None, None, None).status is CheckStatus.NOT_CHECKED


def test_ecdsa_p1363_roundtrip():
    key = ec.generate_private_key(ec.SECP256R1())
    _, der = signing.sign(key, b"a", "der")
    assert signing.p1363_to_der(signing.der_to_p1363(der)) == der
    assert len(signing.sign(key, b"a", "p1363")[1]) == 64
    with pytest.raises(ValueError):
        signing.p1363_to_der(b"\x00" * 10)


# --- KOD II ------------------------------------------------------------------------------------
DOC = kod2.Kod2Params(
    "TEST",
    "Nip",
    "1111111111",
    "1111111111",
    "01F20A5D352AE590",
    "UtQp9Gpc51y-u3xApZjIjgkpZ01js-J8KflSPW8WzIE",
)


def test_signing_string_matches_official_example():
    """Ciąg do podpisu dokładnie jak w `kody-qr.md` (bez https:// i bez końcowego /)."""
    assert DOC.signing_string() == (
        "qr-test.ksef.mf.gov.pl/certificate/Nip/1111111111/1111111111/01F20A5D352AE590/"
        "UtQp9Gpc51y-u3xApZjIjgkpZ01js-J8KflSPW8WzIE"
    )
    assert kod2.build_url(DOC, "SIG").startswith("https://qr-test.ksef.mf.gov.pl/certificate/Nip/")
    assert (
        kod2.QR_BASE["PROD"] == "https://qr.ksef.mf.gov.pl"
        and kod2.QR_BASE["DEMO"] == "https://qr-demo.ksef.mf.gov.pl"
    )


def test_hash_is_unpadded_base64url_sha256():
    h = kod2.invoice_hash(b"x")
    assert "=" not in h and "+" not in h and "/" not in h and len(h) == 43


def test_kod2_sign_and_verify_rsa_pss_and_ecdsa_p1363(pair):
    kind, key, cert = pair
    params = kod2.Kod2Params(
        "TEST", "Nip", "1234563218", "1234563218", f"{cert.serial_number:016X}", kod2.invoice_hash()
    )
    sig = kod2.sign_signing_string(key, params.signing_string())
    raw = kod2.b64url_decode(sig)
    assert len(raw) == (256 if kind == "rsa" else 64)  # RSA 2048 → 256 B, P1363 → 64 B
    url = kod2.build_url(params, sig)
    assert kod2.verify_url(url, cert.public_key(), params.serial_hex16).code == "KOD2_SIGNATURE_VALID"


def test_kod2_tampered_url_and_wrong_key_invalid(pair):
    kind, key, cert = pair
    params = kod2.Kod2Params(
        "TEST", "Nip", "1234563218", "1234563218", f"{cert.serial_number:016X}", kod2.invoice_hash()
    )
    url = kod2.build_url(params, kod2.sign_signing_string(key, params.signing_string()))
    # 15: niepoprawny podpis KODU II
    assert (
        kod2.verify_url(url.replace("1234563218", "1234563219", 1), cert.public_key()).code
        == "KOD2_SIGNATURE_INVALID"
    )
    assert kod2.verify_url(url[:-4] + "AAAA", cert.public_key()).code == "KOD2_SIGNATURE_INVALID"
    other = make_leaf(
        make_ca(),
        key=rsa.generate_private_key(65537, 2048)
        if kind == "ec"
        else ec.generate_private_key(ec.SECP256R1()),
    )[0]
    assert kod2.verify_url(url, other.public_key()).valid is False


def test_kod2_serial_mismatch_and_malformed():
    key = ec.generate_private_key(ec.SECP256R1())
    cert, _ = make_leaf(make_ca(), key=key)
    url = kod2.build_url(DOC, kod2.sign_signing_string(key, DOC.signing_string()))
    assert kod2.verify_url(url, cert.public_key(), "FFFFFFFFFFFFFFFF").code == "KOD2_SERIAL_MISMATCH"
    for bad in (
        "http://qr-test.ksef.mf.gov.pl/x",
        "https://qr-test.ksef.mf.gov.pl/certificate/Nip/1/2",
        "https://a/b/c/d/e/f/g/h",
    ):
        assert kod2.verify_url(bad, cert.public_key()).code == "KOD2_MALFORMED"


def test_kod2_param_validation():
    with pytest.raises(ValueError):
        kod2.Kod2Params("TEST", "Nip", "1", "1", "XYZ", "h").validate()
    with pytest.raises(ValueError):
        kod2.Kod2Params("TEST", "Zly", "1", "1", "01F20A5D352AE590", "h").validate()
    with pytest.raises(ValueError):
        kod2.Kod2Params("MARS", "Nip", "1", "1", "01F20A5D352AE590", "h").validate()
    with pytest.raises(ValueError):
        kod2.Kod2Params("TEST", "Nip", "1/2", "1", "01F20A5D352AE590", "h").validate()
