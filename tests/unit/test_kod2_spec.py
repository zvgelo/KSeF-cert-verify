"""KOD II wg `kody-qr.md`: format, RSA-PSS, ECDSA P-256 (P1363 i DER), zgodność z przykładem MF, manipulacje."""

from __future__ import annotations

import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from ksef_cert_verify.core import kod2
from ksef_cert_verify.core.report import VerifyOptions
from ksef_cert_verify.operations import Kod2Setup, run_kod2_test
from tests.conftest import KEY_PASSWORD, NOW, _name, make_ca, make_leaf, pem, write_key

pytestmark = pytest.mark.simulated

# Przykład z oficjalnej dokumentacji MF (kody-qr.md): kontekst Nip 1111111111, sprzedawca 1111111111.
MF_SIGNED = "qr-test.ksef.mf.gov.pl/certificate/Nip/1111111111/1111111111/01F20A5D352AE590/UtQp9Gpc51y-u3xApZjIjgkpZ01js-J8KflSPW8WzIE"
MF_SIGNATURE = (
    "mSkm_XmM9fq7PgAJwiL32L9ujhyguOEV48cDB0ncemD2r9TMGa3lr0iRoFk588agCi8QPsOuscUY1rZ7ff76STbGquO-gZtQys5_fHdf2HUfDqPq"
    "VTnUS6HknBu0zLkyf9ygoW7WbH06Ty_8BgQTlOmJFzNWSt9WZa7tAGuAE9JOooNps-KG2PYkkIP4q4jPMp3FKypAygHVnXtS0RDGgOxhhM7LWtFP"
    "7D-dWINbh5yXD8Lr-JVbeOpyQjHa6WmMYavCDQJ3X_Z-iS01LZu2s1B3xuOykl1h0sLObCdADrbxOONsXrvQa61Xt_rxyprVraj2Uf9pANQgR4-12HEcMw"
)
MF_URL = f"https://{MF_SIGNED}/{MF_SIGNATURE}"
HASH = kod2.invoice_hash(b"<Faktura/>")
SERIAL = "01F20A5D352AE590"


def params(**kw):
    base = dict(
        environment="TEST",
        context_type="Nip",
        context_value="1111111111",
        seller_nip="1111111111",
        serial_hex16=SERIAL,
        invoice_hash_b64url=HASH,
    )
    base.update(kw)
    return kod2.Kod2Params(**base)


def keypair(kind):
    key = rsa.generate_private_key(65537, 2048) if kind == "rsa" else ec.generate_private_key(ec.SECP256R1())
    return key


def link_for(key, fmt="p1363", **kw):
    p = params(**kw)
    return p, kod2.build_url(p, kod2.sign_signing_string(key, p.signing_string(), fmt))


# ---- zgodność z przykładem MF -----------------------------------------------------------------
def test_mf_example_parses_into_documented_components():
    link = kod2.parse_url(MF_URL)
    assert link is not None
    assert (link.host, link.context_type, link.context_value, link.seller_nip, link.serial_hex16) == (
        "qr-test.ksef.mf.gov.pl",
        "Nip",
        "1111111111",
        "1111111111",
        SERIAL,
    )
    assert link.invoice_hash_b64url == "UtQp9Gpc51y-u3xApZjIjgkpZ01js-J8KflSPW8WzIE"
    assert link.signed_text == MF_SIGNED  # bez https:// i bez końcowego "/"
    assert len(kod2.b64url_decode(link.invoice_hash_b64url)) == 32  # SHA-256
    assert len(kod2.b64url_decode(link.signature_b64url)) == 256  # RSA 2048 → podpis 256 B
    assert kod2.is_official_url(MF_URL)


def test_mf_example_params_reproduce_documented_signing_string():
    p = params(invoice_hash_b64url="UtQp9Gpc51y-u3xApZjIjgkpZ01js-J8KflSPW8WzIE")
    assert p.signing_string() == MF_SIGNED


def test_mf_example_signature_does_not_verify_with_foreign_key():
    key = keypair("rsa")  # klucza MF nie mamy – obcy klucz musi dać INVALID, a nie MALFORMED
    r = kod2.verify_url(MF_URL, key.public_key())
    assert r.code == "KOD2_SIGNATURE_INVALID"


# ---- RSA-PSS / ECDSA (P1363, DER) i Base64URL -------------------------------------------------
@pytest.mark.parametrize(
    "kind,fmt,enc", [("rsa", "p1363", "RSA-PSS"), ("ec", "p1363", "P1363"), ("ec", "der", "DER")]
)
def test_roundtrip_valid_for_every_algorithm_and_encoding(kind, fmt, enc):
    key = keypair(kind)
    p, url = link_for(key, fmt)
    r = kod2.verify_url(url, key.public_key(), SERIAL)
    assert r.valid and r.encoding == enc


def test_ecdsa_signature_lengths_match_documented_encodings():
    key = keypair("ec")
    p = params()
    p1363 = kod2.b64url_decode(kod2.sign_signing_string(key, p.signing_string(), "p1363"))
    der = kod2.b64url_decode(kod2.sign_signing_string(key, p.signing_string(), "der"))
    assert len(p1363) == 64 and der[0] == 0x30 and 68 <= len(der) <= 72


def test_base64url_has_no_padding_or_standard_alphabet():
    for n in range(1, 40):
        enc = kod2.b64url(bytes(range(250, 250 - n, -1)) if n < 6 else b"\xfb\xff\xfe" * n)
        assert "=" not in enc and "+" not in enc and "/" not in enc
        assert kod2.b64url_decode(enc) == (bytes(range(250, 250 - n, -1)) if n < 6 else b"\xfb\xff\xfe" * n)


def test_url_format_and_signing_string():
    key = keypair("ec")
    p, url = link_for(key)
    assert url.startswith(
        "https://qr-test.ksef.mf.gov.pl/certificate/Nip/1111111111/1111111111/" + SERIAL + "/"
    )
    assert not p.signing_string().startswith("https://") and not p.signing_string().endswith("/")
    assert url.count("/") == 9  # https:// (2) + 7 separatorów ścieżki
    assert params(environment="PROD").signing_string().startswith("qr.ksef.mf.gov.pl/")
    assert params(environment="DEMO").signing_string().startswith("qr-demo.ksef.mf.gov.pl/")


def test_invoice_hash_is_sha256_of_file_bytes_base64url():
    assert kod2.invoice_hash(b"abc") == kod2.b64url(hashlib.sha256(b"abc").digest())
    assert len(kod2.invoice_hash(b"abc")) == 43


# ---- manipulacje i niezgodności ---------------------------------------------------------------
@pytest.mark.parametrize("kind", ["rsa", "ec"])
def test_modified_signature_is_rejected(kind):
    key = keypair(kind)
    _, url = link_for(key)
    head, sig = url.rsplit("/", 1)
    raw = bytearray(kod2.b64url_decode(sig))
    raw[5] ^= 0x01
    assert (
        kod2.verify_url(f"{head}/{kod2.b64url(bytes(raw))}", key.public_key()).code
        == "KOD2_SIGNATURE_INVALID"
    )


@pytest.mark.parametrize("kind", ["rsa", "ec"])
def test_changed_seller_nip_hash_context_or_serial_invalidate(kind):
    key = keypair(kind)
    _, url = link_for(key)
    link = kod2.parse_url(url)
    assert link is not None
    sig = link.signature_b64url
    for field, value in (
        ("seller_nip", "5260250995"),
        ("invoice_hash_b64url", kod2.invoice_hash(b"inna")),
        ("context_value", "5260250995"),
        ("serial_hex16", "01F20A5D352AE591"),
    ):
        data = {**link.__dict__, field: value}
        changed = kod2.Kod2Link(**data)
        bad = f"https://{changed.signed_text}/{sig}"
        assert kod2.verify_url(bad, key.public_key()).code == "KOD2_SIGNATURE_INVALID", field


def test_expected_values_detect_mismatch_before_signature_check():
    key = keypair("ec")
    _, url = link_for(key)
    pub = key.public_key()
    assert kod2.verify_url(url, pub, "01F20A5D352AE591").code == "KOD2_SERIAL_MISMATCH"
    assert kod2.verify_url(url, pub, expected_seller_nip="5260250995").code == "KOD2_SELLER_MISMATCH"
    assert (
        kod2.verify_url(url, pub, expected_invoice_hash=kod2.invoice_hash(b"x")).code == "KOD2_HASH_MISMATCH"
    )
    assert kod2.verify_url(url, pub, expected_context=("Nip", "5260250995")).code == "KOD2_CONTEXT_MISMATCH"
    assert kod2.verify_url(url, pub, SERIAL, expected_context=("Nip", "1111111111")).valid


@pytest.mark.parametrize("kind", ["rsa", "ec"])
def test_wrong_certificate_key_is_rejected(kind):
    signer, other = keypair(kind), keypair(kind)
    _, url = link_for(signer)
    assert kod2.verify_url(url, other.public_key()).code == "KOD2_SIGNATURE_INVALID"


@pytest.mark.parametrize(
    "bad",
    [
        "http://qr-test.ksef.mf.gov.pl/certificate/Nip/1/2/3/4/5",
        "https://qr-test.ksef.mf.gov.pl/certificate/Nip/1111111111/1111111111/SERIAL/HASH",
        "https://qr-test.ksef.mf.gov.pl/other/Nip/1111111111/1111111111/SERIAL/HASH/SIG",
        "https://qr-test.ksef.mf.gov.pl/certificate/Bad/1111111111/1111111111/SERIAL/HASH/SIG",
    ],
)
def test_malformed_links(bad):
    assert kod2.verify_url(bad, keypair("ec").public_key()).code == "KOD2_MALFORMED"


def test_params_validation_rejects_invalid_nip_serial_and_hash():
    for kw in (
        {"context_value": "1234567890"},  # zła suma kontrolna
        {"seller_nip": "123"},
        {"serial_hex16": "xyz"},
        {"invoice_hash_b64url": "krotki"},
        {"context_type": "Zly"},
    ):
        with pytest.raises(ValueError):
            params(**kw).validate()


def test_only_official_hosts_are_openable():
    assert kod2.is_official_url(
        "https://qr.ksef.mf.gov.pl/certificate/Nip/1111111111/1111111111/" + SERIAL + "/" + HASH + "/sig"
    )
    assert not kod2.is_official_url(
        "https://evil.example/certificate/Nip/1111111111/1111111111/" + SERIAL + "/" + HASH + "/sig"
    )
    assert not kod2.is_official_url("javascript:alert(1)")


# ---- faktura XML ------------------------------------------------------------------------------
INVOICE = (
    '<?xml version="1.0" encoding="UTF-8"?><Faktura xmlns="http://crd.gov.pl/wzor/2025/06/25/13775/">'
    "<Podmiot1><DaneIdentyfikacyjne><NIP>5260250995</NIP><Nazwa>Sprzedawca</Nazwa></DaneIdentyfikacyjne></Podmiot1></Faktura>"
)


def test_read_invoice_hash_and_seller(tmp_path):
    f = tmp_path / "f.xml"
    f.write_text(INVOICE, encoding="utf-8")
    info = kod2.read_invoice(f)
    assert info.seller_nip == "5260250995" and info.hash_b64url == kod2.invoice_hash(f.read_bytes())


def test_read_invoice_rejects_non_xml_and_does_not_resolve_entities(tmp_path):
    bad = tmp_path / "b.xml"
    bad.write_text("to nie xml", encoding="utf-8")
    with pytest.raises(ValueError):
        kod2.read_invoice(bad)
    secret = tmp_path / "secret.txt"
    secret.write_text("TAJNE", encoding="utf-8")
    xxe = tmp_path / "x.xml"
    xxe.write_text(
        f'<?xml version="1.0"?><!DOCTYPE f [<!ENTITY e SYSTEM "{secret.as_uri()}">]><Faktura><Podmiot1>'
        "<DaneIdentyfikacyjne><NIP>&e;</NIP></DaneIdentyfikacyjne></Podmiot1></Faktura>",
        encoding="utf-8",
    )
    assert "TAJNE" not in str(kod2.read_invoice(xxe))


# ---- operacje: certyfikat Offline vs Authentication, syntetyczny vs faktura -------------------
def offline_files(tmp_path, kind="ec", cert_kind="Offline"):
    key = keypair(kind)
    cert, _ = make_leaf(
        make_ca(), kind=cert_kind, key=key, subject=_name(cn="J", given="J", sn="O", serial="TINPL5260250995")
    )
    c = tmp_path / f"{cert_kind}.crt"
    c.write_bytes(pem(cert))
    return c, write_key(tmp_path / f"{cert_kind}.key", key)


def run(c, k, **setup):
    return run_kod2_test(
        c, k, VerifyOptions(now=NOW), lambda *_a: KEY_PASSWORD, Kod2Setup("TEST", "Nip", **setup)
    )


def test_authentication_certificate_cannot_sign_kod2(tmp_path):
    c, k = offline_files(tmp_path, cert_kind="Authentication")
    op = run(c, k).certificates[0].operations["kod2"]
    assert op["code"] == "KOD2_NOT_APPLICABLE" and "url" not in op


@pytest.mark.parametrize("kind", ["ec", "rsa"])
def test_offline_certificate_synthetic_test_without_invoice(tmp_path, kind):
    c, k = offline_files(tmp_path, kind)
    op = run(c, k, context_value="5260250995").certificates[0].operations["kod2"]
    assert op["status"] == "PASS" and op["kind"] == "SYNTHETIC_CRYPTO_TEST" and op["synthetic"] is True
    assert op["issuing_authority"]["status"] == "NOT_VERIFIED"  # uprawnień nie weryfikujemy (brak API)
    assert op["registry_status"] == "NOT_CHECKED"  # status w rejestrze to osobna rzecz
    assert (kind == "rsa" and op["signature_format"] == "RSA-PSS") or op["encodings_verified"] == [
        "P1363",
        "DER",
    ]


def test_offline_certificate_with_invoice_builds_real_link(tmp_path):
    c, k = offline_files(tmp_path)
    f = tmp_path / "f.xml"
    f.write_text(INVOICE, encoding="utf-8")
    op = run(c, k, context_value="5260250995", invoice_path=f).certificates[0].operations["kod2"]
    assert op["status"] == "PASS" and op["kind"] == "INVOICE_LINK" and op["synthetic"] is False
    assert op["invoice_hash"] == kod2.invoice_hash(f.read_bytes()) and op["seller_nip"] == "5260250995"
    assert op["openable"] is True and op["url"].startswith("https://qr-test.ksef.mf.gov.pl/certificate/Nip/")
    prod = run_kod2_test(
        c,
        k,
        VerifyOptions(now=NOW),
        lambda *_a: KEY_PASSWORD,
        Kod2Setup("PROD", "Nip", "5260250995", None, f),
    )
    assert prod.certificates[0].operations["kod2"]["openable"] is True
    synth = run_kod2_test(
        c, k, VerifyOptions(now=NOW), lambda *_a: KEY_PASSWORD, Kod2Setup("PROD", "Nip", "5260250995")
    )
    assert (
        synth.certificates[0].operations["kod2"]["openable"] is False
    )  # PROD + dane syntetyczne: nie otwieramy


def test_invoice_seller_mismatch_and_invalid_file_fail(tmp_path):
    c, k = offline_files(tmp_path)
    f = tmp_path / "f.xml"
    f.write_text(INVOICE, encoding="utf-8")
    op = (
        run(c, k, context_value="5260250995", seller_nip="1111111111", invoice_path=f)
        .certificates[0]
        .operations["kod2"]
    )
    assert op["code"] == "KOD2_SELLER_MISMATCH" and op["status"] == "FAIL"
    bad = tmp_path / "bad.xml"
    bad.write_text("nie xml", encoding="utf-8")
    op = run(c, k, context_value="5260250995", invoice_path=bad).certificates[0].operations["kod2"]
    assert op["code"] == "KOD2_INVOICE_INVALID"


def test_wrong_key_for_offline_certificate_does_not_sign(tmp_path):
    c, _ = offline_files(tmp_path)
    other = write_key(tmp_path / "other.key", keypair("ec"))
    op = run(c, other).certificates[0].operations.get("kod2")
    assert op is None or op["status"] != "PASS"
    assert not (op and op.get("url"))
