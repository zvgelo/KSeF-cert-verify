"""Fixtury SYMULOWANE.

Wszystkie certyfikaty poniżej są generowane lokalnie na potrzeby testów mechanizmów
kryptograficznych. NIE są certyfikatami KSeF, a ich akceptacja nie dowodzi zgodności z MF
(MF nie publikuje certyfikatów referencyjnych ani CA – patrz docs/TECHNICAL_FINDINGS.md).
Daty są liczone względem stałego zegara testowego NOW, więc fixtury nie "wygasają".
"""

from __future__ import annotations

import datetime as dt
import os
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")  # GUI headless (Linux CI)

NOW = dt.datetime(2026, 10, 28, 12, 0, tzinfo=dt.UTC)
OID_ORGID = x509.ObjectIdentifier("2.5.4.97")


def _name(**kw: str) -> x509.Name:
    attrs = []
    if "cn" in kw:
        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, kw["cn"]))
    if "o" in kw:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, kw["o"]))
    if "orgid" in kw:
        attrs.append(x509.NameAttribute(OID_ORGID, kw["orgid"]))
    if "given" in kw:
        attrs.append(x509.NameAttribute(NameOID.GIVEN_NAME, kw["given"]))
    if "sn" in kw:
        attrs.append(x509.NameAttribute(NameOID.SURNAME, kw["sn"]))
    if "serial" in kw:
        attrs.append(x509.NameAttribute(NameOID.SERIAL_NUMBER, kw["serial"]))
    attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, kw.get("c", "PL")))
    return x509.Name(attrs)


# Rejestr kluczy wygenerowanych w testach (SPKI DER → klucz prywatny), aby testy jednostkowe mogły modelować
# poprawnie zweryfikowaną parę kluczy z prawdziwym podpisem testowym.
KEYS: dict[bytes, object] = {}


def _remember(cert, key):
    KEYS[
        cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ] = key


@dataclass
class CA:
    cert: x509.Certificate
    key: ec.EllipticCurvePrivateKey
    name: x509.Name


def make_ca(
    cn: str = "Symulowane CA (test)",
    *,
    days: int = 3650,
    key=None,
    path_length=None,
    ca: bool = True,
    key_cert_sign: bool = True,
    not_before=None,
) -> CA:
    key = key or ec.generate_private_key(ec.SECP256R1())
    name = _name(cn=cn)
    nb = not_before or NOW - dt.timedelta(days=365)
    b = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(nb + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, key_cert_sign, key_cert_sign, False, False),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    cert = b.sign(key, hashes.SHA256())
    _remember(cert, key)
    return CA(cert, key, name)


def make_leaf(
    issuer: CA,
    *,
    kind: str = "Authentication",
    subject: x509.Name | None = None,
    key=None,
    days_valid: int = 365,
    not_before: dt.datetime | None = None,
    key_usage: x509.KeyUsage | None = None,
    extra_exts: list[tuple[x509.ExtensionType, bool]] | None = None,
    hash_alg=None,
    serial: int | None = None,
    is_ca: bool | None = None,
):
    key = key or ec.generate_private_key(ec.SECP256R1())
    subject = subject or _name(
        cn="Jan Testowy",
        given="Jan",
        sn="Testowy",
        serial="PNOPL44051401359",  # PESEL z poprawną sumą
    )
    ds = kind == "Authentication"
    ku = key_usage or x509.KeyUsage(ds, not ds, False, False, False, False, False, False, False)
    nb = not_before or NOW - dt.timedelta(days=10)
    b = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.name)
        .public_key(key.public_key())
        .serial_number(serial if serial is not None else 0x018209160C631F1E)
        .not_valid_before(nb)
        .not_valid_after(nb + dt.timedelta(days=days_valid))
        .add_extension(ku, critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.key.public_key()), critical=False
        )
    )
    if is_ca is not None:
        b = b.add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    for ext, crit in extra_exts or []:
        b = b.add_extension(ext, critical=crit)
    cert = b.sign(issuer.key, hash_alg or hashes.SHA256())
    _remember(cert, key)
    return cert, key


def pem(*certs: x509.Certificate) -> bytes:
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)


def der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


@pytest.fixture
def now():
    return NOW


@pytest.fixture
def ca():
    return make_ca()


@pytest.fixture
def anchor_file(tmp_path, ca):
    p = tmp_path / "trust" / "ca.pem"
    p.parent.mkdir()
    p.write_bytes(pem(ca.cert))
    return p


@pytest.fixture
def auth_cert(ca):
    return make_leaf(ca, kind="Authentication")


@pytest.fixture
def offline_cert(ca):
    return make_leaf(ca, kind="Offline")


def write_p12(path: Path, cert, key, password: bytes | None, extra=()):
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    path.write_bytes(pkcs12.serialize_key_and_certificates(b"test", key, cert, list(extra) or None, enc))
    return path


KEY_PASSWORD = "haslo-do-klucza-123"


def write_key(
    path: Path, key, password: str | None = KEY_PASSWORD, fmt: str = "pkcs8", encoding: str = "pem"
) -> Path:
    """Zapisuje klucz prywatny (zaszyfrowany hasłem, jeśli podano) – tylko do testów."""
    pf = {
        "pkcs8": serialization.PrivateFormat.PKCS8,
        "traditional": serialization.PrivateFormat.TraditionalOpenSSL,
    }[fmt]
    enc = (
        serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    )
    enc_type = serialization.Encoding.PEM if encoding == "pem" else serialization.Encoding.DER
    path.write_bytes(key.private_bytes(enc_type, pf, enc))
    return path


@pytest.fixture
def auth_key_file(tmp_path, auth_cert):
    return write_key(tmp_path / "KSeF_Ksiegowosc.key", auth_cert[1])


@pytest.fixture
def key_pw():
    """Dostawca hasła zwracający poprawne hasło klucza."""
    return lambda path, retry: None if retry else KEY_PASSWORD
