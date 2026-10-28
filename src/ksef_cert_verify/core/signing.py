"""Operacje podpisu/weryfikacji na kluczach RSA 2048 i EC P-256 (wyłącznie `cryptography`, bez własnej kryptografii).

Schematy zgodne z dokumentacją MF (`kody-qr.md`, `auth/podpis-xades.md`):
* RSA 2048: RSASSA-PSS, SHA-256, MGF1(SHA-256), sól 32 B  (KOD II)
* EC P-256: ECDSA z SHA-256; podpis w formacie IEEE P1363 (R||S, po 32 B) albo DER (RFC 3279)

Podpis testowy z tego modułu jest ODRĘBNY od podpisu XAdES i podpisu KODU II – podpisuje losowe dane testowe.
"""

from __future__ import annotations

from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

SCHEME_RSA_PSS = "RSASSA-PSS-SHA256"
SCHEME_ECDSA = "ECDSA-P256-SHA256"
EcFormat = Literal["der", "p1363"]
_PSS_SALT = 32


class UnsupportedKeyError(Exception):
    """Klucz spoza dozwolonych: RSA 2048 albo EC NIST P-256."""


def scheme_for_private_key(key: object) -> str:
    if isinstance(key, rsa.RSAPrivateKey):
        if key.key_size != 2048:
            raise UnsupportedKeyError(f"RSA {key.key_size} bitów (KSeF dopuszcza wyłącznie 2048)")
        return SCHEME_RSA_PSS
    if isinstance(key, ec.EllipticCurvePrivateKey):
        if key.curve.name != "secp256r1":
            raise UnsupportedKeyError(f"krzywa {key.curve.name} (KSeF dopuszcza wyłącznie NIST P-256)")
        return SCHEME_ECDSA
    raise UnsupportedKeyError(f"algorytm klucza {type(key).__name__} (dozwolone: RSA 2048, EC P-256)")


def scheme_for_public_key(key: object) -> str:
    if isinstance(key, rsa.RSAPublicKey):
        if key.key_size != 2048:
            raise UnsupportedKeyError(f"RSA {key.key_size} bitów")
        return SCHEME_RSA_PSS
    if isinstance(key, ec.EllipticCurvePublicKey):
        if key.curve.name != "secp256r1":
            raise UnsupportedKeyError(f"krzywa {key.curve.name}")
        return SCHEME_ECDSA
    raise UnsupportedKeyError(f"algorytm klucza {type(key).__name__}")


def sign(key: object, data: bytes, ec_format: EcFormat = "der") -> tuple[str, bytes]:
    """Podpisuje `data`; zwraca (schemat, podpis)."""
    scheme = scheme_for_private_key(key)
    if scheme == SCHEME_RSA_PSS:
        if not isinstance(key, rsa.RSAPrivateKey):
            raise UnsupportedKeyError("oczekiwano klucza RSA")
        sig = key.sign(
            data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=_PSS_SALT), hashes.SHA256()
        )
        return scheme, sig
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise UnsupportedKeyError("oczekiwano klucza EC")
    der = key.sign(data, ec.ECDSA(hashes.SHA256()))
    return scheme, (der if ec_format == "der" else der_to_p1363(der))


def verify(public_key: object, data: bytes, signature: bytes, ec_format: EcFormat = "der") -> bool:
    """Weryfikuje podpis; zwraca False dla niepoprawnego podpisu. Wyjątek UnsupportedKeyError dla złego klucza."""
    scheme = scheme_for_public_key(public_key)
    try:
        if scheme == SCHEME_RSA_PSS:
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise UnsupportedKeyError("oczekiwano klucza RSA")
            public_key.verify(
                signature,
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=_PSS_SALT),
                hashes.SHA256(),
            )
        else:
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise UnsupportedKeyError("oczekiwano klucza EC")
            der = signature if ec_format == "der" else p1363_to_der(signature)
            public_key.verify(der, data, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return False
    return True


def der_to_p1363(der: bytes) -> bytes:
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def p1363_to_der(sig: bytes) -> bytes:
    if len(sig) != 64:
        raise ValueError("podpis P1363 P-256 musi mieć 64 bajty")
    return encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
