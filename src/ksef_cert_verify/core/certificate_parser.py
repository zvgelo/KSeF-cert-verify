"""Odczyt pól X.509 do modelu domenowego oraz identyfikacja podmiotu."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

from .models import CertInfo, CertType, ExtensionInfo, SubjectInfo

OID_ORG_IDENTIFIER = x509.ObjectIdentifier("2.5.4.97")
OID_UNIQUE_IDENTIFIER = x509.ObjectIdentifier("2.5.4.45")

# Atrybuty DN dopuszczone w `certyfikaty-KSeF.md` §2.
KSEF_DN_OIDS = {
    NameOID.COMMON_NAME,
    NameOID.SURNAME,
    NameOID.SERIAL_NUMBER,
    NameOID.COUNTRY_NAME,
    NameOID.ORGANIZATION_NAME,
    NameOID.GIVEN_NAME,
    OID_UNIQUE_IDENTIFIER,
    OID_ORG_IDENTIFIER,
}

# Rozszerzenia, które program rozumie i egzekwuje/ignoruje bezpiecznie. NameConstraints, PolicyConstraints
# i InhibitAnyPolicy celowo NIE są tu wymienione: nie są egzekwowane, więc ich krytyczna obecność → FAIL.
KNOWN_EXTENSION_OIDS = {
    x509.ExtensionOID.BASIC_CONSTRAINTS,
    x509.ExtensionOID.KEY_USAGE,
    x509.ExtensionOID.EXTENDED_KEY_USAGE,
    x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER,
    x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
    x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
    x509.ExtensionOID.ISSUER_ALTERNATIVE_NAME,
    x509.ExtensionOID.CERTIFICATE_POLICIES,
    x509.ExtensionOID.CRL_DISTRIBUTION_POINTS,
    x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
}

_SERIAL_PESEL = re.compile(r"(?:PNOPL|PESEL).*?(\d{11})", re.DOTALL)
_SERIAL_NIP = re.compile(r"(?:TINPL|NIP).*?(\d{10})", re.DOTALL)
_ORGID_VAT = re.compile(r"VATPL.*?(\d{10})", re.DOTALL)


def valid_pesel(value: str) -> bool:
    if not re.fullmatch(r"\d{11}", value):
        return False
    w = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
    return (10 - sum(int(c) * k for c, k in zip(value, w)) % 10) % 10 == int(value[10])


def valid_nip(value: str) -> bool:
    if not re.fullmatch(r"\d{10}", value):
        return False
    w = (6, 5, 7, 2, 3, 4, 5, 6, 7)
    s = sum(int(c) * k for c, k in zip(value, w)) % 11
    return s != 10 and s == int(value[9])


def _attr(name: x509.Name, oid: x509.ObjectIdentifier) -> list[str]:
    return [str(a.value) for a in name.get_attributes_for_oid(oid)]


def parse_subject(name: x509.Name) -> tuple[SubjectInfo, list[str]]:
    """Zwraca dane podmiotu i listę uwag (np. identyfikator o błędnej sumie kontrolnej).

    NIP/PESEL są wyciągane wyłącznie z atrybutów i wzorców opisanych przez MF
    (`auth/podpis-xades.md`) i tylko przy poprawnej sumie kontrolnej.
    """
    notes: list[str] = []

    def first(oid: x509.ObjectIdentifier) -> str | None:
        v = _attr(name, oid)
        return v[0] if v else None

    info = SubjectInfo(
        common_name=first(NameOID.COMMON_NAME),
        given_names=_attr(name, NameOID.GIVEN_NAME),
        surname=first(NameOID.SURNAME),
        organization=first(NameOID.ORGANIZATION_NAME),
        country=first(NameOID.COUNTRY_NAME),
        serial_number=first(NameOID.SERIAL_NUMBER),
        organization_identifier=first(OID_ORG_IDENTIFIER),
        unique_identifier=first(OID_UNIQUE_IDENTIFIER),
    )
    has_person = bool(info.given_names or info.surname)
    has_org = bool(info.organization or info.organization_identifier)
    if has_person and not has_org:
        info.kind = "person"
    elif has_org and not has_person:
        info.kind = "organization"

    if info.serial_number:
        if (m := _SERIAL_PESEL.match(info.serial_number)) is not None:
            if valid_pesel(m.group(1)):
                info.pesel = m.group(1)
            else:
                notes.append("PESEL w serialNumber ma nieprawidłową sumę kontrolną – pominięto.")
        elif (m := _SERIAL_NIP.match(info.serial_number)) is not None:
            if valid_nip(m.group(1)):
                info.nip = m.group(1)
            else:
                notes.append("NIP w serialNumber ma nieprawidłową sumę kontrolną – pominięto.")
    if info.organization_identifier and (m := _ORGID_VAT.match(info.organization_identifier)):
        if valid_nip(m.group(1)):
            info.nip = m.group(1)
        else:
            notes.append("NIP w organizationIdentifier ma nieprawidłową sumę kontrolną – pominięto.")
    return info, notes


def key_description(cert: x509.Certificate) -> tuple[str, str, int | str | None]:
    """(opis, rodzina, bity_lub_krzywa). Rodzina: RSA | EC | inna."""
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA {key.key_size}", "RSA", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        curve = key.curve.name
        nice = {"secp256r1": "ECDSA P-256", "secp384r1": "ECDSA P-384", "secp521r1": "ECDSA P-521"}
        return nice.get(curve, f"EC {curve}"), "EC", curve
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", "inna", None
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", "inna", None
    if isinstance(key, dsa.DSAPublicKey):
        return f"DSA {key.key_size}", "inna", key.key_size
    return type(key).__name__, "inna", None


def _fmt_hex(b: bytes) -> str:
    return b.hex().upper()


def _key_usage_names(ku: x509.KeyUsage) -> list[str]:
    names = [
        ("digital_signature", "Digital Signature"),
        ("content_commitment", "Non-Repudiation"),
        ("key_encipherment", "Key Encipherment"),
        ("data_encipherment", "Data Encipherment"),
        ("key_agreement", "Key Agreement"),
        ("key_cert_sign", "Certificate Sign"),
        ("crl_sign", "CRL Sign"),
    ]
    out = [label for attr, label in names if getattr(ku, attr)]
    if ku.key_agreement:
        if ku.encipher_only:
            out.append("Encipher Only")
        if ku.decipher_only:
            out.append("Decipher Only")
    return out


def key_usage_flags(cert: x509.Certificate) -> set[str] | None:
    """Zbiór nazw bitów Key Usage albo None gdy rozszerzenia brak."""
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return None
    return set(_key_usage_names(ku))


def aware(dt: datetime) -> datetime:
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def not_before(cert: x509.Certificate) -> datetime:
    return aware(cert.not_valid_before_utc)


def not_after(cert: x509.Certificate) -> datetime:
    return aware(cert.not_valid_after_utc)


def fingerprint(cert: x509.Certificate) -> str:
    return _fmt_hex(cert.fingerprint(hashes.SHA256()))


def signature_algorithm_name(cert: x509.Certificate) -> str:
    oid = cert.signature_algorithm_oid
    return getattr(oid, "_name", None) or oid.dotted_string


_DN_NAMES = {
    NameOID.SERIAL_NUMBER.dotted_string: "serialNumber",
    NameOID.SURNAME.dotted_string: "SN",
    NameOID.GIVEN_NAME.dotted_string: "GN",
    OID_ORG_IDENTIFIER.dotted_string: "organizationIdentifier",
    OID_UNIQUE_IDENTIFIER.dotted_string: "uniqueIdentifier",
}


def dn_string(name: x509.Name) -> str:
    """RFC 4514 z czytelnymi nazwami atrybutów KSeF zamiast surowych OID."""
    return name.rfc4514_string(
        attr_name_overrides={x509.ObjectIdentifier(k): v for k, v in _DN_NAMES.items()}
    )


def serial_hex(cert: x509.Certificate) -> str:
    """Hex; dla numerów mieszczących się w 64 bitach dopełniony do 16 znaków (format z API KSeF)."""
    n = cert.serial_number
    return f"{n:016X}" if 0 <= n < 1 << 64 else f"{n:X}"


def owner_info(
    info: CertInfo, cert_type: CertType | str, notes: list[str] | None = None
) -> dict[str, object]:
    """Właściciel certyfikatu = WYŁĄCZNIE dane z X.509 Subject (bez gadania z API, bez zgadywania).

    To nie jest „kontekst KSeF" (NIP wskazany do uwierzytelnienia) ani „podmiot z API" (dane zwrócone przez rejestr);
    nazwa własna certyfikatu nadana w KSeF nie jest dowodem tożsamości właściciela. Brak danych = None."""
    s = info.subject_info
    person = " ".join([*s.given_names, s.surname or ""]).strip()
    name = person or s.organization or s.common_name or None
    return {
        "source": "X.509 Subject",
        "kind": s.kind,
        "name": name,
        "given_names": list(s.given_names),
        "surname": s.surname,
        "organization": s.organization,
        "common_name": s.common_name,
        "nip": s.nip,
        "pesel": s.pesel,
        "organization_identifier": s.organization_identifier,
        "country": s.country,
        "certificate_type": getattr(cert_type, "value", cert_type),
        "not_after": info.not_after,
        "notes": list(notes or []),
    }


def api_serial(cert: x509.Certificate) -> str | None:
    """Numer seryjny X.509 w formacie `certificateSerialNumber` API KSeF (`^[0-9A-F]{16}$`).

    Konwersja bez utraty informacji: liczba nieujemna mieszcząca się w 64 bitach → 16 znaków HEX z zerami wiodącymi.
    Inny numer (ujemny, dłuższy) nie ma w API reprezentacji → None (nie wolno go obcinać ani zgadywać)."""
    n = cert.serial_number
    return f"{n:016X}" if 0 <= n < 1 << 64 else None


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_certificate(cert: x509.Certificate) -> tuple[CertInfo, list[str]]:
    exts = cert.extensions
    ski = aki = bc_text = None
    eku: list[str] = []
    ku_names: list[str] = []
    is_ca = False
    ext_infos: list[ExtensionInfo] = []
    for ext in exts:
        oid = ext.oid
        ext_infos.append(
            ExtensionInfo(oid.dotted_string, getattr(oid, "_name", oid.dotted_string), ext.critical)
        )
        v = ext.value
        if isinstance(v, x509.SubjectKeyIdentifier):
            ski = _fmt_hex(v.digest)
        elif isinstance(v, x509.AuthorityKeyIdentifier) and v.key_identifier:
            aki = _fmt_hex(v.key_identifier)
        elif isinstance(v, x509.BasicConstraints):
            is_ca = v.ca
            bc_text = f"CA={'TRUE' if v.ca else 'FALSE'}" + (
                f", pathLen={v.path_length}" if v.path_length is not None else ""
            )
        elif isinstance(v, x509.KeyUsage):
            ku_names = _key_usage_names(v)
        elif isinstance(v, x509.ExtendedKeyUsage):
            eku = [getattr(o, "_name", o.dotted_string) for o in v]
    subject_info, notes = parse_subject(cert.subject)
    key_text, _, _ = key_description(cert)
    info = CertInfo(
        subject=dn_string(cert.subject),
        issuer=dn_string(cert.issuer),
        serial_hex=serial_hex(cert),
        not_before=iso(not_before(cert)),
        not_after=iso(not_after(cert)),
        fingerprint_sha256=fingerprint(cert),
        signature_algorithm=signature_algorithm_name(cert),
        key_algorithm=key_text,
        ski=ski,
        aki=aki,
        key_usage=ku_names,
        extended_key_usage=eku,
        basic_constraints=bc_text,
        is_ca=is_ca,
        extensions=ext_infos,
        subject_info=subject_info,
    )
    return info, notes
