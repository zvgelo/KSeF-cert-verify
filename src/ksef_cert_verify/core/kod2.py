"""KOD II – podpis linku weryfikacyjnego certyfikatu Offline (oficjalna specyfikacja: `kody-qr.md`, §2).

Format (nie wymyślamy własnego):
  https://<host QR>/certificate/<ContextIdentifierType>/<ContextIdentifierValue>/<SellerNip>/<SerialCertyfikatu>/
  <SHA-256 faktury, Base64URL>/<podpis, Base64URL>
Podpisywana jest ścieżka URL BEZ prefiksu `https://` i BEZ końcowego `/` (i bez samego podpisu).
Algorytmy: RSA → RSASSA-PSS (SHA-256, MGF1 SHA-256, sól 32 B); EC P-256 → ECDSA SHA-256, podpis P1363 (R||S).

Domyślnie używamy danych SYNTETYCZNYCH (test kryptograficzny bez faktury). Z plikiem faktury XML link zawiera jej
prawdziwy skrót SHA-256. Link nie jest nigdzie wysyłany ani otwierany bez świadomej akcji użytkownika.

Co NIE jest tu weryfikowane: uprawnienia wystawcy do wystawienia faktury (InvoiceWrite w kontekście) oraz status
certyfikatu w rejestrze sprawdza dopiero system KSeF po otwarciu linku. MF nie udostępnia udokumentowanego,
maszynowo odczytywalnego interfejsu tej weryfikacji (OpenAPI nie ma takiego endpointu), więc nie parsujemy HTML
i nie deklarujemy automatycznego potwierdzenia. Otwarcie strony lub HTTP 200 NIE jest dowodem autentyczności wystawcy.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from typing import Any

from . import signing
from .certificate_parser import valid_nip

QR_BASE = {
    "TEST": "https://qr-test.ksef.mf.gov.pl",
    "DEMO": "https://qr-demo.ksef.mf.gov.pl",
    "PROD": "https://qr.ksef.mf.gov.pl",
}
CONTEXT_TYPES = ("Nip", "InternalId", "NipVatUe", "PeppolId")
SYNTHETIC_INVOICE = "SYNTETYCZNA FAKTURA TESTOWA – dane sztuczne, nie jest to prawdziwa faktura.".encode()
_SERIAL = re.compile(r"[0-9A-F]{16}")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def invoice_hash(invoice: bytes = SYNTHETIC_INVOICE) -> str:
    return b64url(hashlib.sha256(invoice).digest())


MAX_INVOICE_BYTES = 20 * 1024 * 1024


@dataclass(frozen=True)
class InvoiceInfo:
    hash_b64url: str  # SHA-256 całego pliku (bajty bez zmian), Base64URL – tak jak w specyfikacji
    seller_nip: str | None  # Podmiot1/DaneIdentyfikacyjne/NIP, jeśli występuje
    size: int


def read_invoice(path: Any) -> InvoiceInfo:
    """Odczyt faktury XML z dysku: skrót pliku + NIP sprzedawcy (Podmiot1). Plik NIE jest nigdzie wysyłany.

    Parser XML jest zabezpieczony (bez encji zewnętrznych i bez sieci); błędny XML to ValueError."""
    from pathlib import Path

    from lxml import etree

    p = Path(path)
    if not p.is_file():
        raise ValueError(f"Nie znaleziono pliku faktury: {p.name}")
    if p.stat().st_size > MAX_INVOICE_BYTES:
        raise ValueError("Plik faktury jest większy niż 20 MB.")
    data = p.read_bytes()
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False, huge_tree=False)
    try:
        root = etree.fromstring(data, parser)
    except etree.XMLSyntaxError as exc:
        raise ValueError(f"To nie jest poprawny plik XML: {exc}") from None
    nips = root.xpath(
        "//*[local-name()='Podmiot1']/*[local-name()='DaneIdentyfikacyjne']/*[local-name()='NIP']/text()"
    )
    seller = nips[0].strip() if nips else None
    return InvoiceInfo(invoice_hash(data), seller, len(data))


@dataclass(frozen=True)
class Kod2Params:
    environment: str  # TEST | DEMO | PROD
    context_type: str
    context_value: str
    seller_nip: str
    serial_hex16: str
    invoice_hash_b64url: str

    def validate(self) -> None:
        if self.environment not in QR_BASE:
            raise ValueError(f"Nieznane środowisko QR: {self.environment}")
        if self.context_type not in CONTEXT_TYPES:
            raise ValueError(f"ContextIdentifierType musi być jednym z: {', '.join(CONTEXT_TYPES)}")
        if not _SERIAL.fullmatch(self.serial_hex16):
            raise ValueError("Numer seryjny certyfikatu musi mieć 16 znaków hex (A-F, 0-9)")
        for part in (self.context_value, self.seller_nip, self.invoice_hash_b64url):
            if not part or "/" in part:
                raise ValueError("Elementy linku nie mogą być puste ani zawierać '/'")
        if self.context_type == "Nip" and not (
            len(self.context_value) == 10 and valid_nip(self.context_value)
        ):
            raise ValueError("Kontekst typu Nip wymaga poprawnego NIP (10 cyfr, suma kontrolna).")
        if not (len(self.seller_nip) == 10 and valid_nip(self.seller_nip)):
            raise ValueError("NIP sprzedawcy musi być poprawnym NIP (10 cyfr, suma kontrolna).")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", self.invoice_hash_b64url):
            raise ValueError("Skrót faktury musi być SHA-256 w Base64URL (43 znaki).")

    def signing_string(self) -> str:
        """Ciąg podpisywany: ścieżka bez `https://` i bez końcowego `/`."""
        self.validate()
        host = QR_BASE[self.environment].removeprefix("https://")
        return "/".join(
            [
                host,
                "certificate",
                self.context_type,
                self.context_value,
                self.seller_nip,
                self.serial_hex16,
                self.invoice_hash_b64url,
            ]
        )


def sign_signing_string(key: Any, signing_string: str, ec_format: signing.EcFormat = "p1363") -> str:
    """Podpis Base64URL: RSA-PSS albo ECDSA (P1363 – rekomendowany, albo DER). `key` nie opuszcza wywołującego."""
    _, sig = signing.sign(key, signing_string.encode("utf-8"), ec_format)
    return b64url(sig)


def build_url(params: Kod2Params, signature_b64url: str) -> str:
    return f"https://{params.signing_string()}/{signature_b64url}"


@dataclass(frozen=True)
class Kod2Link:
    host: str
    context_type: str
    context_value: str
    seller_nip: str
    serial_hex16: str
    invoice_hash_b64url: str
    signature_b64url: str

    @property
    def signed_text(self) -> str:
        return "/".join(
            [
                self.host,
                "certificate",
                self.context_type,
                self.context_value,
                self.seller_nip,
                self.serial_hex16,
                self.invoice_hash_b64url,
            ]
        )


def parse_url(url: str) -> Kod2Link | None:
    """Rozbiera link KODU II na składniki; None, gdy struktura jest niezgodna ze specyfikacją."""
    if not url.startswith("https://"):
        return None
    parts = url.removeprefix("https://").rstrip("/").split("/")
    if len(parts) != 8 or parts[1] != "certificate" or parts[2] not in CONTEXT_TYPES:
        return None
    return Kod2Link(parts[0], parts[2], parts[3], parts[4], parts[5], parts[6], parts[7])


def is_official_url(url: str) -> bool:
    """Czy link prowadzi do oficjalnego hosta QR KSeF (tylko takie otwieramy w przeglądarce)."""
    link = parse_url(url)
    return link is not None and link.host in {b.removeprefix("https://") for b in QR_BASE.values()}


def signature_encoding(signature: bytes, public_key: Any) -> str:
    """„P1363” / „DER” (ECDSA) albo „RSA-PSS” – wg długości i struktury podpisu."""
    if signing.scheme_for_public_key(public_key) == signing.SCHEME_RSA_PSS:
        return "RSA-PSS"
    if len(signature) == 64:
        return "P1363"
    return "DER" if signature[:1] == b"\x30" else "nieznany"


@dataclass
class Kod2Verification:
    code: str  # KOD2_SIGNATURE_VALID | KOD2_SIGNATURE_INVALID | KOD2_MALFORMED | KOD2_*_MISMATCH | UNSUPPORTED_ALGORITHM
    message: str
    encoding: str | None = None

    @property
    def valid(self) -> bool:
        return self.code == "KOD2_SIGNATURE_VALID"


def verify_url(
    url: str,
    public_key: Any,
    expected_serial_hex16: str | None = None,
    *,
    expected_context: tuple[str, str] | None = None,
    expected_seller_nip: str | None = None,
    expected_invoice_hash: str | None = None,
) -> Kod2Verification:
    """Lokalna weryfikacja podpisu KODU II kluczem publicznym z certyfikatu + zgodność składników linku.

    ECDSA: akceptowane są oba kodowania z dokumentacji MF (IEEE P1363 R||S oraz ASN.1 DER)."""
    link = parse_url(url)
    if link is None:
        return Kod2Verification(
            "KOD2_MALFORMED",
            "Nieprawidłowa struktura linku KODU II (https://host/certificate/<typ>/<kontekst>/<NIP>/<serial>/<hash>/<podpis>).",
        )
    try:
        sig = b64url_decode(link.signature_b64url)
    except ValueError:
        return Kod2Verification("KOD2_MALFORMED", "Podpis nie jest poprawnym Base64URL.")
    checks = (
        (expected_serial_hex16, link.serial_hex16, "KOD2_SERIAL_MISMATCH", "numer seryjny certyfikatu"),
        (expected_seller_nip, link.seller_nip, "KOD2_SELLER_MISMATCH", "NIP sprzedawcy"),
        (expected_invoice_hash, link.invoice_hash_b64url, "KOD2_HASH_MISMATCH", "skrót SHA-256 faktury"),
    )
    for expected, actual, code, label in checks:
        if expected is not None and expected != actual:
            return Kod2Verification(code, f"{label.capitalize()} w linku różni się od oczekiwanego.")
    if expected_context is not None and expected_context != (link.context_type, link.context_value):
        return Kod2Verification(
            "KOD2_CONTEXT_MISMATCH", "Kontekst (typ/wartość) w linku różni się od oczekiwanego."
        )
    data = link.signed_text.encode("utf-8")
    try:
        enc = signature_encoding(sig, public_key)
        if enc in ("RSA-PSS", "P1363"):
            ok = signing.verify(public_key, data, sig, "p1363")
        elif enc == "DER":
            ok = signing.verify(public_key, data, sig, "der")
        else:
            return Kod2Verification(
                "KOD2_MALFORMED", "Nierozpoznane kodowanie podpisu ECDSA (oczekiwano P1363 lub DER)."
            )
    except signing.UnsupportedKeyError as exc:
        return Kod2Verification("UNSUPPORTED_ALGORITHM", f"Nieobsługiwany algorytm: {exc}")
    except ValueError:
        return Kod2Verification("KOD2_SIGNATURE_INVALID", "Podpis KODU II ma niepoprawną strukturę.", enc)
    if ok:
        return Kod2Verification(
            "KOD2_SIGNATURE_VALID",
            f"Podpis KODU II ({enc}) poprawnie zweryfikowany kluczem publicznym z certyfikatu.",
            enc,
        )
    return Kod2Verification(
        "KOD2_SIGNATURE_INVALID", "Podpis KODU II NIE zgadza się z danymi linku i kluczem z certyfikatu.", enc
    )
