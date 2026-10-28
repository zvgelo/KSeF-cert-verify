"""KOD II – podpis linku weryfikacyjnego certyfikatu Offline (oficjalna specyfikacja: `kody-qr.md`, §2).

Format (nie wymyślamy własnego):
  https://<host QR>/certificate/<ContextIdentifierType>/<ContextIdentifierValue>/<SellerNip>/<SerialCertyfikatu>/
  <SHA-256 faktury, Base64URL>/<podpis, Base64URL>
Podpisywana jest ścieżka URL BEZ prefiksu `https://` i BEZ końcowego `/` (i bez samego podpisu).
Algorytmy: RSA → RSASSA-PSS (SHA-256, MGF1 SHA-256, sól 32 B); EC P-256 → ECDSA SHA-256, podpis P1363 (R||S).

Używamy wyłącznie danych SYNTETYCZNYCH (nie prawdziwej faktury). Link nie jest nigdzie wysyłany ani otwierany.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from typing import Any

from . import signing

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


def sign_signing_string(key: Any, signing_string: str) -> str:
    """Podpis Base64URL (RSA-PSS albo ECDSA P1363). `key` nie opuszcza wywołującego modułu."""
    _, sig = signing.sign(key, signing_string.encode("utf-8"), "p1363")
    return b64url(sig)


def build_url(params: Kod2Params, signature_b64url: str) -> str:
    return f"https://{params.signing_string()}/{signature_b64url}"


@dataclass
class Kod2Verification:
    code: str  # KOD2_SIGNATURE_VALID | KOD2_SIGNATURE_INVALID | KOD2_MALFORMED | KOD2_SERIAL_MISMATCH | UNSUPPORTED_ALGORITHM
    message: str

    @property
    def valid(self) -> bool:
        return self.code == "KOD2_SIGNATURE_VALID"


def verify_url(url: str, public_key: Any, expected_serial_hex16: str | None = None) -> Kod2Verification:
    """Lokalna weryfikacja podpisu KODU II kluczem publicznym z certyfikatu."""
    if not url.startswith("https://"):
        return Kod2Verification("KOD2_MALFORMED", "Link KODU II musi zaczynać się od https://")
    path = url.removeprefix("https://").rstrip("/")
    parts = path.split("/")
    # host/certificate/<type>/<ctx>/<seller>/<serial>/<hash>/<signature>
    if len(parts) != 8 or parts[1] != "certificate":
        return Kod2Verification(
            "KOD2_MALFORMED", "Nieprawidłowa struktura linku KODU II (oczekiwano 8 segmentów ścieżki)."
        )
    signed, sig_text = "/".join(parts[:-1]), parts[-1]
    if parts[2] not in CONTEXT_TYPES:
        return Kod2Verification("KOD2_MALFORMED", f"Nieznany typ identyfikatora kontekstu: {parts[2]}")
    try:
        sig = b64url_decode(sig_text)
    except ValueError:
        return Kod2Verification("KOD2_MALFORMED", "Podpis nie jest poprawnym Base64URL.")
    if expected_serial_hex16 is not None and parts[5] != expected_serial_hex16:
        return Kod2Verification(
            "KOD2_SERIAL_MISMATCH", "Numer seryjny w linku różni się od numeru seryjnego certyfikatu."
        )
    try:
        ok = signing.verify(public_key, signed.encode("utf-8"), sig, "p1363")
    except signing.UnsupportedKeyError as exc:
        return Kod2Verification("UNSUPPORTED_ALGORITHM", f"Nieobsługiwany algorytm: {exc}")
    if ok:
        return Kod2Verification(
            "KOD2_SIGNATURE_VALID", "Podpis KODU II poprawnie zweryfikowany kluczem publicznym z certyfikatu."
        )
    return Kod2Verification(
        "KOD2_SIGNATURE_INVALID", "Podpis KODU II NIE zgadza się z danymi linku i kluczem z certyfikatu."
    )
