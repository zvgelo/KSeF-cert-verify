"""Wczytywanie certyfikatów z PEM / DER / PKCS#12.

Format rozpoznawany jest po zawartości, nie po rozszerzeniu. Klucze prywatne
z PKCS#12 są odrzucane natychmiast po odczycie – nigdy nie są zapisywane ani
zwracane.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12

MAX_FILE_BYTES = 1024 * 1024  # 1 MiB – certyfikaty są małe; chroni przed nadużyciami

SUPPORTED_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".p12", ".pfx"}

# (kody runtime → exit 2; pozostałe → zawartość pliku błędna)
RUNTIME_CODES = {
    "FILE_NOT_FOUND",
    "NOT_A_FILE",
    "READ_ERROR",
    "TOO_LARGE",
    "PASSWORD_REQUIRED",
    "WRONG_PASSWORD",
}


class LoaderError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    @property
    def kind(self) -> str:
        return "runtime" if self.code in RUNTIME_CODES else "content"


class PasswordRequired(LoaderError):
    def __init__(self) -> None:
        super().__init__("PASSWORD_REQUIRED", "Plik PKCS#12 jest chroniony hasłem.")


class WrongPassword(LoaderError):
    def __init__(self) -> None:
        super().__init__(
            "WRONG_PASSWORD",
            "Błędne hasło PKCS#12 (lub uszkodzony plik – nie da się tego rozróżnić).",
        )


@dataclass
class LoadedFile:
    certificates: list[x509.Certificate]
    file_format: str  # PEM | DER | PKCS12
    notes: list[str] = field(default_factory=list)
    key_spki: bytes | None = None  # publiczny SPKI DER z klucza w PKCS#12 (klucz prywatny jest odrzucany)
    signature: Any = None  # SignatureEvidence z aktywnego testu podpisu kluczem z PKCS#12
    password_used: bool = False


def _looks_like_pfx(data: bytes) -> bool:
    """PFX: SEQUENCE { INTEGER 3, SEQUENCE { OID pkcs7-data|pkcs7-encrypted, ... } }."""
    if len(data) < 10 or data[0] != 0x30:
        return False
    i = 1
    first = data[i]
    i += 1 + (first & 0x7F if first & 0x80 else 0)
    return data[i : i + 3] == b"\x02\x01\x03"


def _load_pkcs12(data: bytes, password: str | None) -> LoadedFile:
    candidates: list[bytes | None]
    if password is None:
        candidates = [None, b""]
    else:
        candidates = [password.encode("utf-8")]
    last_error: Exception | None = None
    for pw in candidates:
        try:
            p12 = pkcs12.load_pkcs12(data, pw)
        except ValueError as exc:
            last_error = exc
            continue
        except Exception as exc:  # np. UnsupportedAlgorithm dla egzotycznego szyfrowania
            raise LoaderError("INVALID_PKCS12", f"Nie można odczytać PKCS#12: {exc}") from exc
        certs: list[x509.Certificate] = []
        if p12.cert is not None:
            certs.append(p12.cert.certificate)
        certs.extend(c.certificate for c in p12.additional_certs)
        notes = []
        key_spki = None
        evidence = None
        if p12.key is not None:
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

            key_spki = p12.key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            from .private_key import _active_signature_test  # import leniwy (unik cyklu)

            evidence = _active_signature_test(p12.key)
            notes.append(
                "Plik PKCS#12 zawiera klucz prywatny – użyto go tylko do sprawdzenia pary; nie jest zapisywany."
            )
        del p12  # klucz prywatny nie jest przechowywany
        if not certs:
            raise LoaderError("NO_CERTIFICATE", "Plik PKCS#12 nie zawiera certyfikatów.")
        return LoadedFile(certs, "PKCS12", notes, key_spki, evidence, pw not in (None, b""))
    if password is None:
        raise PasswordRequired() from last_error
    raise WrongPassword() from last_error


def load_bytes(data: bytes, password: str | None = None) -> LoadedFile:
    if b"-----BEGIN" in data:
        notes = []
        if b"PRIVATE KEY-----" in data:
            notes.append("Plik zawiera klucz prywatny – został zignorowany (nie jest odczytywany).")
        try:
            certs = x509.load_pem_x509_certificates(data)
        except ValueError as exc:
            raise LoaderError(
                "INVALID_PEM", f"Nie znaleziono poprawnego certyfikatu PEM (uszkodzone dane?): {exc}"
            ) from exc
        if not certs:
            raise LoaderError("NO_CERTIFICATE", "Plik PEM nie zawiera certyfikatów.")
        return LoadedFile(certs, "PEM", notes)

    if _looks_like_pfx(data):
        return _load_pkcs12(data, password)

    try:
        return LoadedFile([x509.load_der_x509_certificate(data)], "DER")
    except ValueError as exc:
        if not data or data[0] != 0x30:
            raise LoaderError(
                "NO_CERTIFICATE", "Plik nie zawiera certyfikatu X.509 (nierozpoznany format)."
            ) from exc
        raise LoaderError("INVALID_DER", f"Uszkodzona struktura DER/ASN.1 certyfikatu: {exc}") from exc


def load_file(path: str | Path, password: str | None = None) -> LoadedFile:
    p = Path(path)
    try:
        if not p.exists():
            raise LoaderError("FILE_NOT_FOUND", f"Plik nie istnieje: {p}")
        if not p.is_file():
            raise LoaderError("NOT_A_FILE", f"To nie jest zwykły plik: {p}")
        size = p.stat().st_size
        if size > MAX_FILE_BYTES:
            raise LoaderError("TOO_LARGE", f"Plik jest zbyt duży ({size} B, limit {MAX_FILE_BYTES} B).")
        with p.open("rb") as fh:
            data = fh.read(MAX_FILE_BYTES + 1)
    except LoaderError:
        raise
    except OSError as exc:
        raise LoaderError("READ_ERROR", f"Nie można odczytać pliku: {exc.strerror or exc}") from exc
    if len(data) > MAX_FILE_BYTES:
        raise LoaderError("TOO_LARGE", f"Plik jest zbyt duży (limit {MAX_FILE_BYTES} B).")
    return load_bytes(data, password)
