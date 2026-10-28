"""Odczyt klucza prywatnego i wyprowadzenie z niego klucza publicznego (SubjectPublicKeyInfo DER).

Klucz prywatny nigdy nie opuszcza tego modułu: zwracany jest wyłącznie publiczny SPKI DER
oraz wyniki kontroli. Hasło nie jest przechowywane ani umieszczane w komunikatach.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_private_key,
    load_pem_private_key,
)

from . import signing
from .certificate_loader import MAX_FILE_BYTES
from .models import Check, CheckStatus, FileError, Finding

# Zwraca hasło albo None (brak/rezygnacja). retry=True: poprzednie hasło było błędne.
PasswordProvider = Callable[[Path, bool], str | None]

_PEM_LABEL = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----")
_SUPPORTED_LABELS = {b"PRIVATE KEY", b"ENCRYPTED PRIVATE KEY", b"RSA PRIVATE KEY", b"EC PRIVATE KEY"}
MAX_PASSWORD_ATTEMPTS = 3


@dataclass
class SignatureEvidence:
    """Dowód aktywnego testu podpisu: losowe dane testowe podpisane kluczem prywatnym (klucza tu nie ma)."""

    challenge: bytes | None = None
    signature: bytes | None = None
    scheme: str | None = None
    error_code: str | None = None  # np. UNSUPPORTED_ALGORITHM
    error_message: str | None = None


@dataclass
class KeyOutcome:
    """Wynik odczytu klucza. `spki` jest ustawione tylko po udanym odszyfrowaniu."""

    decrypt: Check
    spki: bytes | None = None
    runtime_error: FileError | None = None  # np. brak pliku → exit 2 / komunikat
    password_provided: bool = False
    signature: SignatureEvidence | None = None
    action_result: Any = (
        None  # wynik `action(key)` (np. podpis XAdES / KODU II); sam klucz nigdy nie opuszcza modułu
    )
    action_error: str | None = None


def _spki_of_private(key: object) -> bytes | None:
    pub = getattr(key, "public_key", None)
    if pub is None:
        return None
    return pub().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def spki_of_certificate(cert: x509.Certificate) -> bytes:
    return cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


_DECRYPT_FAIL = {"KEY_WRONG_PASSWORD", "KEY_CORRUPT"}


def _fail(code: str, msg: str) -> KeyOutcome:
    shown = "KEY_DECRYPTION_FAILED" if code in _DECRYPT_FAIL else code
    return KeyOutcome(
        Check("key_decrypt", CheckStatus.FAIL, msg, [Finding(code, CheckStatus.FAIL, msg)], code=shown)
    )


def _unknown(code: str, msg: str) -> KeyOutcome:
    return KeyOutcome(
        Check("key_decrypt", CheckStatus.UNKNOWN, msg, [Finding(code, CheckStatus.UNKNOWN, msg)])
    )


def _try_load(data: bytes, is_pem: bool, password: bytes | None):
    return (load_pem_private_key if is_pem else load_der_private_key)(data, password)


def read_private_key(
    path: Path,
    provider: PasswordProvider | None,
    action: Callable[[Any], Any] | None = None,
    require_encrypted: bool = True,
) -> KeyOutcome:
    """Wczytuje klucz (PEM/DER, PKCS#8 / tradycyjny), pyta o hasło tylko gdy klucz jest zaszyfrowany."""
    try:
        if not path.exists():
            return KeyOutcome(
                Check("key_decrypt", CheckStatus.NOT_CHECKED, "Brak pliku klucza prywatnego."),
                runtime_error=FileError(
                    "KEY_NOT_FOUND", f"Plik klucza prywatnego nie istnieje: {path}", "runtime"
                ),
            )
        if not path.is_file():
            return KeyOutcome(
                Check("key_decrypt", CheckStatus.NOT_CHECKED, "Ścieżka klucza nie jest plikiem."),
                runtime_error=FileError("KEY_NOT_A_FILE", f"To nie jest zwykły plik: {path}", "runtime"),
            )
        if path.stat().st_size > MAX_FILE_BYTES:
            return KeyOutcome(
                Check("key_decrypt", CheckStatus.NOT_CHECKED, "Plik klucza jest zbyt duży."),
                runtime_error=FileError("KEY_TOO_LARGE", "Plik klucza przekracza limit rozmiaru.", "runtime"),
            )
        data = path.read_bytes()
    except OSError as exc:
        return KeyOutcome(
            Check("key_decrypt", CheckStatus.NOT_CHECKED, "Nie można odczytać pliku klucza."),
            runtime_error=FileError(
                "KEY_READ_ERROR", f"Nie można odczytać klucza: {exc.strerror or exc}", "runtime"
            ),
        )

    is_pem = b"-----BEGIN" in data
    if is_pem:
        labels = set(_PEM_LABEL.findall(data))
        if not labels & _SUPPORTED_LABELS:
            return _fail(
                "KEY_UNSUPPORTED_FORMAT",
                "Nieobsługiwany format klucza (obsługiwane: PKCS#8, RSA/EC PEM lub DER; "
                "np. OpenSSH, PKCS#12 czy certyfikat nie są kluczem prywatnym PEM).",
            )
    elif not data[:1] == b"\x30":
        return _fail("KEY_UNSUPPORTED_FORMAT", "Nieobsługiwany format klucza (oczekiwano PEM albo DER).")

    password: str | None = None
    password_given = False
    attempts = 0
    while True:
        try:
            key = _try_load(data, is_pem, password.encode("utf-8") if password is not None else None)
        except TypeError:
            if password is None:  # zaszyfrowany, a hasła brak
                password = provider(path, False) if provider else None
                password_given = bool(password)
                if password is None or password == "":
                    return _unknown(
                        "KEY_PASSWORD_MISSING", "Klucz jest zaszyfrowany – podaj hasło do klucza."
                    )
                continue
            # hasło podano, ale klucz nie jest zaszyfrowany
            key = _try_load(data, is_pem, None)
            return _finish(key, True, require_encrypted, action, password_given)
        except ValueError:
            if password is None:
                return _fail("KEY_CORRUPT", "Plik klucza jest uszkodzony lub nie zawiera klucza prywatnego.")
            attempts += 1
            retry_pw = provider(path, True) if provider and attempts < MAX_PASSWORD_ATTEMPTS else None
            if retry_pw is None or retry_pw == "":
                return _fail(
                    "KEY_WRONG_PASSWORD",
                    "Nie udało się odszyfrować klucza: błędne hasło lub uszkodzony plik klucza.",
                )
            password = retry_pw
            continue
        except Exception:  # np. UnsupportedAlgorithm (egzotyczne szyfrowanie)
            return _fail("KEY_UNSUPPORTED_FORMAT", "Klucz używa nieobsługiwanego algorytmu lub szyfrowania.")
        else:
            return _finish(key, password is None, require_encrypted, action, password_given)


def _active_signature_test(key: object) -> SignatureEvidence:
    """Podpisuje losowe dane testowe (CSPRNG). To NIE jest podpis XAdES ani podpis KODU II."""
    challenge = secrets.token_bytes(32)
    try:
        scheme, sig = signing.sign(key, challenge, "der")
    except signing.UnsupportedKeyError as exc:
        return SignatureEvidence(error_code="UNSUPPORTED_ALGORITHM", error_message=str(exc))
    return SignatureEvidence(challenge, sig, scheme)


def _finish(
    key: object,
    unencrypted: bool,
    require_encrypted: bool,
    action: Callable[[Any], Any] | None,
    password_given: bool,
) -> KeyOutcome:
    if isinstance(key, rsa.RSAPrivateKey):
        kind = f"RSA {key.key_size}"
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        kind = f"EC {key.curve.name}"
    elif isinstance(key, dsa.DSAPrivateKey):
        kind = "DSA"
    else:
        kind = type(key).__name__
    spki = _spki_of_private(key)
    if spki is None:
        return _fail("KEY_UNSUPPORTED_FORMAT", "Nie można wyprowadzić klucza publicznego z tego klucza.")
    findings = [Finding("KEY_DECRYPTED", CheckStatus.PASS, f"Klucz prywatny odczytany ({kind}).")]
    status = CheckStatus.PASS
    code = "KEY_DECRYPTED"
    summary = f"Klucz prywatny odszyfrowany i poprawny ({kind})."
    if unencrypted:
        # Problem bezpieczeństwa: klucz leży na dysku bez ochrony hasłem.
        status = CheckStatus.FAIL if require_encrypted else CheckStatus.WARNING
        code = "KEY_UNENCRYPTED"
        summary = f"PROBLEM BEZPIECZEŃSTWA: klucz prywatny ({kind}) nie jest zaszyfrowany hasłem" + (
            " – wymagany jest klucz zabezpieczony hasłem." if require_encrypted else " (dozwolone opcją)."
        )
        findings.append(Finding("KEY_UNENCRYPTED", status, summary))
    evidence = _active_signature_test(key)
    out = KeyOutcome(
        Check("key_decrypt", status, summary, findings, code=code),
        spki=spki,
        password_provided=password_given,
        signature=evidence,
    )
    if action is not None:
        try:
            out.action_result = action(key)
        except (
            Exception
        ) as exc:  # wynik operacji zależnej (podpis XAdES/KODU II); komunikat bez danych wrażliwych
            out.action_error = type(exc).__name__ + (
                f": {exc}" if not isinstance(exc, ValueError) else f": {exc}"
            )
    del key  # referencja do klucza zwolniona; odszyfrowany klucz nigdy nie był zapisany na dysku
    return out


def match_check(cert_spki: bytes, key_spki: bytes | None) -> Check:
    if key_spki is None:
        return Check(
            "key_match",
            CheckStatus.NOT_CHECKED,
            "Klucz prywatny nie został odczytany – zgodność niesprawdzona.",
        )
    if cert_spki == key_spki:
        return Check(
            "key_match",
            CheckStatus.PASS,
            "Klucz publiczny z klucza prywatnego jest identyczny z kluczem w certyfikacie.",
            code="KEY_PAIR_MATCH",
        )
    msg = "Klucz prywatny NIE pasuje do certyfikatu (różne klucze publiczne SubjectPublicKeyInfo)."
    return Check(
        "key_match",
        CheckStatus.FAIL,
        msg,
        [Finding("KEY_MISMATCH", CheckStatus.FAIL, msg)],
        code="KEY_CERT_MISMATCH",
    )


def signature_check(
    cert: x509.Certificate,
    key_spki: bytes | None,
    evidence: SignatureEvidence | None,
    decrypt: Check | None,
) -> Check:
    """Aktywny test podpisu: podpis losowych danych kluczem prywatnym zweryfikowany kluczem z certyfikatu.

    Kody wyniku: SIGNATURE_VALID, SIGNATURE_INVALID, KEY_DECRYPTION_FAILED, KEY_CERT_MISMATCH, UNSUPPORTED_ALGORITHM.
    """

    def result(status: CheckStatus, code: str, msg: str) -> Check:
        return Check("signature_test", status, msg, [Finding(code, status, msg)], code=code)

    if evidence is None:
        if decrypt is not None and decrypt.code == "KEY_DECRYPTION_FAILED":
            return result(
                CheckStatus.FAIL,
                "KEY_DECRYPTION_FAILED",
                "Test podpisu niemożliwy: klucz nie został odszyfrowany.",
            )
        return Check(
            "signature_test",
            CheckStatus.NOT_CHECKED,
            "Test podpisu nie został wykonany (brak odszyfrowanego klucza).",
        )
    if evidence.error_code == "UNSUPPORTED_ALGORITHM":
        return result(
            CheckStatus.FAIL,
            "UNSUPPORTED_ALGORITHM",
            f"Nieobsługiwany algorytm: {evidence.error_message}. KSeF dopuszcza RSA 2048 lub EC P-256.",
        )
    if key_spki != spki_of_certificate(cert):
        return result(
            CheckStatus.FAIL,
            "KEY_CERT_MISMATCH",
            "Test podpisu pominięty: klucz prywatny nie pasuje do certyfikatu.",
        )
    if evidence.challenge is None or evidence.signature is None:
        return result(CheckStatus.FAIL, "SIGNATURE_INVALID", "Brak danych testu podpisu.")
    try:
        ok = signing.verify(cert.public_key(), evidence.challenge, evidence.signature, "der")
    except signing.UnsupportedKeyError as exc:
        return result(
            CheckStatus.FAIL,
            "UNSUPPORTED_ALGORITHM",
            f"Nieobsługiwany algorytm klucza w certyfikacie: {exc}.",
        )
    if ok:
        return result(
            CheckStatus.PASS,
            "SIGNATURE_VALID",
            f"Podpis losowych danych testowych ({evidence.scheme}) poprawnie zweryfikowany kluczem z certyfikatu "
            "(to nie jest podpis XAdES ani KODU II).",
        )
    return result(
        CheckStatus.FAIL,
        "SIGNATURE_INVALID",
        "Podpis testowy nie zgadza się z kluczem publicznym z certyfikatu.",
    )
