"""Warstwa usługowa używana identycznie przez CLI i GUI + serializacja JSON."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography import x509

from .certificate_loader import (
    SUPPORTED_EXTENSIONS,
    LoaderError,
    PasswordRequired,
    WrongPassword,
    load_file,
)
from .certificate_validator import OnlineLookup, VerifyContext, verify_certificate
from .models import SCHEMA_VERSION, CertType, Check, CheckStatus, FileError, FileReport, Verdict
from .private_key import read_private_key, spki_of_certificate
from .trust_store import TrustStore

# Zwraca hasło (str) albo None, gdy użytkownik zrezygnował.
PasswordProvider = Callable[[Path, bool], str | None]


@dataclass
class VerifyOptions:
    trust: TrustStore = field(default_factory=TrustStore)
    expected_type: CertType | None = None
    online: OnlineLookup | None = None
    online_environment: str | None = None
    now: datetime | None = None
    online_requested: bool = False
    online_note: str | None = None
    online_fetch_certificate: bool = False
    require_encrypted_key: bool = True  # klucz niezaszyfrowany = problem bezpieczeństwa (FAIL)


def collect_files(paths: list[Path], recursive: bool = False) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        if p.is_dir():
            it = p.rglob("*") if recursive else p.iterdir()
            out.extend(sorted(f for f in it if f.is_file() and f.suffix.lower() in SUPPORTED_EXTENSIONS))
        else:
            out.append(p)
    return out


def verify_file(
    path: Path,
    options: VerifyOptions,
    password_provider: PasswordProvider | None = None,
    password: str | None = None,
    key_path: Path | None = None,
) -> FileReport:
    now = options.now or datetime.now(UTC)
    loaded = None
    retry = False
    while True:
        try:
            loaded = load_file(path, password)
            break
        except (PasswordRequired, WrongPassword) as exc:
            retry = isinstance(exc, WrongPassword)
            pw = password_provider(path, retry) if password_provider else None
            if pw is None:
                return FileReport(str(path), "PKCS12", error=FileError(exc.code, exc.message, exc.kind))
            password = pw
        except LoaderError as exc:
            return FileReport(str(path), None, error=FileError(exc.code, exc.message, exc.kind))
    certs = loaded.certificates
    non_ca = [i for i, c in enumerate(certs) if not _is_ca(c)]
    leaf_idx = non_ca or list(range(len(certs)))
    report = FileReport(str(path), loaded.file_format, notes=list(loaded.notes))

    key_decrypt: Check | None = None
    key_spki: bytes | None = None
    signature = None
    password_state = "NOT_PROVIDED"
    if key_path is not None:
        outcome = read_private_key(
            key_path, password_provider, require_encrypted=options.require_encrypted_key
        )
        if outcome.runtime_error is not None:
            return FileReport(
                str(path), loaded.file_format, notes=list(loaded.notes), error=outcome.runtime_error
            )
        key_decrypt, key_spki, signature = outcome.decrypt, outcome.spki, outcome.signature
        password_state = (
            "PROVIDED"
            if outcome.password_provided
            else "NOT_REQUIRED"
            if outcome.decrypt.code == "KEY_UNENCRYPTED"
            else "NOT_PROVIDED"
        )
    elif loaded.key_spki is not None:
        key_spki = loaded.key_spki
        signature = loaded.signature
        password_state = "PROVIDED" if loaded.password_used else "NOT_REQUIRED"
        key_decrypt = Check(
            "key_decrypt", CheckStatus.PASS, "Klucz prywatny z pliku PKCS#12 odczytany (hasło poprawne)."
        )
    report.inputs = {
        "certificate": str(path),
        "private_key": str(key_path)
        if key_path is not None
        else ("(PKCS#12)" if loaded.key_spki is not None else None),
        "password": password_state,
    }
    if key_spki is None and key_decrypt is None:
        inputs_check = Check(
            "inputs",
            CheckStatus.NOT_CHECKED,
            "Nie podano klucza prywatnego i hasła – pełna weryfikacja niemożliwa.",
        )
    elif key_decrypt is not None and key_decrypt.status is CheckStatus.UNKNOWN:
        inputs_check = Check(
            "inputs",
            CheckStatus.UNKNOWN,
            "Brak hasła do zaszyfrowanego klucza prywatnego.",
            code="PASSWORD_MISSING",
        )
    else:
        inputs_check = Check(
            "inputs",
            CheckStatus.PASS,
            "Dostarczono certyfikat, klucz prywatny i hasło (lub klucz nie wymaga hasła).",
        )
    if key_spki is not None:
        matching = [i for i in leaf_idx if spki_of_certificate(certs[i]) == key_spki]
        leaf_idx = matching or leaf_idx
    for i in leaf_idx:
        others = [c for j, c in enumerate(certs) if j != i]
        ctx = VerifyContext(
            now=now,
            trust=options.trust,
            expected_type=options.expected_type,
            online=options.online,
            online_requested=options.online_requested,
            online_note=options.online_note,
            online_fetch_certificate=options.online_fetch_certificate,
            candidates=others,
            key_decrypt=key_decrypt,
            key_spki=key_spki,
            signature=signature,
            inputs=inputs_check,
        )
        report.certificates.append(verify_certificate(certs[i], ctx, index=i, role="leaf"))
    return report


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def verify_paths(
    paths: list[Path],
    options: VerifyOptions,
    recursive: bool = False,
    password_provider: PasswordProvider | None = None,
) -> list[FileReport]:
    return [verify_file(f, options, password_provider) for f in collect_files(paths, recursive)]


def exit_code(reports: list[FileReport]) -> int:
    """0 poprawny · 1 niepoprawny · 2 błąd wykonania · 3 niejednoznaczny (priorytet: 2 > 1 > 3 > 0)."""
    if not reports:
        return 2
    verdicts = [r.verdict for r in reports]
    if any(v is None for v in verdicts):
        return 2
    if Verdict.INVALID in verdicts:
        return 1
    if Verdict.INDETERMINATE in verdicts:
        return 3
    return 0


def build_json(
    reports: list[FileReport],
    options: VerifyOptions,
    tool_version: str,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Stabilny, wersjonowany dokument JSON (`schema_version`)."""
    gen = generated_at or options.now or datetime.now(UTC)
    code = exit_code(reports)
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "ksef-cert-verify", "version": tool_version},
        "generated_at": gen.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope": {
            "offline": True,
            "online_requested": options.online is not None,
            "online_environment": options.online_environment,
            "trust_anchors_configured": len(options.trust),
            "expected_type": options.expected_type.value if options.expected_type else None,
        },
        "files": [r.to_dict() for r in reports],
        "exit_code": code,
        "disclaimer": (
            "Wynik lokalny nie oznacza aktywnego statusu certyfikatu w KSeF ani potwierdzenia zgodności "
            "przez Ministerstwo Finansów; ocenia wyłącznie udokumentowane kryteria."
        ),
    }


def dumps(doc: dict[str, Any]) -> str:
    return json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=False)
