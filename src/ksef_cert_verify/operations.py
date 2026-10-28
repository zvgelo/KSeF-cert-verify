"""Operacje wyższego poziomu wspólne dla CLI i GUI: sesja online (automatyczne uwierzytelnienie XAdES albo
istniejący JWT), weryfikacja pary z opcjonalnym statusem online oraz test KODU II.

Zasady: hasło jest przechowywane tylko w pamięci na czas jednego polecenia (`CachedPassword`), tokeny nigdy nie trafiają
do wyników ani logów, PROD wymaga jawnego potwierdzenia (`allow_prod`), a wyniki online nie wpływają na wyniki lokalne.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from cryptography import x509

from .core import kod2
from .core.certificate_classifier import classify
from .core.certificate_loader import LoaderError, load_file
from .core.certificate_parser import parse_certificate, serial_hex
from .core.models import CertType, FileReport
from .core.private_key import PasswordProvider, read_private_key, spki_of_certificate
from .core.report import VerifyOptions, verify_file
from .ksef_api.auth_flow import AuthApi, AuthResult, AuthStep, SigningError, run_xades_auth
from .ksef_api.jwt_utils import describe, inspect_jwt
from .ksef_api.ksef_client import ENVIRONMENTS, KsefApiClient
from .ksef_api.xades import build_auth_token_request, sign_xades


class CachedPassword:
    """Opakowanie dostawcy hasła: pamięta hasło tylko w pamięci, by drugi odczyt klucza nie pytał ponownie."""

    def __init__(self, provider: PasswordProvider | None) -> None:
        self._provider = provider
        self._cache: str | None = None

    def __call__(self, path: Path, retry: bool) -> str | None:
        if self._cache is not None and not retry:
            return self._cache
        pw = self._provider(path, retry) if self._provider else None
        self._cache = pw or None
        return pw

    def clear(self) -> None:
        self._cache = None


@dataclass
class OnlineSetup:
    environment: str  # TEST | DEMO | PROD
    mode: str = "auto"  # auto = uwierzytelnienie XAdES certyfikatem | jwt = istniejący accessToken
    jwt: str | None = field(default=None, repr=False)
    allow_prod: bool = False  # jawne potwierdzenie użytkownika wymagane dla PROD
    context_type: str = "Nip"
    context_value: str | None = None
    subject_type: str = "certificateSubject"
    verify_certificate_chain: bool | None = None
    poll_timeout: float = 60.0
    poll_interval: float = 2.0
    timeout: float = 15.0
    transport: httpx.BaseTransport | None = None  # tylko testy (MockTransport)


@dataclass
class OnlineSession:
    client: KsefApiClient | None
    auth: AuthResult
    note: str | None = None  # dlaczego nie ma klienta (do komunikatu „status nieustalony")


def _leaf_certs(cert_path: Path) -> list[x509.Certificate]:
    loaded = load_file(cert_path)
    certs = loaded.certificates
    non_ca = []
    for c in certs:
        try:
            if not c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                non_ca.append(c)
        except x509.ExtensionNotFound:
            non_ca.append(c)
    return non_ca or certs


def _result(code: str, msg: str, steps: list[AuthStep] | None = None, env: str | None = None) -> AuthResult:
    return AuthResult(code=code, message=msg, environment=env, steps=steps or [])


def establish_online(
    cert_path: Path,
    key_path: Path | None,
    provider: PasswordProvider | None,
    setup: OnlineSetup,
    require_encrypted_key: bool = True,
) -> OnlineSession:
    """Zwraca klienta API (z accessToken) albo powód, dla którego go nie ma. Nie rzuca."""
    env = setup.environment.upper()
    if env not in ENVIRONMENTS:
        return OnlineSession(
            None,
            _result("AUTH_BAD_ENVIRONMENT", f"Nieznane środowisko: {setup.environment}"),
            "Nieznane środowisko.",
        )
    if env == "PROD" and not setup.allow_prod:
        msg = "PROD wymaga świadomego potwierdzenia użytkownika – operacja online nie została wykonana."
        return OnlineSession(None, _result("AUTH_PROD_NOT_CONFIRMED", msg, env=env), msg)

    if setup.mode == "jwt":
        info = inspect_jwt(setup.jwt or "")
        if not info.usable:
            code = "JWT_EXPIRED" if info.structure_ok and info.expired else "JWT_INVALID"
            msg = describe(info)
            return OnlineSession(None, _result(code, msg, env=env), msg)
        token = (setup.jwt or "").strip().removeprefix("Bearer ").strip()
        client = KsefApiClient(env, token, timeout=setup.timeout, transport=setup.transport)
        return OnlineSession(
            client,
            AuthResult(
                code="JWT_PROVIDED",
                message="Użyto istniejącego accessToken (JWT); autentyczność weryfikuje dopiero API.",
                environment=env,
                authentication="NOT_TESTED",
            ),
        )

    # --- automatyczne uwierzytelnienie XAdES ---
    if key_path is None:
        msg = "Uwierzytelnienie XAdES wymaga klucza prywatnego."
        return OnlineSession(None, _result("AUTH_KEY_REQUIRED", msg, env=env), msg)
    try:
        certs = _leaf_certs(cert_path)
    except LoaderError as exc:
        return OnlineSession(None, _result("AUTH_CERT_UNREADABLE", exc.message, env=env), exc.message)
    types = {classify(c)[0] for c in certs}
    if types != {CertType.AUTHENTICATION}:
        msg = (
            "Uwierzytelnienie XAdES jest dostępne tylko dla certyfikatu typu Authentication. Certyfikat Offline służy "
            "wyłącznie do podpisu KODU II – status online wymaga osobnego, uprawnionego uwierzytelnienia (istniejący JWT)."
        )
        return OnlineSession(None, _result("AUTH_NOT_APPLICABLE", msg, env=env), msg)
    cert = certs[0]
    cert_info, _ = parse_certificate(cert)
    ctx_value = setup.context_value or cert_info.subject_info.nip
    if not ctx_value:
        msg = "Brak identyfikatora kontekstu (NIP) – podaj kontekst uwierzytelnienia; w certyfikacie nie znaleziono NIP."
        return OnlineSession(None, _result("AUTH_CONTEXT_REQUIRED", msg, env=env), msg)

    def sign_request(xml: bytes) -> bytes:
        def action(key: Any) -> bytes:
            if spki_of_certificate(cert) != _spki_of_key(key):
                raise SigningError("klucz prywatny nie pasuje do certyfikatu")
            return sign_xades(xml, cert, key)

        out = read_private_key(key_path, provider, action=action, require_encrypted=require_encrypted_key)
        if out.runtime_error is not None:
            raise SigningError(out.runtime_error.message)
        if out.action_error:
            raise SigningError(out.action_error.split(": ", 1)[-1])
        if out.action_result is None:
            raise SigningError("klucz nie został odszyfrowany: " + out.decrypt.summary)
        return out.action_result

    api = AuthApi(env, timeout=setup.timeout, transport=setup.transport)
    try:
        result = run_xades_auth(
            api,
            sign_request,
            lambda ch: build_auth_token_request(ch, setup.context_type, ctx_value, setup.subject_type),
            context_label=f"{setup.context_type}:{ctx_value}",
            verify_certificate_chain=setup.verify_certificate_chain,
            poll_timeout=setup.poll_timeout,
            poll_interval=setup.poll_interval,
        )
    finally:
        api.close()
    if result.access_token:
        client = KsefApiClient(env, result.access_token, timeout=setup.timeout, transport=setup.transport)
        return OnlineSession(client, result)
    return OnlineSession(None, result, result.message)


def _spki_of_key(key: Any) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def verify_with_online(
    cert_path: Path,
    key_path: Path | None,
    options: VerifyOptions,
    provider: PasswordProvider | None,
    setup: OnlineSetup | None = None,
    query_status: bool = True,
) -> tuple[FileReport, OnlineSession | None]:
    """Pełna weryfikacja lokalna + (opcjonalnie) status online. Wyniki lokalne nie zależą od online."""
    cached = CachedPassword(provider)
    session: OnlineSession | None = None
    try:
        if setup is not None:
            session = establish_online(cert_path, key_path, cached, setup, options.require_encrypted_key)
            if query_status:
                options.online_requested = True
                options.online_note = session.note
                options.online = session.client
                options.online_environment = setup.environment.upper()
        report = verify_file(cert_path, options, cached, key_path=key_path)
        if session is not None:
            for c in report.certificates:
                c.operations["authentication"] = session.auth.to_dict()
        return report, session
    finally:
        cached.clear()
        if session is not None and session.client is not None:
            session.client.close()


# ---------------------------------------------------------------- KOD II (certyfikat Offline)
@dataclass
class Kod2Setup:
    environment: str = "TEST"
    context_type: str = "Nip"
    context_value: str | None = None
    seller_nip: str | None = None


def run_kod2_test(
    cert_path: Path,
    key_path: Path,
    options: VerifyOptions,
    provider: PasswordProvider | None,
    setup: Kod2Setup,
) -> FileReport:
    """Weryfikacja pary + test podpisu KODU II (dane syntetyczne; link nie jest nigdzie wysyłany)."""
    cached = CachedPassword(provider)
    try:
        report = verify_file(cert_path, options, cached, key_path=key_path)
        if report.error or not report.certificates:
            return report
        try:
            certs = _leaf_certs(cert_path)
        except LoaderError:
            return report
        cert = certs[0]
        rep = report.certificates[0]
        if rep.cert_type is not CertType.OFFLINE:
            rep.operations["kod2"] = {
                "code": "KOD2_NOT_APPLICABLE",
                "status": "NOT_APPLICABLE",
                "message": "KOD II wymaga certyfikatu typu Offline; certyfikat Authentication nie może być używany do jego generowania.",
            }
            return report
        env = setup.environment.upper()
        info, _ = parse_certificate(cert)
        nip = setup.context_value or info.subject_info.nip or "1111111111"
        try:
            params = kod2.Kod2Params(
                env, setup.context_type, nip, setup.seller_nip or nip, serial_hex(cert), kod2.invoice_hash()
            )
            params.validate()
        except ValueError as exc:
            rep.operations["kod2"] = {"code": "KOD2_BAD_PARAMS", "status": "FAIL", "message": str(exc)}
            return report

        def action(key: Any) -> str:
            if spki_of_certificate(cert) != _spki_of_key(key):
                raise SigningError("klucz prywatny nie pasuje do certyfikatu")
            return kod2.sign_signing_string(key, params.signing_string())

        out = read_private_key(
            key_path, cached, action=action, require_encrypted=options.require_encrypted_key
        )
        if out.action_result is None:
            msg = out.action_error or out.decrypt.summary
            rep.operations["kod2"] = {
                "code": "KOD2_SIGNING_FAILED",
                "status": "FAIL",
                "message": f"Nie wykonano podpisu KODU II: {msg}",
            }
            return report
        url = kod2.build_url(params, out.action_result)
        ver = kod2.verify_url(url, cert.public_key(), params.serial_hex16)
        tampered = kod2.Kod2Params(
            env,
            setup.context_type,
            nip,
            setup.seller_nip or nip,
            serial_hex(cert),
            kod2.invoice_hash(b"inna tresc"),
        )
        tamper_url = f"https://{tampered.signing_string()}/{out.action_result}"
        tamper_ok = not kod2.verify_url(tamper_url, cert.public_key(), params.serial_hex16).valid
        rep.operations["kod2"] = {
            "code": ver.code if tamper_ok else "KOD2_TAMPER_NOT_DETECTED",
            "status": "PASS" if ver.valid and tamper_ok else "FAIL",
            "message": ver.message
            + (
                " Zmiana danych unieważnia podpis (sprawdzone)."
                if tamper_ok
                else " UWAGA: zmiana danych nie unieważniła podpisu!"
            ),
            "environment": env,
            "synthetic": True,
            "url": url,
            "note": "Dane syntetyczne – to nie jest prawdziwa faktura; link NIE może być użyty ani wysłany do KSeF.",
        }
        return report
    finally:
        cached.clear()
