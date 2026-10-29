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
from cryptography.hazmat.primitives.asymmetric import ec

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
    invoice_path: Path | None = None  # opcjonalny plik faktury XML (bez niego: test syntetyczny)
    ec_format: str = "p1363"  # ECDSA: p1363 (rekomendowany) | der


def run_kod2_test(
    cert_path: Path,
    key_path: Path,
    options: VerifyOptions,
    provider: PasswordProvider | None,
    setup: Kod2Setup,
    online: OnlineSetup | None = None,
) -> FileReport:
    """Weryfikacja pary + test podpisu KODU II (dane syntetyczne; link nie jest nigdzie wysyłany).

    Z `online` dodatkowo status w rejestrze KSeF; certyfikatem Offline NIE uwierzytelniamy – bez uprawnionego JWT
    wynik online to jawne „nieustalony” z wyjaśnieniem (patrz `establish_online`)."""
    cached = CachedPassword(provider)
    try:
        if online is not None:
            report, _session = verify_with_online(cert_path, key_path, options, cached, online)
        else:
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
        inv: kod2.InvoiceInfo | None = None
        if setup.invoice_path is not None:
            try:
                inv = kod2.read_invoice(setup.invoice_path)
            except (ValueError, OSError) as exc:
                rep.operations["kod2"] = {
                    "code": "KOD2_INVOICE_INVALID",
                    "status": "FAIL",
                    "message": str(exc),
                }
                return report
            if setup.seller_nip and inv.seller_nip and setup.seller_nip != inv.seller_nip:
                rep.operations["kod2"] = {
                    "code": "KOD2_SELLER_MISMATCH",
                    "status": "FAIL",
                    "message": "NIP sprzedawcy podany przez użytkownika różni się od Podmiot1 w pliku faktury.",
                }
                return report
        nip = setup.context_value or info.subject_info.nip or "1111111111"
        seller = setup.seller_nip or (inv.seller_nip if inv else None) or nip
        inv_hash = inv.hash_b64url if inv else kod2.invoice_hash()
        try:
            params = kod2.Kod2Params(env, setup.context_type, nip, seller, serial_hex(cert), inv_hash)
            params.validate()
        except ValueError as exc:
            rep.operations["kod2"] = {"code": "KOD2_BAD_PARAMS", "status": "FAIL", "message": str(exc)}
            return report

        def action(key: Any) -> tuple[str, str | None]:
            if spki_of_certificate(cert) != _spki_of_key(key):
                raise SigningError("klucz prywatny nie pasuje do certyfikatu")
            text = params.signing_string()
            primary = kod2.sign_signing_string(key, text, "der" if setup.ec_format == "der" else "p1363")
            other = None
            if isinstance(
                key, ec.EllipticCurvePrivateKey
            ):  # dowód, że oba kodowania z dokumentacji MF są obsługiwane
                other = kod2.sign_signing_string(key, text, "p1363" if setup.ec_format == "der" else "der")
            return primary, other

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
        signature, other_signature = out.action_result
        url = kod2.build_url(params, signature)

        def check_link(link: str) -> kod2.Kod2Verification:
            return kod2.verify_url(
                link,
                cert.public_key(),
                params.serial_hex16,
                expected_context=(params.context_type, params.context_value),
                expected_seller_nip=params.seller_nip,
                expected_invoice_hash=params.invoice_hash_b64url,
            )

        ver = check_link(url)
        encodings_ok = ver.valid
        if other_signature is not None:
            encodings_ok = encodings_ok and check_link(kod2.build_url(params, other_signature)).valid
        # zmiana danych (skrót faktury ALBO NIP sprzedawcy) musi unieważnić podpis
        other_nip = "1111111111" if params.seller_nip != "1111111111" else "5260250995"
        tampered = {
            "hash": kod2.Kod2Params(
                env, setup.context_type, nip, seller, serial_hex(cert), kod2.invoice_hash(b"inna tresc")
            ),
            "NIP sprzedawcy": kod2.Kod2Params(
                env, setup.context_type, nip, other_nip, serial_hex(cert), inv_hash
            ),
        }
        tamper_ok = all(
            not kod2.verify_url(
                f"https://{t.signing_string()}/{signature}", cert.public_key(), params.serial_hex16
            ).valid
            for t in tampered.values()
        )
        good = ver.valid and tamper_ok and encodings_ok
        rep.operations["kod2"] = {
            "code": ver.code if (tamper_ok and encodings_ok) else "KOD2_TAMPER_NOT_DETECTED",
            "status": "PASS" if good else "FAIL",
            "message": ver.message
            + (
                " Zmiana skrótu faktury lub NIP sprzedawcy unieważnia podpis (sprawdzone)."
                if tamper_ok
                else " UWAGA: zmiana danych nie unieważniła podpisu!"
            ),
            "kind": "INVOICE_LINK" if inv else "SYNTHETIC_CRYPTO_TEST",
            "environment": env,
            "synthetic": inv is None,
            "signature_format": ver.encoding,
            "encodings_verified": ["P1363", "DER"] if other_signature is not None else [ver.encoding],
            "context": {"type": params.context_type, "value": params.context_value},
            "seller_nip": params.seller_nip,
            "serial_number": params.serial_hex16,
            "invoice_hash": params.invoice_hash_b64url,
            "url": url,
            "openable": kod2.is_official_url(url) and (env != "PROD" or inv is not None),
            # status w rejestrze i uprawnienia do wystawienia faktury to dwie różne rzeczy; to drugie sprawdza wyłącznie KSeF
            "registry_status": rep.online_status,
            "issuing_authority": {
                "status": "NOT_VERIFIED",
                "message": "Uprawnienia wystawcy do wystawienia faktury w kontekście potwierdza dopiero system KSeF po "
                "otwarciu linku; MF nie udostępnia maszynowego interfejsu tej weryfikacji. Otwarcie strony ani HTTP 200 "
                "nie jest dowodem autentyczności wystawcy.",
            },
            "note": (
                "Link zawiera skrót prawdziwego pliku faktury; nic nie jest wysyłane do KSeF bez Twojej akcji."
                if inv
                else "Syntetyczny test kryptograficzny – dane sztuczne, to nie jest prawdziwa faktura; link NIE może być użyty ani wysłany do KSeF."
            ),
        }
        return report
    finally:
        cached.clear()
