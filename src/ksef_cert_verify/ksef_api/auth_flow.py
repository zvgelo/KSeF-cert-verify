"""Uwierzytelnienie w KSeF API 2.0 podpisem XAdES (oficjalny przebieg: `uwierzytelnianie.md`).

Kroki: POST /auth/challenge → AuthTokenRequest → podpis XAdES → POST /auth/xades-signature (202) →
GET /auth/{referenceNumber} (Bearer authenticationToken) do skutku → POST /auth/token/redeem → accessToken (JWT).

* accessToken JWT (wynik tej procedury) ≠ token KSeF (alternatywna metoda uwierzytelnienia) – nie mylić.
* Tokeny i hasła nigdy nie są logowane ani zapisywane; wynik (`AuthResult.to_dict`) nie zawiera tokenów.
* TLS zawsze weryfikowany. PROD wymaga jawnego potwierdzenia po stronie wywołującego (`allow_prod`).
* Rozdzielone wyniki: kryptografia (lokalnie) ≠ uwierzytelnienie (KSeF zaakceptował certyfikat) ≠ autoryzacja (uprawnienia).
"""

from __future__ import annotations

import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from .ksef_client import ENVIRONMENTS

POLL_IN_PROGRESS = 100
POLL_SUCCESS = 200
POLL_NO_PERMISSIONS = 415
POLL_CERT_ERROR = 460


class SigningError(Exception):
    """Błąd lokalnego podpisu (komunikat bez danych wrażliwych)."""


class ApiFailure(Exception):
    """Błąd wywołania API (bez danych wrażliwych w komunikacie)."""

    def __init__(self, kind: str, message: str, http_status: int | None = None, codes: tuple[int, ...] = ()):
        super().__init__(message)
        self.kind, self.message, self.http_status, self.codes = kind, message, http_status, codes


@dataclass
class AuthStep:
    name: str
    status: str  # OK | FAIL | SKIPPED
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status, "message": self.message}


@dataclass
class AuthResult:
    authentication: str = "NOT_TESTED"  # ACCEPTED | REJECTED | UNKNOWN | NOT_TESTED
    authorization: str = "NOT_TESTED"  # GRANTED | DENIED | UNKNOWN | NOT_TESTED
    code: str = "AUTH_NOT_TESTED"
    message: str = "Uwierzytelnienie nie było testowane."
    environment: str | None = None
    context: str | None = None
    steps: list[AuthStep] = field(default_factory=list)
    access_token: str | None = field(default=None, repr=False)  # tylko w pamięci; poza to_dict/repr
    access_valid_until: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "authentication": self.authentication,
            "authorization": self.authorization,
            "code": self.code,
            "message": self.message,
            "environment": self.environment,
            "context": self.context,
            "steps": [s.to_dict() for s in self.steps],
            "access_token_obtained": self.access_token is not None,
            "access_token_valid_until": self.access_valid_until,
        }


def _codes(body: Any) -> tuple[int, ...]:
    found: list[int] = []

    def walk(x: Any) -> None:
        if isinstance(x, dict):
            for k, v in x.items():
                if k in ("exceptionCode", "code") and isinstance(v, int):
                    found.append(v)
                else:
                    walk(v)
        elif isinstance(x, list):
            for i in x:
                walk(i)

    walk(body)
    return tuple(found)


class AuthApi:
    """Cienki klient endpointów /auth/* (tylko to, co potrzebne do uwierzytelnienia XAdES)."""

    def __init__(self, environment: str, timeout: float = 15.0, transport: httpx.BaseTransport | None = None):
        env = environment.upper()
        if env not in ENVIRONMENTS:
            raise ValueError(f"Nieznane środowisko: {environment!r} (dozwolone: TEST, DEMO, PROD)")
        self.environment = env
        self._client = httpx.Client(
            base_url=ENVIRONMENTS[env],
            timeout=timeout,
            transport=transport,
            verify=True,  # nigdy nie wyłączamy walidacji TLS
            follow_redirects=False,
            headers={"Accept": "application/json", "X-Error-Format": "problem-details"},
        )

    def close(self) -> None:
        self._client.close()

    def __repr__(self) -> str:
        return f"AuthApi(environment={self.environment!r})"

    def _call(self, method: str, url: str, **kw: Any) -> httpx.Response:
        try:
            return self._client.request(method, url, **kw)
        except httpx.TimeoutException as exc:
            raise ApiFailure("TIMEOUT", "Przekroczono czas oczekiwania na odpowiedź API KSeF.") from exc
        except httpx.ConnectError as exc:
            cause = exc.__cause__ or exc.__context__
            if (
                isinstance(cause, ssl.SSLError)
                or "CERTIFICATE_VERIFY_FAILED" in str(exc)
                or "SSL" in str(exc)
            ):
                raise ApiFailure(
                    "TLS",
                    "Błąd TLS: nie udało się zweryfikować certyfikatu serwera API (walidacja TLS nie jest wyłączana).",
                ) from exc
            raise ApiFailure("NETWORK", "Błąd połączenia z API KSeF (sieć/DNS).") from exc
        except httpx.HTTPError as exc:
            raise ApiFailure("NETWORK", f"Błąd sieciowy ({type(exc).__name__}).") from exc

    @staticmethod
    def _check(resp: httpx.Response, ok: tuple[int, ...]) -> Any:
        if resp.status_code in ok:
            try:
                return resp.json()
            except ValueError as exc:
                raise ApiFailure(
                    "BAD_RESPONSE", "Odpowiedź API ma nieoczekiwany format.", resp.status_code
                ) from exc
        try:
            codes = _codes(resp.json())
        except ValueError:
            codes = ()
        code = resp.status_code
        kind = {
            401: "UNAUTHORIZED",
            403: "FORBIDDEN",
            429: "RATE_LIMIT",
            400: "BAD_REQUEST",
            410: "GONE",
        }.get(code, "SERVER" if code >= 500 else "HTTP")
        msg = {
            "UNAUTHORIZED": "Brak autoryzacji (401).",
            "FORBIDDEN": "Brak uprawnień (403).",
            "RATE_LIMIT": "Przekroczono limit żądań API (429)"
            + (f"; spróbuj za {resp.headers['Retry-After']} s." if "Retry-After" in resp.headers else "."),
            "BAD_REQUEST": "API odrzuciło żądanie (400).",
            "GONE": "Operacja uwierzytelnienia wygasła (410).",
            "SERVER": f"Błąd serwera API KSeF ({code}).",
        }.get(kind, f"Nieoczekiwana odpowiedź API: HTTP {code}.")
        raise ApiFailure(kind, msg, code, codes)

    def challenge(self) -> dict[str, Any]:
        return self._check(self._call("POST", "/auth/challenge"), (200,))

    def submit_xades(self, signed_xml: bytes, verify_certificate_chain: bool | None = None) -> dict[str, Any]:
        params = (
            {}
            if verify_certificate_chain is None
            else {"verifyCertificateChain": str(verify_certificate_chain).lower()}
        )
        resp = self._call(
            "POST",
            "/auth/xades-signature",
            content=signed_xml,
            params=params,
            headers={"Content-Type": "application/xml"},
        )
        return self._check(resp, (200, 202))

    def status(self, reference_number: str, authentication_token: str) -> dict[str, Any]:
        resp = self._call(
            "GET", f"/auth/{reference_number}", headers={"Authorization": f"Bearer {authentication_token}"}
        )
        return self._check(resp, (200,))

    def redeem(self, authentication_token: str) -> dict[str, Any]:
        resp = self._call(
            "POST", "/auth/token/redeem", headers={"Authorization": f"Bearer {authentication_token}"}
        )
        return self._check(resp, (200,))


def run_xades_auth(
    api: AuthApi,
    sign_request: Callable[[bytes], bytes],
    build_request: Callable[[str], bytes],
    *,
    context_label: str,
    verify_certificate_chain: bool | None = None,
    redeem: bool = True,
    poll_timeout: float = 60.0,
    poll_interval: float = 2.0,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> AuthResult:
    """Pełny przebieg uwierzytelnienia. Nigdy nie rzuca (błędy → wynik z kodem)."""
    res = AuthResult(environment=api.environment, context=context_label)

    def step(name: str, status: str, msg: str) -> None:
        res.steps.append(AuthStep(name, status, msg))

    def fail(code: str, msg: str, authn: str = "UNKNOWN", authz: str = "UNKNOWN") -> AuthResult:
        res.code, res.message, res.authentication, res.authorization = code, msg, authn, authz
        return res

    try:
        ch = api.challenge()
        challenge = ch["challenge"]
        step("challenge", "OK", "Pobrano challenge uwierzytelnienia.")
    except (ApiFailure, KeyError, TypeError) as exc:
        msg = (
            exc.message
            if isinstance(exc, ApiFailure)
            else "Odpowiedź /auth/challenge nie zawiera pola challenge."
        )
        kind = exc.kind if isinstance(exc, ApiFailure) else "BAD_RESPONSE"
        step("challenge", "FAIL", msg)
        return fail(f"AUTH_{kind}" if kind in ("TLS", "TIMEOUT", "NETWORK") else "AUTH_CHALLENGE_FAILED", msg)

    try:
        signed = sign_request(build_request(challenge))
        step("podpis XAdES", "OK", "Przygotowano i podpisano AuthTokenRequest (XAdES-BES).")
    except Exception as exc:  # błąd podpisu lokalnego (np. klucz) – komunikat bez danych wrażliwych
        reason = str(exc) if isinstance(exc, SigningError) else type(exc).__name__
        step("podpis XAdES", "FAIL", f"Nie udało się podpisać żądania: {reason}.")
        return fail(
            "AUTH_SIGNING_FAILED",
            f"Nie udało się podpisać AuthTokenRequest ({reason}).",
            "NOT_TESTED",
            "NOT_TESTED",
        )

    try:
        init = api.submit_xades(signed, verify_certificate_chain)
        ref = init["referenceNumber"]
        auth_token = init["authenticationToken"]["token"]
        step("wysłanie żądania", "OK", "API przyjęło żądanie (202).")
    except ApiFailure as exc:
        step("wysłanie żądania", "FAIL", exc.message)
        if exc.kind == "BAD_REQUEST":
            if 21115 in exc.codes:
                return fail(
                    "AUTH_CERT_REJECTED",
                    "KSeF odrzucił certyfikat (21115: nieprawidłowy certyfikat).",
                    "REJECTED",
                    "UNKNOWN",
                )
            if 21117 in exc.codes:
                return fail(
                    "AUTH_CONTEXT_INVALID",
                    "Nieprawidłowy identyfikator kontekstu dla wskazanego typu (21117).",
                    "UNKNOWN",
                    "UNKNOWN",
                )
            if 21111 in exc.codes:
                return fail("AUTH_CHALLENGE_INVALID", "Nieprawidłowe lub wygasłe challenge (21111).")
            if 21401 in exc.codes:
                return fail("AUTH_REQUEST_INVALID", "Dokument AuthTokenRequest niezgodny ze schemą (21401).")
            return fail(
                "AUTH_REQUEST_REJECTED",
                f"API odrzuciło żądanie uwierzytelnienia (kody: {', '.join(map(str, exc.codes)) or 'brak'}).",
                "REJECTED",
                "UNKNOWN",
            )
        return fail(f"AUTH_{exc.kind}", exc.message)
    except (KeyError, TypeError):
        step("wysłanie żądania", "FAIL", "Odpowiedź API nie zawiera referenceNumber/authenticationToken.")
        return fail("AUTH_BAD_RESPONSE", "Nieoczekiwany format odpowiedzi /auth/xades-signature.")

    deadline = monotonic() + poll_timeout
    while True:
        try:
            st = api.status(ref, auth_token)
        except ApiFailure as exc:
            step("status uwierzytelnienia", "FAIL", exc.message)
            return fail(f"AUTH_{exc.kind}", exc.message)
        code = (st.get("status") or {}).get("code")
        details = "; ".join((st.get("status") or {}).get("details") or [])
        if code == POLL_IN_PROGRESS:
            if monotonic() >= deadline:
                step(
                    "status uwierzytelnienia",
                    "FAIL",
                    "Uwierzytelnianie nadal w toku po upływie limitu czasu.",
                )
                return fail(
                    "AUTH_IN_PROGRESS_TIMEOUT",
                    "Uwierzytelnianie nadal w toku (limit oczekiwania minął) – wynik nieustalony.",
                )
            sleep(poll_interval)
            continue
        break
    if code == POLL_SUCCESS:
        step("status uwierzytelnienia", "OK", "Uwierzytelnianie zakończone sukcesem (200).")
        res.authentication, res.authorization = "ACCEPTED", "GRANTED"
        res.code, res.message = (
            "AUTH_SUCCESS",
            "KSeF zaakceptował certyfikat i podpis; podmiot ma uprawnienia w kontekście.",
        )
        if redeem:
            try:
                tok = api.redeem(auth_token)
                res.access_token = tok["accessToken"]["token"]
                res.access_valid_until = tok["accessToken"].get("validUntil")
                step(
                    "accessToken", "OK", "Odebrano accessToken (JWT) – tylko w pamięci, nie jest zapisywany."
                )
            except (ApiFailure, KeyError, TypeError) as exc:
                msg = (
                    exc.message
                    if isinstance(exc, ApiFailure)
                    else "Nieoczekiwany format odpowiedzi /auth/token/redeem."
                )
                step("accessToken", "FAIL", msg)
                res.message += " Nie udało się odebrać accessToken: " + msg
        return res
    step(
        "status uwierzytelnienia",
        "FAIL",
        f"Status {code}: {details or (st.get('status') or {}).get('description', '')}",
    )
    if code == POLL_NO_PERMISSIONS:
        return fail(
            "AUTH_NO_PERMISSIONS",
            "Brak uprawnień w wybranym kontekście (415). To jest wynik AUTORYZACJI – nie dowodzi nieprawidłowej pary klucz/certyfikat.",
            "UNKNOWN",
            "DENIED",
        )
    if code == POLL_CERT_ERROR:
        return fail(
            "AUTH_CERT_REJECTED",
            f"KSeF odrzucił certyfikat (460): {details or 'błąd certyfikatu'}.",
            "REJECTED",
            "UNKNOWN",
        )
    if code in (450, 425, 470, 480):
        return fail(
            "AUTH_REJECTED", f"Uwierzytelnianie odrzucone (status {code}): {details}.", "REJECTED", "UNKNOWN"
        )
    return fail(
        "AUTH_FAILED", f"Uwierzytelnianie zakończone niepowodzeniem (status {code}).", "UNKNOWN", "UNKNOWN"
    )
