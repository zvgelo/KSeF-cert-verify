"""Klient tylko-do-odczytu dla `POST /certificates/query` (KSeF API 2.0).

* Brak automatycznych połączeń – obiekt tworzy się wyłącznie na żądanie użytkownika.
* Token dostępu (JWT) pochodzi z zewnątrz (zmienna środowiskowa / ukryty prompt);
  program nie implementuje uwierzytelnienia XAdES i nie obchodzi autoryzacji.
* Token nigdy nie trafia do logów ani komunikatów błędów.
* TLS jest zawsze weryfikowany.
* Wyłącznie niemodyfikujące wywołanie (zapytanie filtrujące po numerze seryjnym).
"""

from __future__ import annotations

import httpx

from ksef_cert_verify.core.certificate_validator import OnlineOutcome

ENVIRONMENTS = {
    "TEST": "https://api-test.ksef.mf.gov.pl/v2",
    "DEMO": "https://api-demo.ksef.mf.gov.pl/v2",
    "PROD": "https://api.ksef.mf.gov.pl/v2",
}
KNOWN_STATUSES = {"Active", "Blocked", "Revoked", "Expired"}
TOKEN_ENV = "KSEF_ACCESS_TOKEN"

OWNER_NOTE = (
    "Zapytanie zwraca wyłącznie certyfikaty uwierzytelnionego podmiotu (właściciela) – "
    "dla cudzych certyfikatów status jest niedostępny."
)


class KsefApiClient:
    def __init__(
        self,
        environment: str,
        access_token: str,
        timeout: float = 15.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        env = environment.upper()
        if env not in ENVIRONMENTS:
            raise ValueError(f"Nieznane środowisko: {environment!r} (dozwolone: TEST, DEMO, PROD)")
        if not access_token or any(c in access_token for c in "\r\n"):
            raise ValueError("Nieprawidłowy token dostępu.")
        self.environment = env
        self.base_url = ENVIRONMENTS[env]
        self._token = access_token
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            transport=transport,
            verify=True,  # nigdy nie wyłączamy walidacji TLS
            follow_redirects=False,
            headers={"Accept": "application/json", "X-Error-Format": "problem-details"},
        )

    def __repr__(self) -> str:  # brak tokenu w reprezentacji
        return f"KsefApiClient(environment={self.environment!r})"

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> KsefApiClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def lookup(self, serial_hex16: str) -> OnlineOutcome:
        """Zwraca wynik zapytania; nigdy nie rzuca (błędy → status UNKNOWN z opisem)."""
        try:
            resp = self._client.post(
                "/certificates/query",
                params={"pageSize": 10, "pageOffset": 0},
                json={"certificateSerialNumber": serial_hex16},
                headers={"Authorization": f"Bearer {self._token}"},
            )
        except httpx.TimeoutException:
            return OnlineOutcome("UNKNOWN", "Przekroczono czas oczekiwania na odpowiedź API KSeF.")
        except httpx.ConnectError:
            return OnlineOutcome("UNKNOWN", "Błąd połączenia z API KSeF (sieć/DNS/TLS).")
        except httpx.HTTPError as exc:
            return OnlineOutcome("UNKNOWN", f"Błąd sieciowy ({type(exc).__name__}).")
        return self._interpret(resp, serial_hex16)

    def _interpret(self, resp: httpx.Response, serial: str) -> OnlineOutcome:
        code = resp.status_code
        if code == 401:
            return OnlineOutcome("UNKNOWN", "Brak autoryzacji (401): token niepoprawny lub wygasły.")
        if code == 403:
            return OnlineOutcome(
                "UNKNOWN", "Brak uprawnień (403): token nie uprawnia do odczytu certyfikatów. " + OWNER_NOTE
            )
        if code == 429:
            retry = resp.headers.get("Retry-After")
            return OnlineOutcome(
                "UNKNOWN",
                "Przekroczono limit żądań API (429)"
                + (f"; spróbuj ponownie za {retry} s." if retry else "."),
            )
        if code == 400:
            return OnlineOutcome("UNKNOWN", "API odrzuciło zapytanie jako niepoprawne (400).")
        if code >= 500:
            return OnlineOutcome("UNKNOWN", f"Błąd serwera API KSeF ({code}).")
        if code != 200:
            return OnlineOutcome("UNKNOWN", f"Nieoczekiwana odpowiedź API: HTTP {code}.")
        try:
            body = resp.json()
            items = body["certificates"]
            if not isinstance(items, list):
                raise TypeError
        except (ValueError, KeyError, TypeError):
            return OnlineOutcome("UNKNOWN", "Odpowiedź API ma nieoczekiwany format.")
        match = [i for i in items if isinstance(i, dict) and i.get("certificateSerialNumber") == serial]
        if not match:
            return OnlineOutcome(
                "NOT_FOUND",
                "Nie znaleziono certyfikatu wśród certyfikatów uwierzytelnionego podmiotu. "
                "To nie oznacza unieważnienia. " + OWNER_NOTE,
            )
        item = match[0]
        status = item.get("status")
        if status not in KNOWN_STATUSES:
            return OnlineOutcome("UNKNOWN", f"API zwróciło nieznany status: {status!r}.")
        raw_sid = item.get("subjectIdentifier")
        sid: dict = raw_sid if isinstance(raw_sid, dict) else {}
        return OnlineOutcome(
            status,
            "",
            api_type=item.get("type"),
            api_valid_from=item.get("validFrom"),
            api_valid_to=item.get("validTo"),
            api_common_name=item.get("commonName"),
            api_subject_id_type=sid.get("type"),
            api_subject_id_value=sid.get("value"),
        )
