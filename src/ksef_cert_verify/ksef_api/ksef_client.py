"""Klient tylko-do-odczytu dla `POST /certificates/query` i `POST /certificates/retrieve` (KSeF API 2.0).

* Brak automatycznych połączeń – obiekt tworzy się wyłącznie na żądanie użytkownika.
* Token dostępu (JWT) pochodzi z zewnątrz (zmienna środowiskowa / ukryty prompt);
  program nie implementuje uwierzytelnienia XAdES i nie obchodzi autoryzacji.
* Token nigdy nie trafia do logów ani komunikatów błędów.
* TLS jest zawsze weryfikowany.
* Wyłącznie niemodyfikujące wywołania (zapytanie filtrujące po numerze seryjnym, opcjonalnie pobranie certyfikatu).
* W odpowiedzi `/certificates/query` pole `name` to nazwa własna nadana przy rejestracji, a `commonName` – CN podmiotu;
  żadne z nich nie jest identyfikatorem (identyfikuje numer seryjny, a pewnie – odcisk DER z `/certificates/retrieve`).
"""

from __future__ import annotations

import base64
import binascii

import httpx

from ksef_cert_verify.core.certificate_validator import OnlineOutcome

ENVIRONMENTS = {
    "TEST": "https://api-test.ksef.mf.gov.pl/v2",
    "DEMO": "https://api-demo.ksef.mf.gov.pl/v2",
    "PROD": "https://api.ksef.mf.gov.pl/v2",
}
KNOWN_STATUSES = {"Active", "Blocked", "Revoked", "Expired"}
PAGE_SIZE = 10  # minimum dozwolone przez API (10–50)
MAX_PAGES = 5  # twardy limit zapytań na jedno wyszukiwanie (bez niekontrolowanych pętli)
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
        """Zwraca wynik zapytania; nigdy nie rzuca (błędy → status UNKNOWN z opisem).

        Filtr `certificateSerialNumber` jest dokładny (exact match) i stronicowany: `hasMore` → kolejna strona,
        najwyżej MAX_PAGES żądań. Rekord jest brany pod uwagę wyłącznie przy identycznym numerze seryjnym."""
        matches: list[dict] = []
        for page in range(MAX_PAGES):
            try:
                resp = self._client.post(
                    "/certificates/query",
                    params={"pageSize": PAGE_SIZE, "pageOffset": page},
                    json={"certificateSerialNumber": serial_hex16},
                    headers={"Authorization": f"Bearer {self._token}"},
                )
            except httpx.TimeoutException:
                return OnlineOutcome("UNKNOWN", "Przekroczono czas oczekiwania na odpowiedź API KSeF.")
            except httpx.ConnectError:
                return OnlineOutcome("UNKNOWN", "Błąd połączenia z API KSeF (sieć/DNS/TLS).")
            except httpx.HTTPError as exc:
                return OnlineOutcome("UNKNOWN", f"Błąd sieciowy ({type(exc).__name__}).")
            err = self._http_error(resp)
            if err is not None:
                return err
            try:
                body = resp.json()
                items = body["certificates"]
                if not isinstance(items, list):
                    raise TypeError
                has_more = bool(body.get("hasMore", False))
            except (ValueError, KeyError, TypeError, AttributeError):
                return OnlineOutcome("UNKNOWN", "Odpowiedź API ma nieoczekiwany format.")
            matches += [
                i for i in items if isinstance(i, dict) and i.get("certificateSerialNumber") == serial_hex16
            ]
            if not has_more or matches:
                break
        else:
            if not matches:
                return OnlineOutcome(
                    "UNKNOWN",
                    f"Wyniki zapytania przekraczają limit {MAX_PAGES} stron – status nieustalony.",
                    authorization="GRANTED",
                )
        return self._interpret_matches(matches)

    def retrieve_der(self, serial_hex16: str) -> tuple[bytes | None, str]:
        """`POST /certificates/retrieve`: DER certyfikatu o danym numerze (albo None + powód). Nie rzuca."""
        try:
            resp = self._client.post(
                "/certificates/retrieve",
                json={"certificateSerialNumbers": [serial_hex16]},
                headers={"Authorization": f"Bearer {self._token}"},
            )
        except httpx.HTTPError as exc:
            return None, f"Nie pobrano certyfikatu z API ({type(exc).__name__})."
        if resp.status_code != 200:
            return None, f"Nie pobrano certyfikatu z API (HTTP {resp.status_code})."
        try:
            for item in resp.json()["certificates"]:
                if isinstance(item, dict) and item.get("certificateSerialNumber") == serial_hex16:
                    return base64.b64decode(item["certificate"], validate=True), ""
        except (ValueError, KeyError, TypeError, binascii.Error):
            return None, "Odpowiedź /certificates/retrieve ma nieoczekiwany format."
        return None, "API nie zwróciło certyfikatu o tym numerze seryjnym."

    @staticmethod
    def _http_error(resp: httpx.Response) -> OnlineOutcome | None:
        """Mapowanie kodów HTTP na brak wyniku; None = HTTP 200 (dalej interpretujemy treść)."""
        code = resp.status_code
        if code == 401:
            return OnlineOutcome("UNKNOWN", "Brak autoryzacji (401): token niepoprawny lub wygasły.")
        if code == 403:
            return OnlineOutcome(
                "UNKNOWN",
                "Brak dostępu do rejestru certyfikatów (403): token nie uprawnia do odczytu certyfikatów. "
                + OWNER_NOTE,
                authorization="DENIED",
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
        return None

    @staticmethod
    def _interpret_matches(matches: list[dict]) -> OnlineOutcome:
        if not matches:
            return OnlineOutcome(
                "NOT_FOUND",
                "Rejestr certyfikatów KSeF nie zawiera wpisu o tym numerze seryjnym dla uwierzytelnionego "
                "podmiotu. To nie oznacza błędu ani unieważnienia certyfikatu. " + OWNER_NOTE,
                authorization="GRANTED",
            )
        if len(matches) > 1:
            return OnlineOutcome(
                "UNKNOWN",
                f"API zwróciło {len(matches)} wpisów o tym numerze seryjnym – dopasowanie niejednoznaczne.",
                authorization="GRANTED",
            )
        item = matches[0]
        status = item.get("status")
        if status not in KNOWN_STATUSES:
            return OnlineOutcome(
                "UNKNOWN", f"API zwróciło nieznany status: {status!r}.", authorization="GRANTED"
            )
        raw_sid = item.get("subjectIdentifier")
        sid: dict = raw_sid if isinstance(raw_sid, dict) else {}
        return OnlineOutcome(
            status,
            "",
            api_type=item.get("type"),
            api_valid_from=item.get("validFrom"),
            api_valid_to=item.get("validTo"),
            api_common_name=item.get("commonName"),
            api_name=item.get("name"),
            api_subject_id_type=sid.get("type"),
            api_subject_id_value=sid.get("value"),
            authorization="GRANTED",
        )
