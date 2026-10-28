# Bezpieczeństwo

Program analizuje potencjalnie **niezaufane** pliki. Zasady i ich weryfikacja:

| Zasada | Realizacja |
|---|---|
| Brak wykonywania danych z certyfikatu | tylko parsowanie `cryptography`; brak `eval`/shell/URL-fetch z pól certyfikatu (AIA/CRL ignorowane) |
| Limity | plik ≤ 1 MiB (`MAX_FILE_BYTES`); głębokość łańcucha ≤ 8 |
| Klucze prywatne | klucz jest odszyfrowywany tylko w pamięci (`core/private_key.py`), z niego wyprowadzany jest publiczny SPKI, po czym obiekt klucza jest porzucany; nie jest zapisywany, zwracany, logowany ani trafia do JSON/GUI (testy) |
| Hasła | nigdy w argv (nie ma takiej opcji); ukryty prompt, `--password-stdin` albo `--password-fd`; w GUI pole hasła, czyszczone po każdej weryfikacji; nie są przechowywane, zapisywane w konfiguracji ani logowane; komunikat o błędnym haśle nie zawiera szczegółów (testy na brak wycieku do stdout/stderr/JSON/GUI/ustawień) |
| Sieć | domyślnie **brak**; tylko `--online` / pole wyboru w GUI, jawnie wybrane środowisko; certyfikaty nigdy nie są wysyłane (wysyłany jest wyłącznie numer seryjny) |
| API | tylko `POST /certificates/query` (odczyt); TLS zawsze weryfikowany; bez przekierowań; token tylko w nagłówku, poza logami i `repr` |
| Zaufanie | tylko CA skonfigurowane przez użytkownika, dopasowanie po DER; CA z pliku nie staje się kotwicą |
| Fail-closed | nieznane/niewspierane rozszerzenie krytyczne (w tym NameConstraints/PolicyConstraints) → FAIL; UNKNOWN ≠ PASS |
| Wstrzykiwanie w UI | CLI: escapowanie znaczników Rich + usuwanie znaków sterujących/bidi; GUI: `Qt::PlainText`, czyszczenie znaków sterujących/bidi; JSON jest escapowany przez serializer |
| Własna kryptografia | brak – wyłącznie `cryptography` |

## Token dostępu KSeF

Program nie loguje się do KSeF. Token JWT pochodzi spoza programu (np. z własnego procesu uwierzytelnienia XAdES) i jest
traktowany jak sekret: zmienna środowiskowa lub ukryte pole. Pamiętaj, że zmienne środowiskowe bywają widoczne dla innych
procesów tego samego użytkownika.

## Znane ograniczenia

* Program nie sprawdza CRL/OCSP wystawcy (MF ich nie opisuje dla certyfikatów KSeF) – służy do tego status online.
* Pakiety PyInstaller nie są podpisane cyfrowo.
* Raport o podatności: zgłoś prywatnie opiekunowi repozytorium (nie w publicznym issue).

## Tokeny, uwierzytelnienie online i PROD

| Zasada | Realizacja |
|---|---|
| accessToken (JWT) ≠ token KSeF | automatyczne uwierzytelnienie używa wyłącznie podpisu XAdES; token KSeF nie jest obsługiwany |
| Tokeny nie są zapisywane ani logowane | `AuthResult` nie zawiera tokenów (`repr`/`to_dict`), JSON/GUI/logi sprawdzane testami; `authenticationToken` i `refreshToken` nie są przechowywane |
| JWT z zewnątrz | tylko struktura i `exp`; dekodowanie ≠ autentyczność (jawnie komunikowane) |
| PROD | wymaga jawnego potwierdzenia (`--confirm-prod`/`PROD` w terminalu; w GUI wpisanie `PROD`); bez niego zero wywołań sieciowych |
| TLS | zawsze weryfikowany; błąd TLS to osobny wynik `AUTH_TLS` |
| Klucz | odszyfrowywany w pamięci; operacje (test podpisu, XAdES, KOD II) wykonywane wewnątrz `core/private_key.py`; nie jest zapisywany na dysku |
| Klucz niezaszyfrowany | `FAIL` z komunikatem „PROBLEM BEZPIECZEŃSTWA” (wyjątek tylko świadomą opcją) |
| Zaufane CA | dodawane ręcznie po potwierdzeniu odcisku SHA-256; tylko `CA=TRUE`; kotwica = identyczny DER |

**Ograniczenie:** Python nie pozwala niezawodnie wyzerować pamięci z hasłem/kluczem (niemutowalne `str`/`bytes`, GC). Program ogranicza czas życia
referencji (hasło trzymane w uchwycie czyszczonym po pracy, klucz tylko w wywołaniu), ale nie gwarantuje zerowania pamięci procesu.
