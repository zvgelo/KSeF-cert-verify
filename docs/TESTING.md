# Testy

```bash
pip install -e ".[dev]"
pytest -rs                       # wszystko; -rs pokazuje powody pominięć
pytest tests/unit                # silnik
pytest tests/integration         # loader, API (MockTransport), bezpieczeństwo
pytest tests/e2e                 # CLI jako osobny proces + GUI Qt (offscreen)
ruff check src tests && ruff format --check src tests && mypy src
```

Testy działają **bez internetu**. Klient API jest testowany na `httpx.MockTransport`; nie ma testów na PROD.
GUI: `QT_QPA_PLATFORM=offscreen` jest ustawiane automatycznie (`tests/conftest.py`); na Linuxowym CI dodatkowo instalowane są biblioteki Qt.

## Podział testów

| Obszar | Pliki | Charakter |
|---|---|---|
| kryptografia | `unit/test_signing_kod2.py`, `unit/test_private_key.py`, `unit/test_engine.py` | lokalne, symulowane |
| zgodność z profilem KSeF | `unit/test_engine.py` (profil), `unit/test_signing_kod2.py` (KOD II wg `kody-qr.md`) | wg dokumentacji MF, bez certyfikatów referencyjnych |
| sieć / API | `integration/test_ksef_api.py`, `integration/test_auth_flow.py` | **wyłącznie** `httpx.MockTransport`; testy CLI z zablokowanym DNS |
| E2E CLI / GUI | `e2e/test_cli_e2e.py`, `e2e/test_gui_e2e.py` | osobny proces / okno Qt offscreen |
| branding | `unit/test_branding.py` | spójność nazw i stałych identyfikatorów |

Testy online do prawdziwego API TEST nie istnieją w repozytorium; PROD nie jest nigdy używany.

## Fixtury są symulowane

Wszystkie certyfikaty w testach generuje `tests/conftest.py` (własne „CA”, liście, łańcuchy), z datami względem stałego zegara.
Testy mają znacznik `simulated`: **sprawdzają mechanizmy kryptograficzne i logikę reguł, nie zgodność z MF**. Nie istnieją
oficjalne certyfikaty referencyjne KSeF (zob. TECHNICAL_FINDINGS), więc nie ma testów „potwierdzających zgodność z MF”.

## Pokrycie scenariuszy

| # | Scenariusz | Gdzie |
|---|---|---|
| 1–2 | poprawny Authentication / Offline | `unit/test_engine` |
| 3–4 | przed ważnością / wygasły | `unit/test_engine` |
| 5, 29, 30 | zły podpis, podmiana CA o identycznym Subject, obcy CA | `unit/test_engine` |
| 6 | niezaufany wystawca | `unit/test_engine`, `integration/test_loader_and_service` |
| 7–8 | zły Key Usage / typ nieznany | `unit/test_engine` |
| 9–10, 13 | uszkodzony PEM / DER, brak certyfikatu | `integration/test_loader_and_service` |
| 11–12 | PKCS#12 poprawny / błędne hasło | `integration/…`, `e2e/test_cli_e2e`, `e2e/test_gui_e2e` |
| 14–15 | łańcuch w pliku / brakujące ogniwa | `integration/…`, `unit/test_engine` |
| 16–17 | nieobsługiwany algorytm / krytyczne rozszerzenia | `unit/test_engine` |
| 18–19 | ścieżki Win/Linux, polskie znaki | `integration/test_security_and_paths` (część Windows tylko na Windows CI), `e2e` |
| 20–22 | wiele certyfikatów, eksport JSON, zgodność CLI↔GUI | `integration`, `e2e/test_gui_e2e::test_export_json_matches_cli_output` |
| 23–27 | brak online, statusy API, błędy auth, timeout, sieć | `integration/test_ksef_api` |
| 28 | technicznie poprawny, profil niepotwierdzony | `unit/test_engine` (`INDETERMINATE`) |

Dodatkowo: wstrzykiwanie markupu/ANSI/HTML (CLI i GUI), brak plików i kluczy po analizie PKCS#12, brak ruchu sieciowego w trybie domyślnym.

## Pominięcia

Pominięte testy **nie są zaliczeniem**: `test_md5_signature_weak` (SHA-1 niedostępny w buildzie OpenSSL – zależnie od systemu) oraz test
ścieżek Windows (tylko `win32`). CI uruchamia `pytest -rs`, żeby powody były widoczne.

## Opcjonalnie: prawdziwe API TEST

Znacznik `live_api` jest zarezerwowany na jawne, kontrolowane testy na środowisku TEST (wymagają własnego tokenu i uprawnień
właściciela). W repozytorium nie ma takich testów; PROD nie jest używany.
