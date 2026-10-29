# CLI

```text
ksef-cert-verify [--version] [--help] <polecenie>        # KSeF CertVerify – Weryfikacja certyfikatów KSeF
  verify  --cert C --key K   pełna weryfikacja: certyfikat + klucz + hasło (+ opcjonalnie status online)
  test-signature             aktywny test podpisu kluczem prywatnym (losowe dane)
  test-auth                  test uwierzytelnienia w KSeF (XAdES) – tylko Authentication
  test-kod2                  test podpisu KODU II – tylko Offline (dane syntetyczne)
  trust list|add|remove      zaufane CA (odcisk SHA-256, potwierdzenie)
  inspect PLIK               publiczne dane certyfikatu (to NIE jest weryfikacja)
  gui [--selftest]           interfejs graficzny / autotest
```

## `verify`

```bash
ksef-cert-verify verify --cert KSeF_Ksiegowosc.crt --key KSeF_Ksiegowosc.key -t ca.pem
```

Hasło do klucza pobierane jest **interaktywnie, ukrytym promptem**. Nie istnieje opcja podająca hasło w argumencie
(trafiłoby do historii powłoki i listy procesów).

| Opcja | Opis |
|---|---|
| `-c`, `--cert PLIK` | certyfikat (`.crt .cer .pem .der`; także `.p12`/`.pfx` – wtedy `--key` jest zbędne) |
| `-k`, `--key PLIK` | zaszyfrowany klucz prywatny (`.key`, `.pem`; PKCS#8 lub RSA/EC PEM/DER) |
| `--password-stdin` | hasło z pierwszej linii stdin (automatyzacja) |
| `--password-fd N` | hasło z deskryptora pliku `N` (automatyzacja) |
| `--json` | stabilny, wersjonowany JSON na stdout (`schema_version: "2"`) |
| `-v`, `--verbose` | wszystkie ustalenia kontroli, Key Usage, EKU, rozszerzenia |
| `--expected-type Authentication\|Offline` | niezgodny typ → `FAIL` |
| `-t`, `--trust-anchor PLIK\|KATALOG` | zaufane CA (można powtarzać) |
| `--no-default-trust` | nie ładuj domyślnego katalogu zaufania |
| `--online` | status w API KSeF (tylko odczyt; wymaga `--environment` i tokenu) |
| `-e`, `--environment TEST\|DEMO\|PROD` | środowisko API; brak wartości domyślnej |
| `--token-env NAZWA` | zmienna z tokenem dostępu (domyślnie `KSEF_ACCESS_TOKEN`) |
| `--at ISO-8601` | oceń ważność na podany moment (UTC), np. `2026-10-28T12:00:00Z` |

### Hasło w automatyzacji

```bash
# stdin (jedna linia; bez echa, bez wpisu w historii):
printf '%s\n' "$KEY_PASSWORD" | ksef-cert-verify verify --cert c.crt --key c.key -t ca.pem --password-stdin --json

# deskryptor pliku (np. z menedżera sekretów):
ksef-cert-verify verify --cert c.crt --key c.key -t ca.pem --password-fd 3 3< <(pass show ksef/key)
```

Hasło nigdy nie jest wypisywane na stdout/stderr ani umieszczane w JSON. Bez terminala i bez `--password-stdin` /
`--password-fd` kontrola klucza kończy się wynikiem `UNKNOWN` (exit `3`), a nie zawieszeniem. Gdy klucz **nie jest zaszyfrowany**,
hasło nie jest potrzebne – kontrola zwraca `WARNING` („klucz nie jest zaszyfrowany”).

### Co daje `VALID`

Wszystkie obowiązkowe kontrole `PASS`/`WARNING`: certyfikat, typ, daty, algorytmy/podpisy, zaufanie do wystawcy, profil KSeF,
**odszyfrowanie klucza**, **zgodność klucza z certyfikatem**. Brak klucza (`NOT_CHECKED`/`UNKNOWN`), błędne hasło (`FAIL`),
uszkodzony lub nieobsługiwany klucz (`FAIL`), klucz od innego certyfikatu (`FAIL`) – żaden z tych przypadków nie da `VALID`.

### Zaufane CA

Kolejno ładowane: katalog domyślny (`$KSEF_CERT_VERIFY_TRUST_DIR`, a gdy brak: `~/.config/ksef-cert-verify/trust` lub
`%APPDATA%\ksef-cert-verify\trust`) oraz wszystko z `--trust-anchor`. Kotwica = identyczny certyfikat (DER).

### Status online i automatyczne uwierzytelnienie

```bash
# certyfikat Authentication: program sam się uwierzytelni (XAdES), odbierze accessToken i zapyta o status
ksef-cert-verify verify --cert c.crt --key c.key -t ca.pem --online --environment test [--context-nip 1234563218]

# istniejący accessToken (JWT) – np. dla certyfikatu Offline, który nie może się uwierzytelnić:
export KSEF_ACCESS_TOKEN="<JWT>"
ksef-cert-verify verify --cert o.crt --key o.key --online --environment test
```

* `--environment` jest wymagane z `--online`; **PROD** wymaga `--confirm-prod` albo wpisania `PROD` w terminalu.
* Kontekst uwierzytelnienia (NIP): `--context-nip`, a gdy brak – NIP z certyfikatu; bez żadnego z nich: `AUTH_CONTEXT_REQUIRED`
  (program nie zgaduje).
* Zmienna `KSEF_ACCESS_TOKEN` (nazwa zmieniana przez `--token-env`) to **accessToken JWT**, nie token KSeF. JWT jest wstępnie
  sprawdzany (struktura, `exp`) przed wysłaniem; to nie dowód autentyczności.
* Certyfikat **Offline** nie uwierzytelnia się w KSeF (`AUTH_NOT_APPLICABLE`) – status wymaga JWT z osobnego uwierzytelnienia.
* Tokeny nie są wypisywane ani zapisywane. Wyniki online nie zmieniają wyników LOCAL/TRUST.
* Statusy: `Active | Blocked | Revoked | Expired | UNKNOWN | NOT_CHECKED`. `Active` tylko, gdy numer seryjny **i** metadane
  (typ, daty, commonName, identyfikator) zgadzają się z certyfikatem; inaczej `UNKNOWN`.

### Kody wyjścia

| Kod | Znaczenie |
|---|---|
| 0 | `VALID` |
| 1 | `INVALID` (w tym uszkodzony certyfikat, błędne hasło do klucza, niezgodna para, uszkodzony/nieobsługiwany klucz) |
| 2 | błąd wykonania/argumentów (brak pliku certyfikatu lub klucza, brak `--key`, brak tokenu, zły `--expected-type`) |
| 3 | brak `INVALID`, ale co najmniej jedna kontrola nieustalona (brak hasła, brak zaufanych CA, brak ogniwa łańcucha…) |

### JSON (`schema_version: "2"`)

Zmiany względem wersji 1: nowe kontrole `key_decrypt` i `key_match` w `checks`; bez klucza wynik nigdy nie jest `VALID`.
Pola nie są usuwane ani przemianowywane w obrębie wersji; zmiana łamiąca podbija `schema_version`.

```json
{
  "schema_version": "2",
  "tool": {"name": "ksef-cert-verify", "version": "1.0.1"},
  "generated_at": "2026-10-28T12:00:00Z",
  "scope": {"offline": true, "online_requested": false, "online_environment": null,
            "trust_anchors_configured": 1, "expected_type": null},
  "files": [{
    "file": "KSeF_Ksiegowosc.crt", "format": "PEM", "result": "VALID", "error": null, "notes": [],
    "certificates": [{
      "type": "Authentication", "result": "VALID", "online_status": "NOT_CHECKED",
      "checks": {"parsing": {}, "validity": {}, "crypto": {}, "trust": {}, "classification": {},
                 "profile": {}, "online": {}, "key_decrypt": {"status": "PASS"}, "key_match": {"status": "PASS"}}
    }]
  }],
  "exit_code": 0
}
```

Każdy certyfikat ma też sekcje `groups` (`local`/`trust`/`online`), `summary` (`CERTIFICATE_VALIDATION`, `PRIVATE_KEY_DECRYPTION`, `KEY_PAIR_MATCH`, `SIGNATURE_VERIFICATION`, `KSEF_PROFILE_VALIDATION`, `KSEF_ONLINE_STATUS`, `KSEF_AUTHENTICATION_RESULT`, `LOCAL_KEYSET_RESULT`, `TRUST_RESULT`, `LOCAL_RESULT`) i `operations` (wynik uwierzytelnienia / KODU II – bez tokenów). Statusy kontroli: `PASS | FAIL | WARNING | UNKNOWN | NOT_CHECKED`. Daty w JSON są w UTC (`Z`), w tabeli – lokalne.

## `inspect`

`ksef-cert-verify inspect PLIK [--json]` wypisuje publiczne dane (Subject, Issuer, serial, daty, SHA-256, algorytmy, Key Usage,
EKU, Basic Constraints, SKI/AKI, NIP/PESEL) i zaczyna się ostrzeżeniem, że to **nie jest weryfikacja** – bez klucza, zaufania
i statusu. JSON zawiera `"verification": false`. Plik PKCS#12 wymaga hasła (`--password-stdin` jak wyżej nie dotyczy `inspect` –
użyj ukrytego promptu).

## `gui`

`ksef-cert-verify gui` uruchamia interfejs. `gui --selftest` generuje syntetyczną parę, przeprowadza prawdziwą weryfikację
w oknie Qt (headless, jeśli brak ekranu) i zwraca `0` przy sukcesie – używane do testów zainstalowanych pakietów.

## `test-signature`

`ksef-cert-verify test-signature --cert C --key K [--json]` – podpisuje 32 losowe bajty (CSPRNG) kluczem prywatnym i weryfikuje
kluczem z certyfikatu (RSA 2048: RSASSA-PSS/SHA-256; EC P-256: ECDSA/SHA-256). **To nie jest podpis XAdES ani KODU II.**
Wynik: `SIGNATURE_VALID` (exit 0), `SIGNATURE_INVALID` / `KEY_DECRYPTION_FAILED` / `KEY_CERT_MISMATCH` / `UNSUPPORTED_ALGORITHM`
(exit 1), `NOT_CHECKED` (brak hasła, exit 3).

## `test-auth`

`ksef-cert-verify test-auth --cert C --key K [--environment TEST|DEMO|PROD] [--confirm-prod] [--context-nip N]
[--subject-identifier certificateSubject|certificateFingerprint] [--verify-chain/--no-verify-chain] [--json]`

Przebieg wg `uwierzytelnianie.md`: `POST /auth/challenge` → `AuthTokenRequest` (schemat 2.0) → podpis XAdES-BES →
`POST /auth/xades-signature` → `GET /auth/{referenceNumber}` do skutku → `POST /auth/token/redeem`. Rozdziela **uwierzytelnienie**
(KSeF zaakceptował certyfikat) i **autoryzację** (uprawnienia). Kody: `AUTH_SUCCESS`, `AUTH_NO_PERMISSIONS` (415 – nie dowodzi
złej pary kluczy), `AUTH_CERT_REJECTED` (460/21115), `AUTH_CONTEXT_INVALID`, `AUTH_TLS`, `AUTH_TIMEOUT`, `AUTH_NETWORK`,
`AUTH_IN_PROGRESS_TIMEOUT`… Exit: 0 sukces · 1 odrzucenie · 2 błąd/PROD niepotwierdzony/Offline · 3 nieustalony.
Domyślne środowisko: TEST.

## `test-kod2`

`ksef-cert-verify test-kod2 --cert O --key K [--environment TEST] [--context-nip N] [--seller-nip N] [--json]` – buduje link KODU II wg
`kody-qr.md` (`https://qr-test.ksef.mf.gov.pl/certificate/<typ>/<kontekst>/<NIP sprzedawcy>/<serial>/<SHA-256 faktury>/<podpis>`),
podpisuje ścieżkę (bez `https://` i końcowego `/`) i weryfikuje lokalnie; sprawdza też, że zmiana danych unieważnia podpis. Dane są
**syntetyczne**, link nie jest nigdzie wysyłany ani otwierany. Certyfikat Authentication → `KOD2_NOT_APPLICABLE` (exit 2).

Opcje: `--invoice F.xml` (link zawiera SHA-256 pliku faktury; NIP sprzedawcy z `Podmiot1`), `--context-type`, `--ec-format p1363|der`
(oba kodowania ECDSA z dokumentacji MF są weryfikowane), `--open` (świadome otwarcie linku w przeglądarce, tylko oficjalny host QR).
Bez `--invoice` to **syntetyczny test kryptograficzny**. Wynik rozdziela status w rejestrze (`registry_status`) od uprawnień do
wystawienia faktury (`issuing_authority: NOT_VERIFIED`): MF nie udostępnia udokumentowanego, maszynowego interfejsu weryfikacji KODU II
(brak endpointu w OpenAPI), więc program nie parsuje HTML i nie deklaruje potwierdzenia. Otwarcie strony ani HTTP 200 nie dowodzi
autentyczności wystawcy.


## `trust`

`trust list` pokazuje CA z katalogu zaufania (odcisk SHA-256, ważność); `trust add PLIK` wypisuje Subject i odcisk i pyta o
potwierdzenie (`--yes` po zweryfikowaniu odcisku innym kanałem; bez terminala wymagane `--yes`); dodaje wyłącznie certyfikaty
z `BasicConstraints CA=TRUE`; `trust remove PREFIKS-ODCISKU`. Nic nie jest pobierane z internetu.
