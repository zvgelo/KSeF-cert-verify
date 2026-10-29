# GUI – KSeF CertVerify

Uruchomienie: `ksef-cert-verify gui`, `ksef-cert-verify-gui`, skrót **KSeF CertVerify** w menu systemowym albo AppImage.

| Jasny | Ciemny |
|---|---|
| ![jasny](img/gui-light.png) | ![ciemny](img/gui-dark.png) |

Projekt wizualny (skill `frontend-design`): tokeny kolorów, odstępów i typografii w `gui/theme.py` (QSS stosowany do całej aplikacji,
więc także okna dialogowe), jednolity zestaw ikon SVG w `gui/assets/icons` (check-circle, shield-check, alert-triangle, cloud-off,
x-circle i ikony przycisków; kolory z aktualnego motywu, ostre na HiDPI), logo w `packaging/assets`.

## Dane wejściowe (lewy panel)

* **Certyfikat** (`.crt .cer .pem .der`, także `.p12/.pfx`) – po wskazaniu program rozpoznaje typ (znacznik „Typ: Authentication/Offline”).
* **Klucz prywatny** (`.key`/`.pem`) i **Hasło do klucza** (ukryte; „oko” pokazuje/ukrywa, „schowek” wkleja). Hasło nie jest zapisywane
  i jest czyszczone po każdej weryfikacji. Przeciągnięcie plików na okno uzupełnia pola.
* **Zaufane CA…** – dodawanie CA wymaga potwierdzenia odcisku SHA-256 i certyfikatu z `CA=TRUE`.

## Weryfikacja

**Weryfikuj** zawsze wykonuje weryfikację lokalną (certyfikat, ważność, klucz i hasło, dopasowanie pary, test podpisu, typ, profil KSeF,
zaufanie PKI w zakresie dostępnych danych) – bez możliwości jej wyłączenia i bez sieci.

**Sprawdź również online w KSeF** (domyślnie wyłączone – brak żądań HTTP). Po zaznaczeniu: **Środowisko** TEST (domyślnie) / DEMO / PROD
(PROD wymaga wpisania słowa `PROD`), **Kontekst (NIP)** (domyślnie NIP z certyfikatu). Authentication: automatyczne uwierzytelnienie
XAdES i status w rejestrze. Offline: bez uwierzytelniania certyfikatem Offline – status w rejestrze wymaga uprawnionego JWT. W sekcji
**Zaawansowane**: **Użyj istniejącego tokena JWT** (wstępna kontrola struktury i terminu; autentyczność weryfikuje dopiero API).

**Weryfikacja KODU II** (rozwijana, tylko dla certyfikatu Offline): opcjonalna faktura XML, kontekst, NIP sprzedawcy, środowisko, link
i **Otwórz w KSeF** (świadoma akcja, tylko oficjalny host QR). Bez faktury – syntetyczny test kryptograficzny. Uprawnień wystawcy nie
weryfikujemy (MF nie udostępnia maszynowego interfejsu) – ocenia je strona KSeF po otwarciu linku.

## Wynik (prawy panel)

Trzy karty **LOCAL / TRUST / ONLINE** z ikoną, słowem statusu i krótkim powodem; poniżej sekcje z kontrolami (ikona + słowo + opis).
Nigdy sam kolor: ✓ OK, ✗ BŁĄD, ! UWAGA, ? NIEUSTALONE, – NIE SPRAWDZONO są zawsze podane tekstem. Wynik online nie zmienia kart LOCAL i TRUST.
Pod kartami: „Zestaw certyfikatu i klucza – …”, „Zaufanie do certyfikatu – …”, „Pełna walidacja: …”.
**Szczegóły**, **Eksport JSON** (równoważny `verify --json`), **Kopiuj do schowka**, **Motyw** (systemowy/jasny/ciemny, zapamiętywany),
**O programie** (nazwa, opis, wersja z metadanych aplikacji – ta sama co w CLI i instalatorach, licencja oraz odnośnik do repozytorium GitHub otwierany w domyślnej przeglądarce; adres jest stałą z `pyproject.toml`, a nie odczytem lokalnego `git remote`). Teksty z certyfikatów i nazw plików są wyświetlane jako zwykły tekst (bez HTML), bez znaków sterujących i bidi.
High DPI: skalowanie ułamkowe Qt 6; ikona okna i paska zadań (Windows: własne AppUserModelID).
