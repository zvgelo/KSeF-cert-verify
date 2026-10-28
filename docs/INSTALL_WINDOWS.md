# Instalacja – Windows 10/11 x64

## Instalator EXE (zalecane)

1. Pobierz `KSeF-CertVerify-<wersja>-win-x64-setup.exe` i sprawdź jego sumę SHA-256 względem pliku `SHA256SUMS`:
   `Get-FileHash .\KSeF-cert-verify-<wersja>-windows-x64-setup.exe -Algorithm SHA256`.
2. Uruchom instalator. Domyślnie instaluje **dla bieżącego użytkownika, bez uprawnień administratora**
   (`%LOCALAPPDATA%\Programs\KSeF CertVerify`). W oknie uprawnień można wybrać instalację dla wszystkich użytkowników
   (`Program Files`, wymaga administratora). Można zmienić katalog instalacji.
3. Zadania opcjonalne: skrót na pulpicie, **dodanie wiersza poleceń do PATH** (HKCU przy instalacji per-user, HKLM przy systemowej).
4. Instalator tworzy skrót w menu Start, wpis w „Aplikacje i funkcje” (deinstalator) i instaluje:
   `ksef-cert-verify-gui.exe` (GUI) oraz `ksef-cert-verify.exe` (CLI). Python nie jest potrzebny.

```powershell
& "$env:LOCALAPPDATA\Programs\KSeF CertVerify\ksef-cert-verify.exe" --version
ksef-cert-verify verify --cert KSeF_Ksiegowosc.crt --key KSeF_Ksiegowosc.key -t ca.pem   # po dodaniu do PATH (nowa konsola)
```

### Aktualizacja

Uruchom nowszy instalator – ma ten sam stały identyfikator aplikacji (`AppId`), więc **aktualizuje** istniejącą instalację w tym
samym katalogu (uruchomiona aplikacja jest zamykana). Ustawienia (motyw, zaufane CA w `%APPDATA%\ksef-cert-verify`) są zachowywane.

### Instalacja cicha / automatyzacja

```powershell
.\KSeF-cert-verify-<wersja>-windows-x64-setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CURRENTUSER /TASKS="addtopath"
```

### Odinstalowanie

„Ustawienia → Aplikacje → KSeF CertVerify → Odinstaluj”, albo cicho: `"<katalog>\unins000.exe" /VERYSILENT`.
Usuwa pliki, skróty i wpis w PATH. Pliki użytkownika (zaufane CA, ustawienia) zostają w `%APPDATA%\ksef-cert-verify`.

### Podpis cyfrowy i SmartScreen

Instalator i pliki wykonywalne **nie są podpisane cyfrowo**. Windows SmartScreen może wyświetlić ostrzeżenie „Nieznany wydawca”
(„Więcej informacji → Uruchom mimo to”). Program nie wyłącza SmartScreen ani innych zabezpieczeń. Zweryfikuj SHA-256 przed
uruchomieniem. Podpisanie (certyfikat Authenticode / usługa podpisywania) wymaga dostępu do certyfikatu wydawcy i nie jest
częścią tego repozytorium.

## Portable (bez instalacji)

`KSeF-CertVerify-<wersja>-win-x64-portable.exe` to **jeden plik GUI** – uruchom go dwuklikiem z dowolnego katalogu. Nie wymaga instalacji,
Pythona ani uprawnień administratora i nie zapisuje niczego w rejestrze.

* Przy każdym starcie PyInstaller rozpakowuje program do `%TEMP%\_MEIxxxxx` i usuwa ten katalog po zamknięciu aplikacji. Start trwa dłużej
  niż w wersji Setup (kilka sekund). Jeśli proces zostanie zabity, katalog `_MEI*` może zostać – można go bezpiecznie usunąć.
* Aplikacja nie zapisuje tam kluczy ani haseł (odszyfrowany klucz istnieje tylko w pamięci procesu).
* Niepodpisane pliki onefile bywają oznaczane przez SmartScreen/antywirusy jako „nieznane” – sprawdź SHA-256 przed uruchomieniem.
* Samodzielne CLI: `ksef-cert-verify-<wersja>-win-x64-cli.exe` (jeden plik konsolowy, bez GUI): `.\ksef-cert-verify-<wersja>-win-x64-cli.exe verify --cert c.crt --key c.key`.

Setup czy Portable: **Setup** – menu Start, opcjonalny PATH, odinstalowanie, szybszy start; **Portable** – bez instalacji, do przenoszenia.

## pip

```powershell
py -3.12 -m venv $HOME\.venvs\ksef
& $HOME\.venvs\ksef\Scripts\Activate.ps1
pip install ".[gui]"
ksef-cert-verify gui
```

Konsola PowerShell/Windows Terminal obsługuje UTF-8; w CMD ustaw `chcp 65001` (program przełącza stdout/stderr na UTF-8).

## Rozwiązywanie problemów

| Objaw | Rozwiązanie |
|---|---|
| ostrzeżenie SmartScreen | oczekiwane dla niepodpisanego instalatora – sprawdź SHA-256 |
| `ksef-cert-verify` nie jest rozpoznawane | nie wybrano zadania PATH albo konsola otwarta przed instalacją – otwórz nową konsolę lub użyj pełnej ścieżki |
| brak `VCRUNTIME140.dll` | zainstaluj „Microsoft Visual C++ Redistributable (x64)” |
| GUI nie startuje | uruchom `ksef-cert-verify.exe gui --selftest` w konsoli i sprawdź komunikat |

## Budowanie własnego instalatora

Na Windows: `pip install -e ".[dev]"`, zainstaluj Inno Setup 6, uruchom `packaging\windows\build.ps1`.
Szczegóły i status: [PACKAGING.md](PACKAGING.md).
