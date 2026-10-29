<#
.SYNOPSIS
  Test E2E instalatora Windows: cicha instalacja → CLI → pełna weryfikacja (cert + zaszyfrowany klucz) → GUI selftest
  → skrót menu Start → PATH → odinstalowanie → sprawdzenie usunięcia plików. Dane syntetyczne.
.NOTES
  Uruchamiaj na Windows (np. runner windows-latest). Wymaga Pythona tylko do wygenerowania syntetycznej pary testowej.
#>
param(
    [Parameter(Mandatory)][string]$Setup,
    # Opcjonalnie: PRAWDZIWY instalator poprzedniej wersji -> test aktualizacji "w miejscu" (stara wersja, potem nowa na niej).
    [string]$OldSetup
)
$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$work = Join-Path ([IO.Path]::GetTempPath()) ("ksef-inst-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$app = Join-Path $work "app"
$fix = Join-Path $work "fix"
New-Item -ItemType Directory -Force $work, $fix | Out-Null
$script:fail = 0
function Check($ok, $name) { if ($ok) { Write-Host "PASS: $name" } else { Write-Host "FAIL: $name"; $script:fail++ } }

python "$root\scripts\make_fixture_pair.py" $fix
$log = Join-Path $work "install.log"

function Uninstall-Entries {
    # Wpisy "Aplikacje i funkcje" tego programu (HKCU + HKLM, 64/32 bit); po aktualizacji ma być dokładnie jeden.
    $keys = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    @($keys | Where-Object { Test-Path $_ } | ForEach-Object { Get-ChildItem $_ } |
        Where-Object { $_.PSChildName -like "{B6D7C3A2-5E1F-4B8A-9C34-7A2E6F1D0C95}*" })
}
$lnkStart = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\KSeF CertVerify.lnk"
$setupArgs = "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/CURRENTUSER", "/TASKS=addtopath"

if ($OldSetup) {
    # --- A. poprzednia wersja (prawdziwy, wcześniej wydany instalator) ---
    $o = Start-Process -FilePath $OldSetup -Wait -PassThru -ArgumentList ($setupArgs + "/DIR=`"$app`"")
    Check ($o.ExitCode -eq 0) "stara wersja: instalacja (exit $($o.ExitCode))"
    $oldVer = (& "$app\ksef-cert-verify.exe" --version) -join ""
    Write-Host "Stara wersja: $oldVer"
    Check ((Uninstall-Entries).Count -eq 1) "stara wersja: jeden wpis na liście programów"
    # plik spoza nowej wersji: musi zniknąć po aktualizacji (czyszczenie pozostałości)
    New-Item -ItemType Directory -Force "$app\_internal" | Out-Null
    Set-Content "$app\_internal\stale_from_old_version.txt" "stary plik"
    Set-Content "$app\ksef-cert-verify-user-marker.txt" "plik użytkownika obok programu"
}

# 1. cicha instalacja per-user z zadaniem PATH (przy -OldSetup: AKTUALIZACJA istniejącej instalacji, bez /DIR – katalog ma zostać zapamiętany)
$dirArg = if ($OldSetup) { @() } else { @("/DIR=`"$app`"") }
$p = Start-Process -FilePath $Setup -Wait -PassThru -ArgumentList ($setupArgs + $dirArg + "/LOG=`"$log`"")
Check ($p.ExitCode -eq 0) "instalator /VERYSILENT (exit $($p.ExitCode))"
Check (Test-Path "$app\ksef-cert-verify.exe") "ksef-cert-verify.exe zainstalowany"
Check (Test-Path "$app\ksef-cert-verify-gui.exe") "ksef-cert-verify-gui.exe zainstalowany"
Check (Test-Path "$app\unins000.exe") "deinstalator obecny"

if ($OldSetup) {
    $newVer = (& "$app\ksef-cert-verify.exe" --version) -join ""
    Check ($newVer -ne $oldVer) "aktualizacja: wersja CLI zmieniona ($oldVer -> $newVer)"
    Check (-not (Test-Path "$app\_internal\stale_from_old_version.txt")) "aktualizacja: usunięto pozostałości po starej wersji"
    Check (Test-Path "$app\ksef-cert-verify-user-marker.txt") "aktualizacja: plik użytkownika nietknięty"
    Check ((Uninstall-Entries).Count -eq 1) "aktualizacja: dokładnie jeden wpis na liście programów"
    Check (@(Get-ChildItem (Split-Path $lnkStart) -Filter "KSeF CertVerify*.lnk").Count -eq 1) "aktualizacja: jeden skrót w menu Start"
    $guiVer = (Get-Item "$app\ksef-cert-verify-gui.exe").VersionInfo.ProductVersion
    Check ($newVer -eq "ksef-cert-verify $guiVer") "wersja GUI (metadane EXE) = wersja CLI ($guiVer)"
}

# 2. CLI
$ver = & "$app\ksef-cert-verify.exe" --version
Check ($ver -match "^ksef-cert-verify \d+\.\d+") "CLI --version: $ver"
$pw = Get-Content "$fix\password.txt" -Raw
$json = $pw | & "$app\ksef-cert-verify.exe" verify --cert "$fix\KSeF_Ksiegowosc.crt" --key "$fix\KSeF_Ksiegowosc.key" -t "$fix\ca.pem" --password-stdin --json
Check (($LASTEXITCODE -eq 0) -and ($json -match '"result": "VALID"')) "CLI pełna weryfikacja (exit 0, VALID)"
"zle-haslo" | & "$app\ksef-cert-verify.exe" verify --cert "$fix\KSeF_Ksiegowosc.crt" --key "$fix\KSeF_Ksiegowosc.key" -t "$fix\ca.pem" --password-stdin --json | Out-Null
Check ($LASTEXITCODE -eq 1) "CLI błędne hasło → exit 1"

# 3. GUI (prawdziwe okno Qt na pulpicie runnera)
$g = Start-Process -FilePath "$app\ksef-cert-verify-gui.exe" -ArgumentList "--selftest" -Wait -PassThru
Check ($g.ExitCode -eq 0) "GUI --selftest (exit $($g.ExitCode))"
# GUI jest aplikacją okienkową – selftest wypisuje na stdout tylko przy konsoli; liczy się kod wyjścia.
& "$app\ksef-cert-verify.exe" gui --selftest | Out-Null
Check ($LASTEXITCODE -eq 0) "CLI: gui --selftest"

# 4. skrót menu Start i PATH
$lnk = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\KSeF CertVerify.lnk"
Check (Test-Path $lnk) "skrót w menu Start"
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
Check ($userPath -split ";" -contains $app) "katalog instalacji dodany do PATH (użytkownika)"

# 5. odinstalowanie
$u = Start-Process -FilePath "$app\unins000.exe" -ArgumentList "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART" -Wait -PassThru
Start-Sleep -Seconds 3
Check ($u.ExitCode -eq 0) "deinstalator /VERYSILENT (exit $($u.ExitCode))"
Check (-not (Test-Path "$app\ksef-cert-verify.exe")) "pliki usunięte po odinstalowaniu"
Check (-not (Test-Path $lnk)) "skrót menu Start usunięty"
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
Check (-not ($userPath -split ";" -contains $app)) "wpis PATH usunięty"

if ($OldSetup) {
    Check ((Uninstall-Entries).Count -eq 0) "po odinstalowaniu: brak wpisu na liście programów"
    Check (-not (Test-Path "$app\_internal")) "po odinstalowaniu: brak katalogu _internal"
}
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
if ($script:fail) { Write-Host "BŁĘDY: $script:fail"; exit 1 }
Write-Host "WSZYSTKIE TESTY INSTALATORA ZALICZONE"
