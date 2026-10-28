<#
.SYNOPSIS
  Test E2E instalatora Windows: cicha instalacja → CLI → pełna weryfikacja (cert + zaszyfrowany klucz) → GUI selftest
  → skrót menu Start → PATH → odinstalowanie → sprawdzenie usunięcia plików. Dane syntetyczne.
.NOTES
  Uruchamiaj na Windows (np. runner windows-latest). Wymaga Pythona tylko do wygenerowania syntetycznej pary testowej.
#>
param([Parameter(Mandatory)][string]$Setup)
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

# 1. cicha instalacja per-user z zadaniem PATH
$p = Start-Process -FilePath $Setup -Wait -PassThru -ArgumentList "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/CURRENTUSER", "/DIR=`"$app`"", "/TASKS=addtopath", "/LOG=`"$log`""
Check ($p.ExitCode -eq 0) "instalator /VERYSILENT (exit $($p.ExitCode))"
Check (Test-Path "$app\ksef-cert-verify.exe") "ksef-cert-verify.exe zainstalowany"
Check (Test-Path "$app\ksef-cert-verify-gui.exe") "ksef-cert-verify-gui.exe zainstalowany"
Check (Test-Path "$app\unins000.exe") "deinstalator obecny"

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

Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
if ($script:fail) { Write-Host "BŁĘDY: $script:fail"; exit 1 }
Write-Host "WSZYSTKIE TESTY INSTALATORA ZALICZONE"
