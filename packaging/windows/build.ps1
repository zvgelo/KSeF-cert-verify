<#
.SYNOPSIS
  KSeF CertVerify - natywny build Windows: CLI + GUI (PyInstaller) -> instalator EXE (Inno Setup 6) -> SHA-256.

.DESCRIPTION
  Uruchom NA WINDOWS 10/11 x64 (PyInstaller nie buduje miedzyplatformowo). Skrypt konczy sie bledem (exit 1), jesli
  KTORYKOLWIEK obowiazkowy krok sie nie powiedzie. Kroki:
    Wynik: instalator Setup, Portable (jeden plik GUI) i samodzielne CLI - wszystko z jednego uruchomienia.
    1. sprawdzenie narzedzi (Python 3.11+ x64, Inno Setup 6)
    2. przygotowanie srodowiska Python (.venv-build)
    3. instalacja zaleznosci
    4. testy (pytest)
    5. budowa CLI i GUI (PyInstaller: onedir dla instalatora, onefile portable GUI, onefile CLI; ikona i metadane wersji)
    6. testy zbudowanych plikow EXE (onedir, portable, CLI - prawdziwe procesy)
    7. generowanie instalatora (Inno Setup)
    8. SHA-256
    9. lokalizacja artefaktow

.PARAMETER SkipTests
  Pomija krok 4 (np. gdy testy uruchomiono osobno). Krok jest wtedy oznaczony jako POMINIETY - nie jako zaliczony.
.PARAMETER UseCurrentPython
  Nie tworzy .venv-build; uzywa Pythona z PATH (np. w CI po `pip install`). Krok 3 nadal instaluje zaleznosci.
.PARAMETER OldSetup
  Z -TestInstaller: sciezka do instalatora POPRZEDNIEJ wersji (prawdziwy plik z wydania) - dodatkowo test aktualizacji w miejscu.
.PARAMETER TestInstaller
  Po zbudowaniu instalatora wykonuje test E2E: cicha instalacja -> CLI/GUI -> odinstalowanie (packaging\windows\test-installer.ps1).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\packaging\windows\build.ps1 -TestInstaller
#>
[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$UseCurrentPython,
    [switch]$TestInstaller,
    [string]$OldSetup,
    [switch]$AllowNetworkPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$global:LASTEXITCODE = 0

$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $root
$script:step = 0
$script:skipped = @()

function Step([string]$title) {
    $script:step++
    Write-Host ""
    Write-Host "=== [$($script:step)/9] $title ===" -ForegroundColor Cyan
}

function Run([string]$exe, [string[]]$arguments) {
    & $exe @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Polecenie nie powiodlo sie (exit $LASTEXITCODE): $exe $($arguments -join ' ')"
    }
}

function Find-Python {
    $candidates = @(
        @{ Exe = "py"; Pre = @("-3.13") }, @{ Exe = "py"; Pre = @("-3.12") }, @{ Exe = "py"; Pre = @("-3.11") },
        @{ Exe = "python"; Pre = @() }, @{ Exe = "python3"; Pre = @() }
    )
    foreach ($c in $candidates) {
        if (-not (Get-Command $c.Exe -ErrorAction SilentlyContinue)) { continue }
        try {
            $code = "import sys,struct;print('%d.%d %d' % (sys.version_info[0], sys.version_info[1], struct.calcsize('P')*8))"
            $out = & $c.Exe @($c.Pre + @("-c", $code)) 2>$null
            if ($LASTEXITCODE -ne 0) { continue }
            $p = "$out".Trim().Split(" ")
            if ([version]$p[0] -ge [version]"3.11" -and $p[1] -eq "64") { return $c }
        } catch { continue }
    }
    return $null
}

function Find-Iscc {
    $paths = @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
    )
    foreach ($p in $paths) { if ($p -and (Test-Path $p)) { return $p } }
    $cmd = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

try {
    # ---------------------------------------------------------------- 1. narzedzia
    Step "Sprawdzenie narzedzi"
    if ($env:OS -ne "Windows_NT") { throw "Ten skrypt dziala tylko na Windows (PyInstaller nie buduje miedzyplatformowo)." }
    if (-not [Environment]::Is64BitOperatingSystem) { throw "Wymagany jest Windows x64." }
    # Budowa na dysku sieciowym/wspoldzielonym (UNC, mapowany dysk, VMware/VirtualBox share) psuje PyInstaller i Inno Setup
    # (brak uprawnien do kasowania plikow, sciezki ze spacjami). Wymagamy lokalnego dysku.
    $driveRoot = [IO.Path]::GetPathRoot($root).TrimEnd("\").TrimEnd(":")
    $drive = if ($driveRoot.Length -eq 1) { Get-PSDrive -Name $driveRoot -ErrorAction SilentlyContinue } else { $null }
    $isNetwork = $root.StartsWith("\\") -or ($drive -and $drive.DisplayRoot -like "\\*")
    if ($isNetwork -and -not $AllowNetworkPath) {
        throw "Repozytorium lezy na dysku sieciowym/wspoldzielonym ($root). Skopiuj je na lokalny dysk, np.: robocopy `"$root`" C:\ksef\KSeF-cert-verify /E /XD .venv .venv-build build dist .git .local   (potem uruchom build.ps1 stamtad; -AllowNetworkPath omija te kontrole)."
    }
    $pyInfo = Find-Python
    if (-not $pyInfo) { throw "Nie znaleziono Pythona 3.11+ (64-bit). Zainstaluj z https://www.python.org/downloads/ (opcja 'Add python.exe to PATH' lub py launcher)." }
    $iscc = Find-Iscc
    if (-not $iscc) { throw "Nie znaleziono Inno Setup 6 (ISCC.exe). Zainstaluj: https://jrsoftware.org/isdl.php (lub: choco install innosetup)." }
    foreach ($f in @("packaging\windows\KSeF-cert-verify.iss", "packaging\ksef-cert-verify.spec", "scripts\build.py", "packaging\assets\icon.ico", "LICENSE")) {
        if (-not (Test-Path $f)) { throw "Brak wymaganego pliku w repozytorium: $f" }
    }
    $pyDesc = ($pyInfo.Pre + @()) -join " "
    Write-Host "Python : $($pyInfo.Exe) $pyDesc"
    Write-Host "ISCC   : $iscc"

    # ---------------------------------------------------------------- 2. srodowisko
    Step "Przygotowanie srodowiska Python"
    if ($UseCurrentPython) {
        $py = $pyInfo.Exe
        $pyPre = $pyInfo.Pre
        Write-Host "Uzywam biezacego Pythona (-UseCurrentPython)."
    } else {
        $venv = Join-Path $root ".venv-build"
        if (-not (Test-Path (Join-Path $venv "Scripts\python.exe"))) {
            Run $pyInfo.Exe ($pyInfo.Pre + @("-m", "venv", $venv))
        }
        $py = Join-Path $venv "Scripts\python.exe"
        $pyPre = @()
        Write-Host "Srodowisko: $venv"
    }
    Run $py ($pyPre + @("-m", "pip", "install", "--upgrade", "pip"))

    # ---------------------------------------------------------------- 3. zaleznosci
    Step "Instalacja zaleznosci"
    Run $py ($pyPre + @("-m", "pip", "install", "-e", ".[dev]"))
    $version = (& $py @($pyPre + @("-c", "import sys; sys.path.insert(0,'src'); from ksef_cert_verify import __version__ as v; print(v)"))).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $version) { throw "Nie udalo sie odczytac wersji projektu." }
    Write-Host "Wersja projektu: $version"

    # ---------------------------------------------------------------- 4. testy
    Step "Testy (pytest)"
    if ($SkipTests) {
        Write-Host "POMINIETO (-SkipTests) - testy NIE zostaly uruchomione." -ForegroundColor Yellow
        $script:skipped += "testy pytest"
    } else {
        $env:QT_QPA_PLATFORM = "offscreen"
        Run $py ($pyPre + @("-m", "pytest", "-q", "-rs", "-p", "no:cacheprovider"))
    }

    # ---------------------------------------------------------------- 5. budowa CLI + GUI
    Step "Budowa CLI i GUI (PyInstaller)"
    New-Item -ItemType Directory -Force (Join-Path $root "build") | Out-Null
    $parts = @($version.Split("-")[0].Split("."))
    while ($parts.Count -lt 4) { $parts += "0" }
    $tuple = ($parts[0..3] -join ", ")
    $dotted = ($parts[0..3] -join ".")
    $versionFile = Join-Path $root "build\version_info.txt"
    $versionText = @"
VSVersionInfo(
  ffi=FixedFileInfo(filevers=($tuple), prodvers=($tuple), mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'KSeF CertVerify contributors'),
      StringStruct('FileDescription', 'KSeF CertVerify - Weryfikacja certyfikatow KSeF'),
      StringStruct('FileVersion', '$dotted'),
      StringStruct('InternalName', 'ksef-cert-verify'),
      StringStruct('LegalCopyright', 'MIT License'),
      StringStruct('OriginalFilename', 'ksef-cert-verify.exe'),
      StringStruct('ProductName', 'KSeF CertVerify'),
      StringStruct('ProductVersion', '$version')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"@
    Set-Content -Path $versionFile -Value $versionText -Encoding ascii
    $env:KSEF_VERSION_FILE = $versionFile
    Run $py ($pyPre + @("scripts\build.py", "--target", "all"))
    $portableExe = Join-Path $root "dist\KSeF-CertVerify-$version-win-x64-portable.exe"
    $cliOnefile = Join-Path $root "dist\ksef-cert-verify-$version-win-x64-cli.exe"
    foreach ($exe in @($portableExe, $cliOnefile)) { if (-not (Test-Path $exe)) { throw "PyInstaller nie utworzyl: $exe" } }
    Write-Host "Portable: $portableExe"
    Write-Host "CLI (1 plik): $cliOnefile"
    $dist = Join-Path $root "dist\ksef-cert-verify"
    $cliExe = Join-Path $dist "ksef-cert-verify.exe"
    $guiExe = Join-Path $dist "ksef-cert-verify-gui.exe"
    foreach ($exe in @($cliExe, $guiExe)) { if (-not (Test-Path $exe)) { throw "PyInstaller nie utworzyl: $exe" } }
    Write-Host "CLI: $cliExe"
    Write-Host "GUI: $guiExe"

    # ---------------------------------------------------------------- 6. testy EXE
    Step "Testy zbudowanych plikow EXE"
    $vi = (Get-Item $cliExe).VersionInfo
    if ($vi.ProductName -ne "KSeF CertVerify") { throw "Metadane EXE: ProductName='$($vi.ProductName)' (oczekiwano 'KSeF CertVerify')" }
    if ($vi.ProductVersion -ne $version) { throw "Metadane EXE: ProductVersion='$($vi.ProductVersion)' (oczekiwano '$version')" }
    Write-Host "PASS: metadane EXE ($($vi.ProductName) $($vi.ProductVersion))"
    $ver = (& $cliExe --version) -join ""
    if ($LASTEXITCODE -ne 0 -or $ver.Trim() -ne "ksef-cert-verify $version") { throw "CLI --version: '$ver' (oczekiwano 'ksef-cert-verify $version')" }
    Write-Host "PASS: CLI --version = $ver"
    $fix = Join-Path ([IO.Path]::GetTempPath()) ("ksef-build-fix-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
    Run $py ($pyPre + @("scripts\make_fixture_pair.py", $fix))
    $pw = Get-Content (Join-Path $fix "password.txt") -Raw
    $json = $pw | & $cliExe verify --cert (Join-Path $fix "KSeF_Ksiegowosc.crt") --key (Join-Path $fix "KSeF_Ksiegowosc.key") -t (Join-Path $fix "ca.pem") --password-stdin --json
    if ($LASTEXITCODE -ne 0 -or (($json -join "`n") -notmatch '"result": "VALID"')) { throw "CLI: pelna weryfikacja pary nie zwrocila VALID (exit $LASTEXITCODE)" }
    Write-Host "PASS: CLI pelna weryfikacja (exit 0, VALID)"
    "zle-haslo" | & $cliExe verify --cert (Join-Path $fix "KSeF_Ksiegowosc.crt") --key (Join-Path $fix "KSeF_Ksiegowosc.key") -t (Join-Path $fix "ca.pem") --password-stdin --json | Out-Null
    if ($LASTEXITCODE -ne 1) { throw "CLI: bledne haslo powinno dac exit 1 (jest $LASTEXITCODE)" }
    Write-Host "PASS: CLI bledne haslo -> exit 1"
    $g = Start-Process -FilePath $guiExe -ArgumentList "--selftest" -Wait -PassThru
    if ($g.ExitCode -ne 0) { throw "GUI --selftest zakonczyl sie kodem $($g.ExitCode)" }
    Write-Host "PASS: GUI --selftest (exit 0)"
    & $cliExe gui --selftest | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "CLI: gui --selftest zakonczyl sie kodem $LASTEXITCODE" }
    Write-Host "PASS: CLI gui --selftest"
    # --- portable GUI + samodzielne CLI: prawdziwe procesy, bez Pythona w PATH, z innego katalogu
    Write-Host ""
    Write-Host "--- Testy portable i samodzielnego CLI ---" -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot "test-portable.ps1") -Portable $portableExe -Cli $cliOnefile -FixtureDir $fix -Version $version
    if ($LASTEXITCODE -ne 0) { throw "Testy portable/CLI zakonczyly sie bledem (exit $LASTEXITCODE)" }
    Remove-Item -Recurse -Force $fix -ErrorAction SilentlyContinue

    # ---------------------------------------------------------------- 7. instalator
    Step "Generowanie instalatora (Inno Setup)"
    Run $iscc @("/DAppVersion=$version", (Join-Path $root "packaging\windows\KSeF-cert-verify.iss"))
    $setup = Join-Path $root "dist\KSeF-CertVerify-$version-win-x64-setup.exe"
    if (-not (Test-Path $setup)) { throw "Inno Setup nie utworzyl: $setup" }

    # ---------------------------------------------------------------- 8. SHA-256
    Step "Suma SHA-256"
    $artifacts = @($setup, $portableExe, $cliOnefile)
    $sumsFile = Join-Path $root "dist\SHA256SUMS"
    $names = @($artifacts | ForEach-Object { Split-Path $_ -Leaf })
    $lines = @()
    if (Test-Path $sumsFile) {
        $lines = @(Get-Content $sumsFile | Where-Object { $line = $_; $line -and -not ($names | Where-Object { $line.EndsWith("  $_") }) })
    }
    foreach ($a in $artifacts) {
        $h = (Get-FileHash $a -Algorithm SHA256).Hash.ToLower()
        $lines += "$h  $(Split-Path $a -Leaf)"
        Write-Host "$h  $(Split-Path $a -Leaf)"
    }
    Set-Content -Path $sumsFile -Value $lines -Encoding ascii

    if ($TestInstaller) {
        Write-Host ""
        Write-Host "--- Test instalatora: cicha instalacja -> CLI/GUI -> odinstalowanie ---" -ForegroundColor Cyan
        & (Join-Path $PSScriptRoot "test-installer.ps1") -Setup $setup -OldSetup $OldSetup
        if ($LASTEXITCODE -ne 0) { throw "Test instalatora zakonczyl sie bledem (exit $LASTEXITCODE)" }
    } else {
        $script:skipped += "test instalatora (uruchom z -TestInstaller)"
    }

    # ---------------------------------------------------------------- 9. artefakty
    Step "Gotowe artefakty"
    Write-Host "Setup (instalator) : $setup"
    Write-Host "Portable (GUI)     : $portableExe"
    Write-Host "CLI (1 plik)       : $cliOnefile"
    Write-Host "SHA256SUMS         : $sumsFile"
    Write-Host "Katalog onedir     : $dist"
    if ($script:skipped.Count -gt 0) {
        Write-Host ""
        Write-Host "NIE WYKONANO: $($script:skipped -join '; ')" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "BUILD ZAKONCZONY POMYSLNIE (wersja $version)" -ForegroundColor Green
    exit 0
}
catch {
    Write-Host ""
    Write-Host "BLAD: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Build PRZERWANY na kroku $($script:step)/9." -ForegroundColor Red
    exit 1
}
