<#
.SYNOPSIS
  KSeF CertVerify - test E2E plikow portable (GUI onefile) i samodzielnego CLI na Windows.
.DESCRIPTION
  Uruchamia PRAWDZIWE procesy (nie tylko sprawdza istnienie plikow): z dowolnego katalogu (spacje, polskie znaki),
  bez Pythona w PATH, bez instalacji i bez uprawnien administratora. Sprawdza: ladowanie PySide6, zasoby i pakiet CA,
  wybor certyfikatu, odszyfrowanie klucza haslem, dopasowanie pary, podpis testowy, okno "O programie" (nazwa/wersja/
  link GitHub), dzialajace okno GUI (uchwyt okna, tytul), czyszczenie katalogu rozpakowania (_MEI*) i brak
  pozostawionych plikow kluczy/certyfikatow. Blad dowolnego sprawdzenia -> exit 1.
.PARAMETER Portable
  Sciezka do KSeF-CertVerify-<wersja>-win-x64-portable.exe
.PARAMETER Cli
  Sciezka do ksef-cert-verify-<wersja>-win-x64-cli.exe
.PARAMETER FixtureDir
  Katalog z SYNTETYCZNA para testowa (scripts\make_fixture_pair.py); tworzony PRZED uruchomieniem (wymaga Pythona).
.PARAMETER Version
  Oczekiwana wersja (z projektu).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Portable,
    [Parameter(Mandatory)][string]$Cli,
    [Parameter(Mandatory)][string]$FixtureDir,
    [Parameter(Mandatory)][string]$Version
)
$ErrorActionPreference = "Stop"
$script:fail = 0
function Check($ok, $name) { if ($ok) { Write-Host "PASS: $name" } else { Write-Host "FAIL: $name"; $script:fail++ } }

$tempRoot = [IO.Path]::GetTempPath()
$work = Join-Path $tempRoot ("ksef-portable-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
# spacje i polskie znaki w sciezce (znaki z kodow - niezaleznie od kodowania pliku w Windows PowerShell 5.1)
$polish = "Katalog Testowy " + [char]0x0105 + [char]0x0119 + [char]0x0142
$dir = Join-Path $work $polish
New-Item -ItemType Directory -Force $dir | Out-Null
$portableCopy = Join-Path $dir (Split-Path $Portable -Leaf)
$cliCopy = Join-Path $dir (Split-Path $Cli -Leaf)
Copy-Item $Portable $portableCopy
Copy-Item $Cli $cliCopy

$oldPath = $env:PATH
$oldPythonHome = $env:PYTHONHOME
$oldPythonPath = $env:PYTHONPATH
# zmienne QT_* z otoczenia uzytkownika (np. QT_QPA_PLATFORM=offscreen z IDE/testow) ukrywaja okno GUI - test uruchamia aplikacje
# tak jak zwykly uzytkownik, wiec czyscimy je na czas testu i przywracamy na koniec
$savedQt = @{}
foreach ($v in @(Get-ChildItem Env: | Where-Object { $_.Name -like "QT_*" })) { $savedQt[$v.Name] = $v.Value; Remove-Item "Env:$($v.Name)" }
if ($savedQt.Count -gt 0) { Write-Host ("UWAGA: w srodowisku ustawione: " + (($savedQt.GetEnumerator() | ForEach-Object { $_.Key + "=" + $_.Value }) -join ", ") + " - na czas testu usuniete") }
$startTime = Get-Date
$meiBefore = @(Get-ChildItem $tempRoot -Directory -Filter "_MEI*" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
$uninstallKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
$uninstallBefore = if (Test-Path $uninstallKey) { (Get-ChildItem $uninstallKey).Count } else { 0 }

try {
    # --- srodowisko bez Pythona: PATH tylko z katalogami systemowymi
    $env:PATH = "$env:SystemRoot\System32"
    Remove-Item Env:PYTHONHOME -ErrorAction SilentlyContinue
    Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
    Check (-not (Get-Command python -ErrorAction SilentlyContinue) -and -not (Get-Command py -ErrorAction SilentlyContinue)) "Python nie jest dostepny w PATH procesu testowego"
    Set-Location $env:SystemRoot                    # uruchomienie z innego katalogu niz plik EXE

    # --- metadane
    foreach ($f in @($portableCopy, $cliCopy)) {
        $vi = (Get-Item $f).VersionInfo
        Check (($vi.ProductName -eq "KSeF CertVerify") -and ($vi.ProductVersion -eq $Version)) "metadane EXE: $(Split-Path $f -Leaf) ($($vi.ProductName) $($vi.ProductVersion))"
    }

    # --- PORTABLE: autotest w prawdziwym procesie GUI (weryfikacja pary, O programie, zasoby, CA)
    $report = Join-Path $work "selftest-report.json"
    $p = Start-Process -FilePath $portableCopy -ArgumentList @("--selftest", "--selftest-report", "`"$report`"") -Wait -PassThru -WorkingDirectory $env:SystemRoot
    Check ($p.ExitCode -eq 0) "portable --selftest (exit $($p.ExitCode))"
    if (Test-Path $report) {
        $r = Get-Content $report -Raw -Encoding UTF8 | ConvertFrom-Json
        Check ($r.ok -eq $true) "raport selftest: ok"
        foreach ($name in @("gui_verification", "key_decrypted", "key_matches_certificate", "signature_test", "about_dialog", "assets_present", "ca_bundle_present", "temp_files_removed")) {
            Check ($r.checks.$name -eq $true) "selftest: $name"
        }
        Check ($r.details.frozen -eq "True") "uruchomiono jako aplikacja spakowana (frozen)"
        # katalog rozpakowania PyInstallera (_MEIxxxxx) musi lezec poza katalogiem programu i poza Program Files (bez admina)
        $mei = [string]$r.details.meipass
        Check (($mei -match "\\_MEI[^\\]+$") -and -not $mei.StartsWith($dir, [StringComparison]::OrdinalIgnoreCase) -and ($mei -notlike "$env:ProgramFiles*")) "zasoby rozpakowane do katalogu tymczasowego uzytkownika: $mei"
        Check ($r.details.version -eq $Version) "wersja w aplikacji = $Version"
    } else { Check $false "raport selftest nie zostal utworzony" }

    # --- PORTABLE: dzialajace okno GUI (bez argumentow), prawdziwy proces z uchwytem okna
    # onefile: Start-Process zwraca proces bootloadera, a okno nalezy do jego potomka - szukamy w calym drzewie procesow.
    # Okna wyszukujemy przez Win32 (EnumWindows), niezaleznie od wersji PowerShella (5.1 / 7).
    Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class WinFinder {
    delegate bool EnumProc(IntPtr h, IntPtr l);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc p, IntPtr l);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr h, StringBuilder sb, int n);
    [DllImport("user32.dll")] static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
    public static string[] Find(int[] pids) {
        var set = new HashSet<int>(pids); var res = new List<string>();
        EnumWindows(delegate (IntPtr h, IntPtr l) {
            uint pid; GetWindowThreadProcessId(h, out pid);
            if (set.Contains((int)pid) && IsWindowVisible(h)) {
                var sb = new StringBuilder(256); GetWindowText(h, sb, 256);
                if (sb.Length > 0) res.Add(h.ToInt64() + "|" + sb.ToString());
            }
            return true; }, IntPtr.Zero);
        return res.ToArray();
    }
    public static string[] Dump(int[] pids) {
        var set = new HashSet<int>(pids); var res = new List<string>();
        EnumWindows(delegate (IntPtr h, IntPtr l) {
            uint pid; GetWindowThreadProcessId(h, out pid);
            if (set.Contains((int)pid)) {
                var sb = new StringBuilder(256); GetWindowText(h, sb, 256);
                res.Add("pid=" + pid + " hwnd=" + h.ToInt64() + " visible=" + IsWindowVisible(h) + " title='" + sb.ToString() + "'");
            }
            return true; }, IntPtr.Zero);
        return res.ToArray();
    }
    public static void Close(long h) { PostMessage(new IntPtr(h), 0x0010, IntPtr.Zero, IntPtr.Zero); }
}
"@
    function Get-Tree([int]$id) {
        $id
        foreach ($k in @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$id" -ErrorAction SilentlyContinue)) { Get-Tree ([int]$k.ProcessId) }
    }
    $traceFile = Join-Path $work "gui-trace.txt"
    $env:KSEF_CERT_VERIFY_TRACE = $traceFile       # zrzut stosu po 40 s (diagnostyka, gdyby start sie zawiesil)
    $gui = Start-Process -FilePath $portableCopy -PassThru -WorkingDirectory $env:SystemRoot
    Remove-Item Env:KSEF_CERT_VERIFY_TRACE -ErrorAction SilentlyContinue
    $deadline = (Get-Date).AddSeconds(120)
    $title = ""; $hwnd = 0
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
        if ($gui.HasExited) { break }
        $found = @([WinFinder]::Find([int[]]@(Get-Tree $gui.Id)) | Where-Object { $_ -like "*KSeF CertVerify*" })
        if ($found.Count -gt 0) { $hwnd = [long]($found[0].Split("|")[0]); $title = $found[0].Substring($found[0].IndexOf("|") + 1); break }
    }
    Check (-not $gui.HasExited) "proces GUI dziala"
    if (-not $title) {
        Write-Host "DIAGNOSTYKA: brak okna z tytulem. Drzewo procesow i okna:"
        Write-Host ("  QT_QPA_PLATFORM=[{0}] QT_* w srodowisku: {1}; sesja={2}" -f $env:QT_QPA_PLATFORM, (($savedQt.GetEnumerator() | ForEach-Object { $_.Key + "=" + $_.Value }) -join ", "), $env:SESSIONNAME)
        foreach ($id in @(Get-Tree $gui.Id)) { $pr = Get-Process -Id $id -ErrorAction SilentlyContinue; if ($pr) { Write-Host ("  proces {0} {1} responding={2}" -f $pr.Id, $pr.ProcessName, $pr.Responding) } }
        foreach ($line in @([WinFinder]::Dump([int[]]@(Get-Tree $gui.Id)))) { Write-Host "  okno: $line" }
        Start-Sleep -Seconds 2
        if (Test-Path $traceFile) { Write-Host "  --- zrzut stosu procesu GUI (faulthandler) ---"; Get-Content $traceFile -Encoding UTF8 | ForEach-Object { Write-Host "  $_" } }
    }
    Check ($title -like "*KSeF CertVerify*$Version*") "okno GUI ma tytul: '$title'"
    if ($hwnd -ne 0) {
        $owner = Get-Process -Id (@(Get-Tree $gui.Id) | Where-Object { Get-Process -Id $_ -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle.ToInt64() -eq $hwnd } } | Select-Object -First 1) -ErrorAction SilentlyContinue
        if ($owner) { Check ($owner.Responding) "okno GUI odpowiada" }
        [WinFinder]::Close($hwnd)          # WM_CLOSE = lagodne zamkniecie jak krzyzykiem
    }
    if (-not $gui.WaitForExit(30000)) {
        foreach ($id in @(Get-Tree $gui.Id)) { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue }
        Check $false "GUI zamkniete lagodnie (trzeba bylo zabic proces)"
    } else { Check ($gui.ExitCode -eq 0) "GUI zamkniete lagodnie (exit $($gui.ExitCode))" }

    # --- CLI
    $v = (& $cliCopy --version) -join ""
    Check (($LASTEXITCODE -eq 0) -and ($v.Trim() -eq "ksef-cert-verify $Version")) "CLI --version = $v"
    $pw = Get-Content (Join-Path $FixtureDir "password.txt") -Raw
    $crt = Join-Path $FixtureDir "KSeF_Ksiegowosc.crt"; $key = Join-Path $FixtureDir "KSeF_Ksiegowosc.key"; $ca = Join-Path $FixtureDir "ca.pem"
    $json = $pw | & $cliCopy verify --cert $crt --key $key -t $ca --password-stdin --json
    Check (($LASTEXITCODE -eq 0) -and (($json -join "`n") -match '"result": "VALID"')) "CLI pelna weryfikacja (exit 0, VALID)"
    "zle-haslo" | & $cliCopy verify --cert $crt --key $key -t $ca --password-stdin --json | Out-Null
    Check ($LASTEXITCODE -eq 1) "CLI bledne haslo -> exit 1"
    $sig = $pw | & $cliCopy test-signature --cert $crt --key $key --password-stdin --json
    Check (($LASTEXITCODE -eq 0) -and (($sig -join "`n") -match "SIGNATURE_VALID")) "CLI test podpisu: SIGNATURE_VALID"
    & $cliCopy gui 2>&1 | Out-Null
    Check ($LASTEXITCODE -eq 2) "CLI: polecenie gui informuje o braku GUI (exit 2)"
    & $cliCopy inspect $crt | Out-Null
    Check ($LASTEXITCODE -eq 0) "CLI inspect"
}
finally {
    $env:PATH = $oldPath
    foreach ($k in $savedQt.Keys) { Set-Item "Env:$k" $savedQt[$k] }
    if ($oldPythonHome) { $env:PYTHONHOME = $oldPythonHome }
    if ($oldPythonPath) { $env:PYTHONPATH = $oldPythonPath }
}

# --- sprzatanie i brak pozostalosci
Start-Sleep -Seconds 3
$meiAfter = @(Get-ChildItem $tempRoot -Directory -Filter "_MEI*" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
$leftover = @($meiAfter | Where-Object { $meiBefore -notcontains $_ })
Check ($leftover.Count -eq 0) "katalogi rozpakowania _MEI* usuniete po zamknieciu ($($leftover.Count) pozostalosci)"
$secretFiles = @(Get-ChildItem $tempRoot -Recurse -File -Include *.key, *.pem, *.crt, *.p12, *.pfx -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt $startTime -and -not $_.FullName.StartsWith($work, [StringComparison]::OrdinalIgnoreCase) -and -not $_.FullName.StartsWith($FixtureDir, [StringComparison]::OrdinalIgnoreCase) })
Check ($secretFiles.Count -eq 0) "brak nowych plikow kluczy/certyfikatow w katalogu tymczasowym ($($secretFiles.Count))"
$uninstallAfter = if (Test-Path $uninstallKey) { (Get-ChildItem $uninstallKey).Count } else { 0 }
Check ($uninstallAfter -eq $uninstallBefore) "portable nie rejestruje sie w systemie (brak wpisu odinstalowania)"

Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
if ($script:fail) { Write-Host "BLEDY: $script:fail"; exit 1 }
Write-Host "WSZYSTKIE TESTY PORTABLE ZALICZONE"
exit 0
