; Inno Setup 6 – instalator KSeF-cert-verify (Windows 10/11 x64).
; Budowanie:  ISCC.exe /DAppVersion=<wersja> packaging\windows\KSeF-cert-verify.iss   (lub packaging\windows\build.ps1)
; Wejście:    dist\ksef-cert-verify\  (wynik scripts\build.py – PyInstaller: CLI + GUI + PySide6, bez Pythona)
; Wynik:      dist\KSeF-cert-verify-<wersja>-windows-x64-setup.exe

; Wersja pochodzi z projektu (ksef_cert_verify.__version__) i jest przekazywana przez build.ps1 (/DAppVersion=...).
; Brak wartości domyślnej celowo: nie wolno wpisywać numeru wersji ręcznie w wielu miejscach.
#ifndef AppVersion
  #error Brak /DAppVersion=<wersja> (uruchom packaging\windows\build.ps1 – odczytuje wersję z projektu).
#endif
; Nazwa wyświetlana produktu. Stałe identyfikatory (AppId, nazwy plików wyjściowych, polecenie CLI) pozostają bez zmian.
#define AppName "KSeF CertVerify"
#define AppSubtitle "Weryfikacja certyfikatów KSeF"
#define AppPublisher "KSeF-cert-verify contributors"
#define GuiExe "ksef-cert-verify-gui.exe"
#define CliExe "ksef-cert-verify.exe"

[Setup]
; AppId MUSI pozostać stały między wydaniami – dzięki niemu nowa wersja aktualizuje istniejącą instalację
; (ten sam katalog, ten sam wpis w „Aplikacje i funkcje”). NIE ZMIENIAĆ.
AppId={{B6D7C3A2-5E1F-4B8A-9C34-7A2E6F1D0C95}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppComments={#AppSubtitle}
VersionInfoVersion={#AppVersion}
VersionInfoProductName={#AppName}
VersionInfoDescription={#AppName} – {#AppSubtitle}
; Domyślnie instalacja per-user (bez administratora): %LOCALAPPDATA%\Programs\KSeF-cert-verify.
; Użytkownik może wybrać instalację systemową (dla wszystkich) w oknie dialogowym uprawnień.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog commandline
DefaultDirName={autopf}\{#AppName}
; Aktualizacja = ta sama instalacja: katalog, tryb (per-user/systemowy), zadania i język zapamiętane z poprzedniej wersji.
UsePreviousAppDir=yes
UsePreviousPrivileges=yes
UsePreviousTasks=yes
UsePreviousLanguage=yes
DisableProgramGroupPage=yes
DisableDirPage=no
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\..\dist
OutputBaseFilename=KSeF-CertVerify-{#AppVersion}-win-x64-setup
SetupIconFile=..\assets\icon.ico
UninstallDisplayIcon={app}\{#GuiExe}
UninstallDisplayName={#AppName} {#AppVersion}
LicenseFile=..\..\LICENSE
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
; Aktualizacja: zamknij uruchomioną aplikację przed podmianą plików, bez wymuszania restartu systemu.
CloseApplications=yes
CloseApplicationsFilter=*.exe,*.dll,*.pyd
RestartApplications=no
ChangesEnvironment=yes
; Instalator NIE jest podpisany cyfrowo (patrz docs/INSTALL_WINDOWS.md). Nie wyłączamy SmartScreen ani
; innych zabezpieczeń Windows – przy braku podpisu system może pokazać ostrzeżenie.

[Languages]
Name: "polish"; MessagesFile: "compiler:Languages\Polish.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Utwórz skrót na &pulpicie"; GroupDescription: "Skróty:"; Flags: unchecked
Name: "addtopath"; Description: "Dodaj wiersz poleceń (ksef-cert-verify) do zmiennej &PATH"; GroupDescription: "Wiersz poleceń:"; Flags: unchecked

[InstallDelete]
; Usuń pliki poprzedniej wersji, których nowa nie zawiera (PyInstaller: katalog _internal i pliki EXE).
; Ustawienia użytkownika są poza katalogiem programu (rejestr HKCU / profil), więc zostają nietknięte.
Type: filesandordirs; Name: "{app}\_internal"
Type: files; Name: "{app}\{#GuiExe}"
Type: files; Name: "{app}\{#CliExe}"
; (unins000.exe/.dat NIE są ruszane – należą do mechanizmu odinstalowania Inno Setup)

[Files]
Source: "..\..\dist\ksef-cert-verify\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#GuiExe}"; Comment: "{#AppName} – {#AppSubtitle}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#GuiExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#GuiExe}"; Description: "Uruchom {#AppName}"; Flags: nowait postinstall skipifsilent

[Code]
// --- PATH: HKCU (instalacja per-user) albo HKLM (instalacja systemowa) ---
function EnvRoot: Integer;
begin
  if IsAdminInstallMode then Result := HKEY_LOCAL_MACHINE else Result := HKEY_CURRENT_USER;
end;

function EnvSubKey: String;
begin
  if IsAdminInstallMode then
    Result := 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
  else
    Result := 'Environment';
end;

function PathContains(const Dir: String): Boolean;
var
  Orig: String;
begin
  if not RegQueryStringValue(EnvRoot, EnvSubKey, 'Path', Orig) then
    Result := False
  else
    Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Orig) + ';') > 0;
end;

procedure AddToPath(const Dir: String);
var
  Orig: String;
begin
  if PathContains(Dir) then Exit;
  if not RegQueryStringValue(EnvRoot, EnvSubKey, 'Path', Orig) then Orig := '';
  if (Orig <> '') and (Orig[Length(Orig)] <> ';') then Orig := Orig + ';';
  RegWriteExpandStringValue(EnvRoot, EnvSubKey, 'Path', Orig + Dir);
end;

procedure RemoveFromPath(const Dir: String);
var
  Orig, Marked: String;
  P: Integer;
begin
  if not RegQueryStringValue(EnvRoot, EnvSubKey, 'Path', Orig) then Exit;
  Marked := ';' + Orig + ';';
  P := Pos(';' + Uppercase(Dir) + ';', Uppercase(Marked));
  if P = 0 then Exit;
  Delete(Marked, P, Length(Dir) + 1);
  Marked := Copy(Marked, 2, Length(Marked) - 2);
  RegWriteExpandStringValue(EnvRoot, EnvSubKey, 'Path', Marked);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and WizardIsTaskSelected('addtopath') then
    AddToPath(ExpandConstant('{app}'));
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveFromPath(ExpandConstant('{app}'));
end;
