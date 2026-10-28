# -*- mode: python ; coding: utf-8 -*-
# Jedna specyfikacja PyInstaller dla wszystkich platform i instalatorów (Windows/AppImage/RPM/DEB).
# Wynik: dist/ksef-cert-verify/{ksef-cert-verify[.exe], ksef-cert-verify-gui[.exe], _internal/}
# – dwa pliki wykonywalne współdzielą jedno drzewo bibliotek (PySide6 jest dołączone raz).
import os
import sys
from pathlib import Path

ROOT = Path(SPECPATH).resolve().parent
ICON = str(ROOT / "packaging" / "assets" / "icon.ico") if sys.platform == "win32" else None
# Zasób wersji EXE (Windows): plik generuje packaging/windows/build.ps1 i wskazuje zmienną KSEF_VERSION_FILE.
VERSION_FILE = os.environ.get("KSEF_VERSION_FILE") if sys.platform == "win32" else None
PATHS = [str(ROOT / "src")]
ASSETS = [(str(ROOT / "src" / "ksef_cert_verify" / "gui" / "assets"), "ksef_cert_verify/gui/assets")]

cli = Analysis([str(ROOT / "packaging" / "entry_cli.py")], pathex=PATHS, datas=ASSETS, hiddenimports=["ksef_cert_verify.gui.main", "ksef_cert_verify.gui.selftest"])
gui = Analysis([str(ROOT / "packaging" / "entry_gui.py")], pathex=PATHS, datas=ASSETS, hiddenimports=["ksef_cert_verify.cli"])
MERGE((cli, "entry_cli", "ksef-cert-verify"), (gui, "entry_gui", "ksef-cert-verify-gui"))

cli_exe = EXE(PYZ(cli.pure), cli.scripts, [], exclude_binaries=True, name="ksef-cert-verify",
              console=True, icon=ICON, version=VERSION_FILE, upx=False)
gui_exe = EXE(PYZ(gui.pure), gui.scripts, [], exclude_binaries=True, name="ksef-cert-verify-gui",
              console=False, icon=ICON, version=VERSION_FILE, upx=False)
COLLECT(cli_exe, cli.binaries, cli.datas, gui_exe, gui.binaries, gui.datas,
        strip=False, upx=False, name="ksef-cert-verify")
