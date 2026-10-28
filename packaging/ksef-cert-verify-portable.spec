# -*- mode: python ; coding: utf-8 -*-
# Portable: JEDEN samodzielny plik GUI (--onefile --windowed). Nie wymaga instalacji, Pythona ani uprawnień administratora.
# Zawiera PySide6, cryptography, lxml, httpx + pakiet CA (certifi) oraz zasoby GUI (ikony, logo).
# PyInstaller onefile rozpakowuje się przy starcie do katalogu tymczasowego użytkownika (%TEMP%\_MEIxxxxx) i usuwa go
# przy zamknięciu. Aplikacja NIE zapisuje tam kluczy ani haseł (nic nie zapisuje); odszyfrowany klucz żyje tylko w pamięci.
import os
import sys
from pathlib import Path

ROOT = Path(SPECPATH).resolve().parent
NAME = os.environ.get("KSEF_ARTIFACT_NAME", "KSeF-CertVerify-portable")
ICON = str(ROOT / "packaging" / "assets" / "icon.ico") if sys.platform == "win32" else None
VERSION_FILE = os.environ.get("KSEF_VERSION_FILE") if sys.platform == "win32" else None
ASSETS = [(str(ROOT / "src" / "ksef_cert_verify" / "gui" / "assets"), "ksef_cert_verify/gui/assets")]

a = Analysis(
    [str(ROOT / "packaging" / "entry_gui.py")],
    pathex=[str(ROOT / "src")],
    datas=ASSETS,
    hiddenimports=["ksef_cert_verify.gui.selftest"],
    excludes=["tkinter"],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name=NAME, console=False, icon=ICON, version=VERSION_FILE, upx=False, strip=False,
)
