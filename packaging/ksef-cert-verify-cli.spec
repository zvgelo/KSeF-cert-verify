# -*- mode: python ; coding: utf-8 -*-
# Samodzielne CLI: JEDEN plik konsolowy (--onefile), bez Qt/PySide6 (mały rozmiar). Polecenie `gui` wyświetla wskazówkę.
import os
import sys
from pathlib import Path

ROOT = Path(SPECPATH).resolve().parent
NAME = os.environ.get("KSEF_ARTIFACT_NAME", "ksef-cert-verify-cli")
ICON = str(ROOT / "packaging" / "assets" / "icon.ico") if sys.platform == "win32" else None
VERSION_FILE = os.environ.get("KSEF_VERSION_FILE") if sys.platform == "win32" else None

a = Analysis(
    [str(ROOT / "packaging" / "entry_cli.py")],
    pathex=[str(ROOT / "src")],
    excludes=["PySide6", "shiboken6", "ksef_cert_verify.gui", "tkinter"],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name=NAME, console=True, icon=ICON, version=VERSION_FILE, upx=False, strip=False,
)
