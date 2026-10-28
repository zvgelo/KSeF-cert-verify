"""Buduje natywne pakiety PyInstaller dla bieżącego systemu.

PyInstaller NIE buduje międzyplatformowo: Windows → na Windows, Linux → na Linux (najlepiej na najstarszym wspieranym
systemie, bo zależy od glibc).

Cele (--target):
  onedir    katalog dist/ksef-cert-verify/ (CLI + GUI + biblioteki) – wejście dla instalatorów (Inno Setup, RPM, DEB, AppImage)
  portable  jeden plik GUI:  KSeF-CertVerify-<wersja>-<platforma>-portable[.exe]   (--onefile --windowed)
  cli       jeden plik CLI:  ksef-cert-verify-<wersja>-<platforma>-cli[.exe]       (--onefile, bez Qt)
  all       wszystkie powyższe

Użycie:  python scripts/build.py [--target onedir|portable|cli|all]
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

SPECS = {
    "onedir": "ksef-cert-verify.spec",
    "portable": "ksef-cert-verify-portable.spec",
    "cli": "ksef-cert-verify-cli.spec",
}


def platform_label() -> str:
    return "win-x64" if sys.platform == "win32" else "linux-x64"


def artifact_name(target: str, version: str) -> str:
    plat = platform_label()
    return {
        "portable": f"KSeF-CertVerify-{version}-{plat}-portable",
        "cli": f"ksef-cert-verify-{version}-{plat}-cli",
    }[target]


def build_target(target: str, version: str) -> Path:
    env = dict(os.environ)
    if target != "onedir":
        env["KSEF_ARTIFACT_NAME"] = artifact_name(target, version)
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--distpath",
        str(ROOT / "dist"),
        "--workpath",
        str(ROOT / "build" / f"pyinstaller-{target}"),
        str(ROOT / "packaging" / SPECS[target]),
    ]
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True, cwd=ROOT, env=env)
    suffix = ".exe" if sys.platform == "win32" else ""
    if target == "onedir":
        out = ROOT / "dist" / "ksef-cert-verify"
        archive = shutil.make_archive(
            str(ROOT / "dist" / f"ksef-cert-verify-{version}-{platform_label()}-onedir"),
            "zip" if sys.platform == "win32" else "gztar",
            out.parent,
            out.name,
        )
        print("pakiet:", archive)
        return out
    out = ROOT / "dist" / (artifact_name(target, version) + suffix)
    if not out.is_file():
        raise SystemExit(f"PyInstaller nie utworzył oczekiwanego pliku: {out}")
    print("artefakt:", out, f"({out.stat().st_size // (1024 * 1024)} MB)")
    return out


def main() -> int:
    from ksef_cert_verify import __version__

    ap = argparse.ArgumentParser()
    ap.add_argument("--target", choices=[*SPECS, "all"], default="onedir")
    args = ap.parse_args()
    targets = list(SPECS) if args.target == "all" else [args.target]
    for t in targets:
        build_target(t, __version__)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
