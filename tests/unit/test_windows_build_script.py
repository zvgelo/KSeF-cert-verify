"""Kontrola strukturalna packaging/windows/build.ps1 (pełne wykonanie wymaga Windows – robi to CI i użytkownik)."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PS1 = (ROOT / "packaging" / "windows" / "build.ps1").read_text(encoding="utf-8")


def test_nine_mandatory_steps_in_order():
    titles = re.findall(r'^\s*Step "([^"]+)"', PS1, re.M)
    assert len(titles) == 9
    keys = [
        "narzedzi",
        "srodowiska",
        "zaleznosci",
        "pytest",
        "PyInstaller",
        "EXE",
        "Inno",
        "SHA-256",
        "artefakty",
    ]
    assert all(k.lower() in t.lower() for k, t in zip(keys, titles, strict=True)), titles


def test_script_fails_hard_and_checks_native_exit_codes():
    assert '$ErrorActionPreference = "Stop"' in PS1 and "Set-StrictMode" in PS1
    assert re.search(r"catch\s*\{.*?exit 1", PS1, re.S)  # błąd = kod wyjścia 1
    assert "$LASTEXITCODE -ne 0" in PS1 and "function Run" in PS1


def test_script_uses_project_version_and_builds_expected_artifact_names():
    assert "/DAppVersion=$version" in PS1 and "win-x64-setup.exe" in PS1
    assert "SHA256SUMS" in PS1 and "Get-FileHash" in PS1 and "-Algorithm SHA256" in PS1
    assert "KSeF CertVerify" in PS1 and "KSEF_VERSION_FILE" in PS1
    assert "ProductVersion -ne $version" in PS1  # metadane EXE muszą zgadzać się z wersją projektu


def test_skipped_steps_are_reported_not_passed():
    assert "POMINIETO" in PS1 and "NIE WYKONANO" in PS1


def test_spec_applies_version_resource_only_on_windows():
    spec = (ROOT / "packaging" / "ksef-cert-verify.spec").read_text(encoding="utf-8")
    assert 'os.environ.get("KSEF_VERSION_FILE") if sys.platform == "win32" else None' in spec
    assert spec.count("version=VERSION_FILE") == 2  # CLI i GUI


# ---- Portable (onefile) i samodzielne CLI ---------------------------------------------------------------------------
PORTABLE_SPEC = (ROOT / "packaging" / "ksef-cert-verify-portable.spec").read_text(encoding="utf-8")
CLI_SPEC = (ROOT / "packaging" / "ksef-cert-verify-cli.spec").read_text(encoding="utf-8")
TEST_PORTABLE = (ROOT / "packaging" / "windows" / "test-portable.ps1").read_text(encoding="utf-8")


def test_portable_spec_is_single_file_windowed_with_icon_version_and_assets():
    assert "console=False" in PORTABLE_SPEC and "COLLECT" not in PORTABLE_SPEC  # onefile: bez COLLECT
    assert "a.binaries, a.datas" in PORTABLE_SPEC and "ksef_cert_verify/gui/assets" in PORTABLE_SPEC
    assert (
        "icon=ICON" in PORTABLE_SPEC
        and "version=VERSION_FILE" in PORTABLE_SPEC
        and "upx=False" in PORTABLE_SPEC
    )


def test_cli_spec_is_single_file_console_without_qt():
    assert "console=True" in CLI_SPEC and "COLLECT" not in CLI_SPEC
    assert (
        '"PySide6"' in CLI_SPEC and "ksef_cert_verify.gui" in CLI_SPEC and "version=VERSION_FILE" in CLI_SPEC
    )


def test_artifact_names_match_the_release_contract():
    import sys

    sys.path.insert(0, str(ROOT / "scripts"))
    import build

    assert build.artifact_name("portable", "1.0.0").endswith("-portable") and build.artifact_name(
        "portable", "1.0.0"
    ).startswith("KSeF-CertVerify-1.0.0-")
    assert build.artifact_name("cli", "1.0.0").startswith("ksef-cert-verify-1.0.0-") and build.artifact_name(
        "cli", "1.0.0"
    ).endswith("-cli")
    assert "OutputBaseFilename=KSeF-CertVerify-{#AppVersion}-win-x64-setup" in (
        ROOT / "packaging/windows/KSeF-cert-verify.iss"
    ).read_text(encoding="utf-8")
    for expected in (
        "KSeF-CertVerify-$version-win-x64-portable.exe",
        "ksef-cert-verify-$version-win-x64-cli.exe",
        "KSeF-CertVerify-$version-win-x64-setup.exe",
    ):
        assert expected in PS1


def test_build_script_builds_all_three_targets_and_hashes_them():
    assert '"--target", "all"' in PS1 and "test-portable.ps1" in PS1
    assert "$artifacts = @($setup, $portableExe, $cliOnefile)" in PS1


def test_portable_test_script_checks_real_process_and_cleanup():
    for needle in (
        "EnumWindows",
        "GetWindowText",
        "WM_CLOSE",
        "_MEI*",
        "--selftest-report",
        "Get-Command python",
        "[char]0x0105",
        "*.key",
        "Uninstall",
        "about_dialog",
        "ca_bundle_present",
        "exit 1",
    ):
        assert needle in TEST_PORTABLE, needle


def test_powershell_scripts_survive_windows_powershell_encoding():
    """Windows PowerShell 5.1 czyta skrypty bez BOM jako ANSI – pliki z polskimi znakami muszą mieć BOM albo być ASCII."""
    for f in (ROOT / "packaging" / "windows").glob("*.ps1"):
        raw = f.read_bytes()
        assert raw.startswith(b"\xef\xbb\xbf") or raw.isascii(), f.name


def test_build_script_refuses_network_drives_unless_overridden():
    assert "[switch]$AllowNetworkPath" in PS1 and "DisplayRoot" in PS1 and "robocopy" in PS1
