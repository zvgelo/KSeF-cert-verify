"""Niezmienniki aktualizacji: jedno źródło wersji, stałe identyfikatory instalatorów, brak ręcznie wpisanych wersji."""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

from ksef_cert_verify import __version__

ROOT = Path(__file__).resolve().parents[2]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8-sig")


ISS = read("packaging/windows/KSeF-cert-verify.iss")


def test_single_source_of_truth_is_package_version():
    meta = tomllib.loads(read("pyproject.toml"))
    assert "version" in meta["project"]["dynamic"] and "version" not in meta["project"]
    assert meta["tool"]["setuptools"]["dynamic"]["version"] == {"attr": "ksef_cert_verify.__version__"}
    assert re.fullmatch(r"\d+(\.\d+)*", __version__)  # format zgodny z RPM i DEB


def test_cli_reports_package_version():
    r = subprocess.run(
        [sys.executable, "-m", "ksef_cert_verify", "--version"], capture_output=True, text=True, timeout=60
    )
    assert r.stdout.strip() == f"ksef-cert-verify {__version__}"


def test_installer_and_packages_take_version_from_project_not_literals():
    assert "#error" in ISS and not re.search(r'#define AppVersion\s+"\d', ISS)
    assert "@VERSION@" in read("packaging/linux/deb/control.in")
    assert "%{pkg_version}" in read("packaging/linux/rpm/ksef-cert-verify.spec")
    build = read("packaging/linux/build.sh")
    assert "from ksef_cert_verify import __version__" in build and "[0-9]+(" in build
    assert "/DAppVersion=$version" in read("packaging/windows/build.ps1")


def test_inno_setup_upgrades_existing_installation_in_place():
    assert "AppId={{B6D7C3A2-5E1F-4B8A-9C34-7A2E6F1D0C95}" in ISS  # NIE ZMIENIAĆ (jeden wpis między wersjami)
    assert '#define AppName "KSeF CertVerify"' in ISS
    for needed in (
        "UsePreviousAppDir=yes",
        "UsePreviousPrivileges=yes",
        "CloseApplications=yes",
        "DefaultDirName={autopf}\\{#AppName}",
        "PrivilegesRequired=lowest",
    ):
        assert needed in ISS, needed
    delete = ISS.split("[InstallDelete]")[1].split("[Files]")[0]
    assert "{app}\\_internal" in delete and "unins" not in delete.replace("unins000.exe/.dat NIE", "")
    assert "ignoreversion" in ISS  # starsze pliki są zawsze zastępowane nowymi


def test_native_packages_keep_constant_name_and_paths():
    spec = read("packaging/linux/rpm/ksef-cert-verify.spec")
    assert re.search(r"^Name:\s+ksef-cert-verify$", spec, re.M) and "/opt/ksef-cert-verify" in spec
    control = read("packaging/linux/deb/control.in")
    assert control.startswith("Package: ksef-cert-verify\n")
    assert (
        "%config" not in spec
    )  # brak plików konfiguracyjnych w pakiecie – konfiguracja użytkownika jest w ~/.config


def test_upgrade_tests_use_two_real_packages_and_ci_runs_them():
    script = read("packaging/linux/test-upgrade.sh")
    assert "tę samą wersję" in script or "tej samej" in script or "same" in script.lower()
    assert "dnf upgrade" in script and "apt-get install" in script
    workflow = ROOT / ".github" / "workflows" / "build.yml"
    if workflow.is_file():  # kopia robocza bez .github (np. robocopy) – kontrola CI pomijana
        ci = workflow.read_text(encoding="utf-8")
        assert "upgrade-linux" in ci and "gh release download" in ci and "-OldSetup" in ci
    ps = read("packaging/windows/test-installer.ps1")
    assert "$OldSetup" in ps and "stale_from_old_version" in ps and "Uninstall-Entries" in ps


def test_portable_and_appimage_are_single_files_without_updater():
    assert "autoupdate" not in read("packaging/ksef-cert-verify-portable.spec").lower()
    assert "KSeF-CertVerify-$version-win-x64-portable.exe" in read("packaging/windows/build.ps1")


def test_build_outputs_are_named_after_the_project_version():
    sys.path.insert(0, str(ROOT / "scripts"))
    import build  # type: ignore[import-not-found]

    for target, suffix in (("portable", "-portable"), ("cli", "-cli")):
        assert build.artifact_name(target, __version__).count(__version__) == 1
        assert build.artifact_name(target, __version__).endswith(suffix)
    iss = read("packaging/windows/KSeF-cert-verify.iss")
    assert "OutputBaseFilename=KSeF-CertVerify-{#AppVersion}-win-x64-setup" in iss
    assert "$version" in read("packaging/windows/build.ps1") and "KSEF_VERSION_FILE" in read(
        "packaging/windows/build.ps1"
    )
    assert f'"version": "{__version__}"' in read(
        "docs/CLI.md"
    )  # przykład w dokumentacji nie rozjeżdża się z wersją
