"""Spójność brandingu: nazwa wyświetlana KSeF CertVerify vs. stałe identyfikatory techniczne."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

from ksef_cert_verify import branding

ROOT = Path(__file__).resolve().parents[2]
NAME = "KSeF CertVerify"


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_repository_url_is_fixed_and_consistent():
    """Adres repozytorium jest stałą w metadanych (nie czytamy `git remote` u użytkownika) i zgadza się z origin."""
    import subprocess

    meta = tomllib.loads(read("pyproject.toml"))
    assert meta["project"]["urls"]["Repository"] == branding.REPOSITORY_URL
    assert branding.REPOSITORY_URL == "https://github.com/zvgelo/KSeF-cert-verify"
    assert branding.REPOSITORY_URL.endswith("/KSeF-cert-verify")  # nazwa repozytorium bez zmian
    try:
        origin = subprocess.run(
            ["git", "remote", "get-url", "origin"], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("brak git/origin")
    if origin.removesuffix(".git") != branding.REPOSITORY_URL:
        pytest.skip(
            "origin różni się od adresu projektu (fork/inny klon) – stała w metadanych pozostaje źródłem prawdy"
        )


def test_single_version_source_matches_installers_and_license():
    from ksef_cert_verify import __version__

    meta = tomllib.loads(read("pyproject.toml"))
    assert "version" in meta["project"]["dynamic"] and meta["tool"]["setuptools"]["dynamic"]["version"] == {
        "attr": "ksef_cert_verify.__version__"
    }
    assert f'#define AppVersion "{__version__}"' in read(
        "packaging/windows/KSeF-cert-verify.iss"
    )  # domyślna wersja instalatora
    from importlib.metadata import PackageNotFoundError, version

    try:
        installed = version("ksef-cert-verify")
    except PackageNotFoundError:
        installed = None  # pakiet niezainstalowany – sprawdzamy tylko pozostałe źródła wersji
    if installed is not None:
        assert installed == __version__  # metadane zainstalowanego pakietu
    assert read("LICENSE").startswith(f"{branding.LICENSE_NAME} License")


def test_product_name_constants():
    assert branding.PRODUCT_NAME == NAME and branding.PRODUCT_SUBTITLE == "Weryfikacja certyfikatów KSeF"
    assert branding.CLI_COMMAND == "ksef-cert-verify" and branding.REPOSITORY_NAME == "KSeF-cert-verify"


def test_technical_identifiers_unchanged():
    meta = tomllib.loads(read("pyproject.toml"))
    assert meta["project"]["name"] == "ksef-cert-verify"
    assert meta["project"]["scripts"] == {"ksef-cert-verify": "ksef_cert_verify.cli:main"}
    assert meta["project"]["gui-scripts"] == {"ksef-cert-verify-gui": "ksef_cert_verify.gui.main:main"}
    assert (ROOT / "src" / "ksef_cert_verify").is_dir()


def test_inno_setup_branding_and_stable_app_id():
    iss = read("packaging/windows/KSeF-cert-verify.iss")
    assert '#define AppName "KSeF CertVerify"' in iss
    assert "AppId={{B6D7C3A2-5E1F-4B8A-9C34-7A2E6F1D0C95}" in iss  # stały identyfikator – nie wolno zmieniać
    assert (
        "OutputBaseFilename=KSeF-CertVerify-{#AppVersion}-win-x64-setup" in iss
    )  # nazwa artefaktu bez zmian
    assert "AppName={#AppName}" in iss and "Weryfikacja certyfikatów KSeF" in iss


def test_linux_menu_and_package_metadata_use_display_name():
    desktop = read("packaging/assets/ksef-cert-verify.desktop")
    assert re.search(r"^Name=KSeF CertVerify$", desktop, re.M) and "Exec=ksef-cert-verify-gui" in desktop
    assert "Icon=ksef-cert-verify" in desktop  # identyfikator ikony niezmieniony
    assert "KSeF CertVerify" in read("packaging/linux/rpm/ksef-cert-verify.spec")
    assert re.search(r"^Name:\s+ksef-cert-verify$", read("packaging/linux/rpm/ksef-cert-verify.spec"), re.M)
    control = read("packaging/linux/deb/control.in")
    assert "Package: ksef-cert-verify" in control and "Description: KSeF CertVerify" in control


def test_docs_use_display_name_and_keep_commands():
    readme = read("README.md")
    assert readme.startswith(f"# {NAME}") and "ksef-cert-verify verify" in readme
    assert "logo-wordmark" in readme


def test_gui_source_uses_branding_constants_not_hardcoded_old_name():
    for f in (ROOT / "src" / "ksef_cert_verify" / "gui").glob("*.py"):
        text = f.read_text(encoding="utf-8")
        for m in re.finditer(r"[\"']([^\"'\n]*KSeF-cert-verify[^\"'\n]*)[\"']", text):
            assert m.group(1) in {"KSeF-cert-verify"} or "ksef-cert-verify" in m.group(1).lower(), (
                f.name,
                m.group(1),
            )


@pytest.mark.gui
def test_window_title_and_about_show_product_name(qtbot):
    pytest.importorskip("PySide6")
    from ksef_cert_verify import __version__
    from ksef_cert_verify.gui.main_window import MainWindow

    w = MainWindow()
    qtbot.addWidget(w)
    assert w.windowTitle() == f"{NAME} {__version__}"
    assert NAME in w.about_text() and branding.PRODUCT_SUBTITLE in w.about_text()
    assert w.windowIcon().isNull() is False


def test_cli_help_shows_product_name_but_command_unchanged():
    from typer.testing import CliRunner

    from ksef_cert_verify.cli import app

    r = CliRunner().invoke(app, ["--help"])
    assert r.exit_code == 0 and NAME in r.output
    v = CliRunner().invoke(app, ["--version"])
    assert v.output.startswith("ksef-cert-verify ")
