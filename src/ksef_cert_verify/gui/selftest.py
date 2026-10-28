"""Autotest spakowanego GUI: `ksef-cert-verify-gui --selftest`.

Generuje SYNTETYCZNĄ parę (własne CA, certyfikat, zaszyfrowany klucz) w katalogu tymczasowym, uruchamia prawdziwe
okno Qt (headless, jeśli brak ekranu), wypełnia pola, klika „Weryfikuj” i sprawdza wynik. Kod wyjścia 0 = sukces.
To nie jest certyfikat KSeF – test sprawdza instalację (Qt, biblioteki, silnik), nie zgodność z MF.
"""

from __future__ import annotations

import datetime as dt
import os
import sys
import tempfile
from pathlib import Path

SELFTEST_PASSWORD = "selftest-haslo-123"


def _make_pair(tmp: Path) -> tuple[Path, Path, Path]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = dt.datetime.now(dt.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Selftest CA (syntetyczne)"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PL"),
        ]
    )
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True
        )
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Jan Selftest"),
            x509.NameAttribute(NameOID.GIVEN_NAME, "Jan"),
            x509.NameAttribute(NameOID.SURNAME, "Selftest"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PL"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(0x0123456789ABCDEF)
        .not_valid_before(now - dt.timedelta(hours=1))
        .not_valid_after(now + dt.timedelta(days=20))
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True
        )
        .sign(ca_key, hashes.SHA256())
    )
    pem = serialization.Encoding.PEM
    (tmp / "KSeF_Selftest.crt").write_bytes(cert.public_bytes(pem))
    (tmp / "ca.pem").write_bytes(ca.public_bytes(pem))
    (tmp / "KSeF_Selftest.key").write_bytes(
        key.private_bytes(
            pem,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(SELFTEST_PASSWORD.encode()),
        )
    )
    return tmp / "KSeF_Selftest.crt", tmp / "KSeF_Selftest.key", tmp / "ca.pem"


def _write_report(path: str | None, report: dict) -> None:
    if path:
        import json

        Path(path).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


def run_selftest(report_path: str | None = None) -> int:
    """Uruchamia prawdziwe okno, weryfikuje parę i sprawdza zasoby aplikacji (także w wersji portable/PyInstaller)."""
    if sys.platform.startswith("linux") and not (
        os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
    ):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from ksef_cert_verify import __version__
    from ksef_cert_verify.branding import PRODUCT_NAME, REPOSITORY_URL
    from ksef_cert_verify.core.report import VerifyOptions
    from ksef_cert_verify.core.trust_store import TrustStore

    from . import icons
    from .main_window import MainWindow

    app = QApplication.instance() or QApplication(sys.argv[:1])
    checks: dict[str, bool] = {}
    details: dict[str, str] = {}
    tmp_path: Path | None = None
    with tempfile.TemporaryDirectory(prefix="ksef-selftest-") as d:
        tmp_path = Path(d)
        cert, key, ca = _make_pair(tmp_path)
        trust = TrustStore()
        trust.load_path(ca)
        win = MainWindow(options_factory=lambda: VerifyOptions(trust=trust))
        win.show()
        win.set_cert(cert)
        win.set_key(key)
        win.edit_password.setText(SELFTEST_PASSWORD)
        win.btn_verify.click()
        win.wait_until_idle(20000)
        for _ in range(200):  # dostarcz sygnały z wątku roboczego
            app.processEvents()
        verdict = win._cards["local"]["status"].text()  # type: ignore[attr-defined]
        rows = {k: b.text() for k, b in win._badges.items()}
        checks["gui_verification"] = verdict.endswith("POPRAWNY")
        checks["key_decrypted"] = "OK" in rows["key_decrypt"]
        checks["key_matches_certificate"] = "OK" in rows["key_match"]
        checks["signature_test"] = "OK" in rows["signature_test"]
        # „O programie": nazwa, wersja i odnośnik do repozytorium
        dlg = win.build_about_dialog()
        from PySide6.QtWidgets import QLabel

        checks["about_dialog"] = (
            dlg.findChild(QLabel, "aboutName").text() == PRODUCT_NAME  # type: ignore[union-attr]
            and dlg.findChild(QLabel, "aboutVersion").text() == __version__  # type: ignore[union-attr]
            and REPOSITORY_URL.removeprefix("https://") in win.btn_repo.text()
            and not win.btn_repo.icon().isNull()
        )
        dlg.deleteLater()
        win.close()
    checks["temp_files_removed"] = tmp_path is not None and not tmp_path.exists()
    # zasoby spakowanej aplikacji: ikony/logo i pakiet certyfikatów CA używany do TLS (httpx → certifi)
    checks["assets_present"] = (icons.ASSETS / "logo.svg").is_file() and all(
        (icons.ASSETS / "icons" / f"{n}.svg").is_file() for n, _ in icons.STATUS_ICON.values()
    )
    try:
        import certifi

        bundle = Path(certifi.where())
        checks["ca_bundle_present"] = bundle.is_file() and bundle.stat().st_size > 10_000
        details["ca_bundle"] = str(bundle)
    except Exception as exc:  # brak certifi = brak TLS do API
        checks["ca_bundle_present"] = False
        details["ca_bundle_error"] = type(exc).__name__
    details.update(
        executable=sys.executable,
        frozen=str(bool(getattr(sys, "frozen", False))),
        meipass=str(getattr(sys, "_MEIPASS", "")),
        assets=str(icons.ASSETS),
        version=__version__,
    )
    ok = all(checks.values())
    print(
        f"selftest GUI: werdykt={verdict!r} key_decrypt={rows['key_decrypt']!r} key_match={rows['key_match']!r}"
    )
    print("SELFTEST " + ("OK" if ok else "FAIL"), {k: v for k, v in checks.items() if not v} or "")
    _write_report(report_path, {"ok": ok, "checks": checks, "details": details})
    return 0 if ok else 1
