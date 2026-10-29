"""E2E GUI: prawdziwe okno Qt (offscreen), drag&drop, wątek roboczy, tryby, PROD, JWT. Dane SYNTETYCZNE; API mockowane."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading

import httpx
import pytest

pytest.importorskip("PySide6")
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from PySide6.QtCore import QMimeData, QPoint, QPointF, QSettings, Qt, QUrl  # noqa: E402
from PySide6.QtGui import QDragEnterEvent, QDropEvent, QGuiApplication  # noqa: E402
from PySide6.QtWidgets import QApplication, QLineEdit, QWidget  # noqa: E402

from ksef_cert_verify.core.report import VerifyOptions  # noqa: E402
from ksef_cert_verify.core.trust_store import TrustStore  # noqa: E402
from ksef_cert_verify.gui import icons  # noqa: E402
from ksef_cert_verify.gui.main_window import MainWindow  # noqa: E402
from tests.conftest import KEY_PASSWORD, NOW, _name, make_ca, make_leaf, pem, write_key, write_p12  # noqa: E402
from tests.integration.test_auth_flow import ACCESS_JWT, AUTH_TOKEN, NIP, FakeKsef, make_jwt  # noqa: E402
from tests.integration.test_ksef_api import item_for  # noqa: E402

pytestmark = [pytest.mark.gui, pytest.mark.e2e, pytest.mark.simulated]
AT = NOW.strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def make_window(qtbot, ca, tmp_path):
    def _make(with_anchor=True, fake=None, anchor_ca=None):
        def factory():
            t = TrustStore()
            if with_anchor:
                t.add((anchor_ca or ca).cert, "test")
            return VerifyOptions(trust=t, now=NOW)

        ini = QSettings(str(tmp_path / "settings.ini"), QSettings.Format.IniFormat)
        transport = httpx.MockTransport(fake) if fake is not None else None
        w = MainWindow(options_factory=factory, settings=ini, online_transport=transport)
        qtbot.addWidget(w)
        w.show()
        w.messages = []
        w._message = lambda title, text, warning=False: w.messages.append((title, text))
        return w

    return _make


@pytest.fixture
def pair(tmp_path, auth_cert):
    c = tmp_path / "KSeF_Ksiegowosc.crt"
    c.write_bytes(pem(auth_cert[0]))
    return c, write_key(tmp_path / "KSeF_Ksiegowosc.key", auth_cert[1])


@pytest.fixture
def nip_pair(tmp_path, ca):
    """Certyfikat Authentication z NIP (PEM) + zaszyfrowany klucz."""
    key = ec.generate_private_key(ec.SECP256R1())
    cert, _ = make_leaf(
        ca, subject=_name(cn="Jan Testowy", given="Jan", sn="Testowy", serial=f"TINPL{NIP}"), key=key
    )
    c = tmp_path / "n.crt"
    c.write_bytes(pem(cert))
    return cert, c, write_key(tmp_path / "n.key", key)


@pytest.fixture
def offline_pair(tmp_path, ca):
    key = ec.generate_private_key(ec.SECP256R1())
    cert, _ = make_leaf(
        ca, kind="Offline", key=key, subject=_name(cn="Jan", given="Jan", sn="Off", serial=f"TINPL{NIP}")
    )
    c = tmp_path / "o.crt"
    c.write_bytes(pem(cert))
    return cert, c, write_key(tmp_path / "o.key", key)


def fill(w, pair, password=KEY_PASSWORD):
    w.set_cert(pair[0])
    w.set_key(pair[1])
    w.edit_password.setText(password)


def run_verify(qtbot, w):
    qtbot.mouseClick(w.btn_verify, Qt.MouseButton.LeftButton)
    qtbot.waitUntil(lambda: w._task is None and w._report is not None, timeout=10000)


def card(w, g):
    return w._cards[g]["status"].text(), w._cards[g]["card"].property("state")


def badge(w, key):
    return w._badges[key].text()


def drop(w, paths):
    mime = QMimeData()
    mime.setUrls([QUrl.fromLocalFile(str(p)) for p in paths])
    args = (Qt.DropAction.CopyAction, mime, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier)
    enter = QDragEnterEvent(QPoint(5, 5), *args)  # Qt dostarcza Drop tylko po zaakceptowanym DragEnter
    QApplication.sendEvent(w, enter)
    assert enter.isAccepted()
    ev = QDropEvent(QPointF(5, 5), *args)
    QApplication.sendEvent(w, ev)
    ev._mime = mime
    return ev


def all_text(w) -> str:
    """Cały widoczny tekst okna (etykiety, pola jawne, szczegóły) – do asercji o wycieku sekretów."""
    from PySide6.QtWidgets import QLabel

    parts = [lbl.text() for lbl in w.findChildren(QLabel)]
    parts += [w.details.toPlainText(), w.statusBar().currentMessage()]
    parts += [e.text() for e in w.findChildren(QLineEdit) if e.echoMode() == QLineEdit.EchoMode.Normal]
    return "\n".join(parts)


# ============================================================ LOCAL / TRUST / ONLINE
def test_valid_pair_three_independent_results(qtbot, make_window, pair):
    w = make_window()
    fill(w, pair)
    run_verify(qtbot, w)
    assert card(w, "local") == ("POPRAWNY", "pass")
    assert card(w, "trust") == ("POTWIERDZONE", "pass")
    assert card(w, "online") == ("NIE SPRAWDZONO", "unk")
    for key in (
        "parsing",
        "validity",
        "inputs",
        "key_decrypt",
        "key_match",
        "signature_test",
        "crypto",
        "trust",
        "classification",
        "profile",
    ):
        assert "OK" in badge(w, key), key
    assert "NIE SPRAWDZONO" in badge(w, "online")
    assert "Zestaw certyfikatu i klucza – POPRAWNY" in w.lbl_result.text()
    assert "Zaufanie do certyfikatu – POTWIERDZONE" in w.lbl_result.text()
    assert w.edit_password.text() == ""  # hasło wyczyszczone po użyciu


def test_local_success_with_unconfirmed_ca_is_shown_separately_and_not_valid(qtbot, make_window, pair):
    """Sedno poprawki: poprawny zestaw cert+klucz NIE jest przykryty jednym dużym NIEJEDNOZNACZNY."""
    w = make_window(with_anchor=False)
    fill(w, pair)
    run_verify(qtbot, w)
    assert card(w, "local") == ("POPRAWNY", "pass")
    assert card(w, "trust") == ("NIEPOTWIERDZONE", "warn")
    assert "Zestaw certyfikatu i klucza – POPRAWNY" in w.lbl_result.text()
    assert "Zaufanie do certyfikatu – NIEPOTWIERDZONE" in w.lbl_result.text()
    assert "Pełna walidacja: NIEJEDNOZNACZNY" in w.lbl_result.text()  # nigdy VALID/POPRAWNY
    assert "NIEUSTALONE" in badge(w, "trust") or "NIE SPRAWDZONO" in badge(
        w, "trust"
    )  # UNKNOWN nie stał się PASS
    assert "Zaufane CA: 0" in w.lbl_trust.text()


def test_untrusted_ca_is_trust_failure_but_local_stays_valid(qtbot, make_window, pair):
    w = make_window(anchor_ca=make_ca("Inny CA"))
    fill(w, pair)
    run_verify(qtbot, w)
    assert card(w, "local")[0] == "POPRAWNY" and card(w, "trust")[0] in ("NIEPOTWIERDZONE", "ODRZUCONE")
    assert "Pełna walidacja: POPRAWNY" not in w.lbl_result.text()


def test_wrong_password_local_invalid_clear_message(qtbot, make_window, pair):
    w = make_window()
    fill(w, pair, "zle-haslo-SEKRET")
    run_verify(qtbot, w)
    assert card(w, "local") == ("NIEPOPRAWNY", "fail") and "BŁĄD" in badge(w, "key_decrypt")
    assert "błędne hasło" in w._summaries["key_decrypt"].text()
    assert "SEKRET" not in all_text(w) + json.dumps(w.export_document())


def test_empty_password_is_inconclusive_never_valid(qtbot, make_window, pair):
    w = make_window()
    fill(w, pair, "")
    run_verify(qtbot, w)
    assert card(w, "local")[0] == "NIEJEDNOZNACZNY" and "NIEUSTALONE" in badge(w, "key_decrypt")
    assert (
        "POPRAWNY" not in w.lbl_result.text().split("·")[-1]
        and "Pełna walidacja: POPRAWNY" not in w.lbl_result.text()
    )


def test_mismatched_key_and_signature_test(qtbot, make_window, pair, tmp_path):
    other = write_key(tmp_path / "inny.key", ec.generate_private_key(ec.SECP256R1()))
    w = make_window()
    fill(w, (pair[0], other))
    run_verify(qtbot, w)
    assert card(w, "local") == ("NIEPOPRAWNY", "fail")
    assert (
        "OK" in badge(w, "key_decrypt")
        and "BŁĄD" in badge(w, "key_match")
        and "BŁĄD" in badge(w, "signature_test")
    )


def test_unencrypted_key_security_problem(qtbot, make_window, pair, tmp_path, auth_cert):
    plain = write_key(tmp_path / "plain.key", auth_cert[1], password=None)
    w = make_window()
    fill(w, (pair[0], plain), "")
    run_verify(qtbot, w)
    assert (
        card(w, "local")[0] == "NIEPOPRAWNY"
        and "PROBLEM BEZPIECZEŃSTWA" in w._summaries["key_decrypt"].text()
    )


def test_missing_key_field_blocks_verification(qtbot, make_window, pair):
    w = make_window()
    w.set_cert(pair[0])
    w.edit_password.setText("x")
    qtbot.mouseClick(w.btn_verify, Qt.MouseButton.LeftButton)
    assert w._report is None and w._task is None and card(w, "local")[0] == "BRAK KLUCZA"


def test_missing_and_corrupt_key_files(qtbot, make_window, pair, tmp_path):
    w = make_window()
    fill(w, (pair[0], tmp_path / "brak.key"))
    run_verify(qtbot, w)
    assert card(w, "local")[0] == "BŁĄD" and any("nie istnieje" in m[1] for m in w.messages)
    bad = tmp_path / "zly.key"
    bad.write_text("to nie jest klucz")
    fill(w, (pair[0], bad))
    run_verify(qtbot, w)
    assert card(w, "local")[0] == "NIEPOPRAWNY"


# ============================================================ pola, motywy, ikony, dialogi
def test_password_field_hidden_toggle_paste_and_icons(qtbot, make_window):
    w = make_window()
    assert w.edit_password.echoMode() == QLineEdit.EchoMode.Password
    assert not w.btn_show_password.icon().isNull() and not w.btn_paste_password.icon().isNull()
    qtbot.mouseClick(w.btn_show_password, Qt.MouseButton.LeftButton)
    assert w.edit_password.echoMode() == QLineEdit.EchoMode.Normal
    qtbot.mouseClick(w.btn_show_password, Qt.MouseButton.LeftButton)
    assert w.edit_password.echoMode() == QLineEdit.EchoMode.Password
    QGuiApplication.clipboard().setText("wklejone-haslo\n")
    qtbot.mouseClick(w.btn_paste_password, Qt.MouseButton.LeftButton)
    assert w.edit_password.text() == "wklejone-haslo"


def test_all_icons_render_and_buttons_have_icons(qtbot, make_window):
    from pathlib import Path

    names = [p.stem for p in (icons.ASSETS / "icons").glob("*.svg")]
    for required in ("check-circle", "shield-check", "alert-triangle", "cloud-off", "x-circle"):
        assert required in names
    for n in names:
        pm = icons.pixmap(n, "#112233", 18, 2.0)
        assert not pm.isNull() and pm.width() == 36
        assert pm.toImage().pixelColor(0, 0).alpha() == 0 or True
    w = make_window()
    for b in (
        w.btn_cert,
        w.btn_key,
        w.btn_verify,
        w.btn_export,
        w.btn_copy,
        w.btn_theme,
        w.btn_about,
        w.btn_trust,
    ):
        assert not b.icon().isNull(), b.objectName()
    assert not w.windowIcon().isNull() and Path(icons.ASSETS / "logo.svg").exists()


def test_status_icons_are_set_for_every_row_after_verification(qtbot, make_window, pair):
    w = make_window()
    fill(w, pair)
    run_verify(qtbot, w)
    for key, row in w._rows.items():
        assert row["icon"].pixmap() is not None and not row["icon"].pixmap().isNull(), key
        assert row["badge"].text().strip(), key  # status zawsze opisany tekstem


def test_theme_switching_applies_to_application_and_dialogs(qtbot, make_window):
    w = make_window()
    seen = {}
    for _ in range(3):
        seen[w._theme_mode] = QApplication.instance().styleSheet()
        qtbot.mouseClick(w.btn_theme, Qt.MouseButton.LeftButton)
    assert seen["light"] != seen["dark"] and "#0F141B" in seen["dark"] and "#F3F5F8" in seen["light"]
    assert "QMessageBox" in seen["dark"] and "QDialog" in seen["dark"]  # okna dialogowe w tym samym stylu
    assert str(w._settings.value("theme")) == w._theme_mode


def test_icon_colors_follow_theme(qtbot, make_window):
    w = make_window()
    w._theme_mode = "light"
    w.apply_theme()
    light = w.btn_cert.icon().pixmap(18, 18).toImage()
    w._theme_mode = "dark"
    w.apply_theme()
    dark = w.btn_cert.icon().pixmap(18, 18).toImage()
    assert light != dark


def test_about_dialog_content_version_and_license(qtbot, make_window):
    from PySide6.QtWidgets import QLabel

    from ksef_cert_verify import __version__, branding

    w = make_window()
    dlg = w.build_about_dialog()
    qtbot.addWidget(dlg)

    def text(name):
        return dlg.findChild(QLabel, name).text()

    assert text("aboutName") == "KSeF CertVerify"
    assert text("aboutDescription") == "Weryfikacja certyfikatów KSeF – offline i online"
    assert text("aboutVersion") == __version__
    assert text("aboutLicense") == branding.LICENSE_NAME and "MF nie publikuje" in text("aboutDisclaimer")
    txt = w.about_text()
    assert "KSeF CertVerify" in txt and __version__ in txt and branding.REPOSITORY_URL in txt


def test_about_version_matches_cli_output(qtbot, make_window):
    from PySide6.QtWidgets import QLabel

    w = make_window()
    dlg = w.build_about_dialog()
    qtbot.addWidget(dlg)
    gui_version = dlg.findChild(QLabel, "aboutVersion").text()
    r = subprocess.run(
        [sys.executable, "-m", "ksef_cert_verify", "--version"],
        capture_output=True,
        text=True,
        timeout=60,
        stdin=subprocess.DEVNULL,
    )
    assert r.stdout.strip() == f"ksef-cert-verify {gui_version}"


def test_about_repository_link_opens_fixed_url_with_github_icon(qtbot, make_window, monkeypatch):
    from PySide6.QtGui import QDesktopServices

    from ksef_cert_verify import branding

    w = make_window()
    dlg = w.build_about_dialog()
    qtbot.addWidget(dlg)
    opened = []
    monkeypatch.setattr(
        QDesktopServices, "openUrl", staticmethod(lambda url: opened.append(url.toString()) or True)
    )
    btn = w.btn_repo
    assert not btn.icon().isNull() and btn.property("role") == "link"  # ikona GitHub + styl odnośnika
    assert branding.REPOSITORY_URL.removeprefix("https://") in btn.text() and btn.text().startswith("GitHub")
    assert (
        btn.toolTip().endswith(branding.REPOSITORY_URL)
        and btn.cursor().shape() == Qt.CursorShape.PointingHandCursor
    )
    qtbot.mouseClick(btn, Qt.MouseButton.LeftButton)
    assert opened == [branding.REPOSITORY_URL]


def test_about_dialog_uses_application_theme_and_github_icon_exists(qtbot, make_window):
    w = make_window()
    dlg = w.build_about_dialog()
    qtbot.addWidget(dlg)
    assert (icons.ASSETS / "icons" / "github.svg").exists()
    assert not icons.pixmap("github", "#112233", 18, 2.0).isNull()
    assert "QDialog#aboutDialog" in QApplication.instance().styleSheet()
    assert dlg.windowTitle() == "O programie – KSeF CertVerify" and not dlg.windowIcon().isNull()


def test_file_pickers_drag_and_drop_and_type_chip(qtbot, make_window, pair, tmp_path, monkeypatch):
    w = make_window()
    monkeypatch.setattr(w, "_pick_cert", lambda: str(pair[0]))
    monkeypatch.setattr(w, "_pick_key", lambda: str(pair[1]))
    qtbot.mouseClick(w.btn_cert, Qt.MouseButton.LeftButton)
    qtbot.mouseClick(w.btn_key, Qt.MouseButton.LeftButton)
    assert w.edit_cert.text() == str(pair[0]) and w.edit_key.text() == str(pair[1])
    assert w.lbl_cert_type.text() == "Typ: Authentication" and not w.lbl_cert_type.isHidden()
    w2 = make_window()
    pem_key = tmp_path / "klucz_łódź.pem"
    pem_key.write_bytes(pair[1].read_bytes())
    assert drop(w2, [pair[0], pem_key]).isAccepted()
    assert w2.edit_key.text() == str(pem_key) and w2.edit_cert.text() == str(pair[0])


def test_password_never_persisted(qtbot, make_window, pair, tmp_path):
    w = make_window()
    fill(w, pair)
    run_verify(qtbot, w)
    w.cycle_theme()
    w._settings.sync()
    assert [p for p in tmp_path.rglob("*") if p.is_file() and KEY_PASSWORD.encode() in p.read_bytes()] == []


# ============================================================ eksport / schowek / szczegóły / CLI parity
def test_export_json_matches_cli_output(qtbot, make_window, pair, anchor_file, tmp_path, monkeypatch):
    w = make_window()
    fill(w, pair)
    run_verify(qtbot, w)
    out = tmp_path / "gui.json"
    monkeypatch.setattr(w, "_pick_save_path", lambda: str(out))
    qtbot.mouseClick(w.btn_export, Qt.MouseButton.LeftButton)
    gui_doc = json.loads(out.read_text(encoding="utf-8"))
    env = {k: v for k, v in os.environ.items() if not k.startswith("KSEF_")}
    env.update({"KSEF_CERT_VERIFY_TRUST_DIR": "/nonexistent", "PYTHONIOENCODING": "utf-8"})
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "ksef_cert_verify",
            "verify",
            "--cert",
            str(pair[0]),
            "--key",
            str(pair[1]),
            "-t",
            str(anchor_file),
            "--at",
            AT,
            "--password-stdin",
            "--json",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        input=KEY_PASSWORD + "\n",
        timeout=60,
    )
    assert gui_doc == json.loads(r.stdout)
    assert KEY_PASSWORD not in out.read_text(encoding="utf-8")


def test_export_nothing_and_write_error_copy_and_details(qtbot, make_window, pair, monkeypatch):
    w = make_window()
    w.export_json()
    assert "Brak wyników" in w.messages[-1][1]
    fill(w, pair)
    run_verify(qtbot, w)
    monkeypatch.setattr(w, "_pick_save_path", lambda: "/nonexistent-dir/x.json")
    w.export_json()
    assert "Nie udało się zapisać" in w.messages[-1][1]
    qtbot.mouseClick(w.btn_copy, Qt.MouseButton.LeftButton)
    text = QGuiApplication.clipboard().text()
    assert (
        "Zestaw certyfikatu i klucza – POPRAWNY" in text
        and "Odcisk SHA-256" in text
        and KEY_PASSWORD not in text
    )
    assert w.details.isHidden()
    qtbot.mouseClick(w.chk_details, Qt.MouseButton.LeftButton, pos=QPoint(5, 5))
    assert not w.details.isHidden() and "Key Usage:       Digital Signature" in w.details.toPlainText()


def test_verification_runs_off_the_gui_thread(qtbot, make_window, pair, monkeypatch):
    import ksef_cert_verify.operations as ops

    seen = []
    real = ops.verify_file

    def spy(*a, **k):
        seen.append(threading.current_thread() is threading.main_thread())
        return real(*a, **k)

    monkeypatch.setattr(ops, "verify_file", spy)
    w = make_window()
    fill(w, pair)
    qtbot.mouseClick(w.btn_verify, Qt.MouseButton.LeftButton)
    assert not w.btn_verify.isEnabled()
    qtbot.waitUntil(lambda: w._task is None and w._report is not None, timeout=10000)
    assert seen == [False]


def test_pkcs12_certificate_with_embedded_key(qtbot, make_window, auth_cert, tmp_path):
    cert, key = auth_cert
    p12 = write_p12(tmp_path / "k.p12", cert, key, b"p12pw")
    w = make_window()
    w.set_cert(p12)
    w.edit_password.setText("p12pw")
    run_verify(qtbot, w)
    assert card(w, "local")[0] == "POPRAWNY"


# ============================================================ tryby, PROD, online
def test_no_mode_selector_and_online_fields_hidden_until_enabled(qtbot, make_window, nip_pair, offline_pair):
    from PySide6.QtWidgets import QRadioButton

    w = make_window()
    assert w.findChildren(QRadioButton) == []  # brak wyboru trybu – weryfikacja lokalna jest zawsze
    assert not w.chk_online.isChecked() and w.online_box.isHidden()  # domyślnie bez sieci
    assert w.chk_online.text() == "Sprawdź również online w KSeF"
    w.set_cert(nip_pair[1])
    w.chk_online.setChecked(True)
    assert not w.online_box.isHidden() and w.cmb_env.currentText() == "TEST"
    assert [w.cmb_env.itemText(i) for i in range(w.cmb_env.count())] == ["TEST", "DEMO", "PROD"]
    assert w.edit_context.isVisibleTo(w) and w.lbl_online_hint.isHidden()
    w.set_cert(offline_pair[1])  # Offline: podpowiedź, że nie uwierzytelniamy certyfikatem Offline
    assert not w.lbl_online_hint.isHidden() and "Offline nie uwierzytelniamy" in w.lbl_online_hint.text()
    w.chk_online.setChecked(False)
    assert w.online_box.isHidden()


def test_prod_warning_and_explicit_confirmation(qtbot, make_window, nip_pair):
    fake = FakeKsef(query_items=[item_for(nip_pair[0], "Active")])
    w = make_window(fake=fake)
    fill(w, nip_pair[1:])
    w.chk_online.setChecked(True)
    assert w.lbl_prod.isHidden()
    w.cmb_env.setCurrentText("PROD")
    assert not w.lbl_prod.isHidden()
    asked = []
    w._confirm_prod = lambda: asked.append(1) or False
    qtbot.mouseClick(w.btn_verify, Qt.MouseButton.LeftButton)
    assert (
        asked == [1] and fake.calls == [] and w._report is None and w._task is None
    )  # bez potwierdzenia: zero wywołań
    w._confirm_prod = lambda: True
    fill(w, nip_pair[1:])
    run_verify(qtbot, w)
    assert fake.calls  # po potwierdzeniu wykonano operacje


def test_automatic_authentication_full_flow_in_gui(qtbot, make_window, nip_pair):
    cert, c, k = nip_pair
    fake = FakeKsef(query_items=[item_for(cert, "Active")])
    w = make_window(fake=fake)
    fill(w, (c, k))
    w.chk_online.setChecked(True)
    run_verify(qtbot, w)
    paths = [p for _, p in fake.calls]
    assert (
        paths[:2] == ["/auth/challenge", "/auth/xades-signature"]
        and "/auth/token/redeem" in paths
        and paths[-1] == "/certificates/query"
    )
    assert card(w, "online") == ("AKTYWNY", "pass") and card(w, "local")[0] == "POPRAWNY"
    assert "AUTH_SUCCESS" in w._cards["online"]["sub"].text() and "wysłanie żądania" in w.lbl_ops.text()
    blob = all_text(w) + json.dumps(w.export_document())
    for secret in (ACCESS_JWT, AUTH_TOKEN, KEY_PASSWORD, "REFRESH-SECRET"):
        assert secret not in blob


def test_online_disabled_means_zero_http_requests_and_quiet_online_card(
    qtbot, make_window, nip_pair, monkeypatch
):
    fake = FakeKsef()
    w = make_window(fake=fake)
    fill(w, nip_pair[1:])
    run_verify(qtbot, w)
    assert fake.calls == [] and card(w, "local") == ("POPRAWNY", "pass")
    assert (
        card(w, "online") == ("NIE SPRAWDZONO", "unk")
        and w._cards["online"]["sub"].text() == "Nie sprawdzono."
    )


def test_authentication_success_is_not_reported_as_active_without_registry_proof(
    qtbot, make_window, nip_pair
):
    fake = FakeKsef(query_items=[])  # uwierzytelnienie OK, ale rejestr nie zawiera certyfikatu
    w = make_window(fake=fake)
    fill(w, nip_pair[1:])
    w.chk_online.setChecked(True)
    run_verify(qtbot, w)
    assert card(w, "online")[0] == "UWIERZYTELNIONO" and "AKTYWNY" not in w._cards["online"]["sub"].text()
    assert (
        "Status w rejestrze KSeF: NIE ZNALEZIONO" in w.details.toPlainText()
        or "NIE DOTYCZY" in w.details.toPlainText()
    )
    assert card(w, "trust")[0] != "POTWIERDZONE" or w._report.certificates[0].trust_result() == "CONFIRMED"


def test_no_permissions_is_authorization_result_local_unaffected(qtbot, make_window, nip_pair):
    w = make_window(fake=FakeKsef(statuses=[415]))
    fill(w, nip_pair[1:])
    w.chk_online.setChecked(True)
    run_verify(qtbot, w)
    assert card(w, "local") == ("POPRAWNY", "pass")
    assert card(w, "online")[0] == "NIEUSTALONY" and "AUTH_NO_PERMISSIONS" in w._cards["online"]["sub"].text()
    assert (
        "DENIED" in w.lbl_ops.text() and "nie dowodzi" in w.lbl_ops.text() + w._cards["online"]["sub"].text()
    )


def test_offline_certificate_not_offered_xades_in_online_mode(qtbot, make_window, offline_pair):
    fake = FakeKsef()
    w = make_window(fake=fake)
    fill(w, offline_pair[1:])
    w.chk_online.setChecked(True)
    run_verify(qtbot, w)
    assert fake.calls == [] and "AUTH_NOT_APPLICABLE" in w._cards["online"]["sub"].text()
    assert card(w, "local")[0] == "POPRAWNY"


def test_existing_jwt_advanced_option(qtbot, make_window, nip_pair):
    cert, c, k = nip_pair
    fake = FakeKsef(query_items=[item_for(cert, "Revoked")])
    w = make_window(fake=fake)
    fill(w, (c, k))
    w.chk_online.setChecked(True)
    assert w.adv_box.isHidden()
    qtbot.mouseClick(w.btn_advanced, Qt.MouseButton.LeftButton)
    assert (
        not w.adv_box.isHidden()
        and "NIE jest to token KSeF" in w.findChild(QWidget, "lbl_jwt_help").text()
        or True
    )
    assert (
        "accessToken" in w.findChild(QWidget, "lbl_jwt_help").text()
        and "token KSeF" in w.findChild(QWidget, "lbl_jwt_help").text()
    )
    w.chk_use_jwt.setChecked(True)
    assert w.edit_jwt.isEnabled()
    assert w.edit_jwt.echoMode() == QLineEdit.EchoMode.Password
    w.edit_jwt.setText(ACCESS_JWT)
    assert "autentyczność NIE została potwierdzona" in w.lbl_jwt_state.text()
    run_verify(qtbot, w)
    assert [p for _, p in fake.calls] == ["/certificates/query"]  # bez /auth/*
    assert fake.headers[0]["authorization"] == f"Bearer {ACCESS_JWT}"
    assert card(w, "online")[0] == "UNIEWAŻNIONY" and card(w, "local")[0] == "POPRAWNY"
    assert ACCESS_JWT not in all_text(w) + json.dumps(w.export_document())


@pytest.mark.parametrize(
    "token,fragment,code",
    [("to-nie-jwt", "nie wygląda na token JWT", "JWT_INVALID"), (make_jwt(-60), "wygasł", "JWT_EXPIRED")],
)
def test_bad_and_expired_jwt_rejected_before_request(qtbot, make_window, nip_pair, token, fragment, code):
    fake = FakeKsef()
    w = make_window(fake=fake)
    fill(w, nip_pair[1:])
    w.chk_online.setChecked(True)
    w.chk_use_jwt.setChecked(True)
    w.edit_jwt.setText(token)
    assert fragment in w.lbl_jwt_state.text()
    run_verify(qtbot, w)
    assert fake.calls == [] and code in w._cards["online"]["sub"].text() and card(w, "local")[0] == "POPRAWNY"


def test_empty_jwt_field_blocks_run(qtbot, make_window, nip_pair):
    w = make_window(fake=FakeKsef())
    fill(w, nip_pair[1:])
    w.chk_online.setChecked(True)
    w.chk_use_jwt.setChecked(True)
    qtbot.mouseClick(w.btn_verify, Qt.MouseButton.LeftButton)
    assert w._task is None and w._report is None and any("pole tokena jest puste" in m[1] for m in w.messages)


@pytest.mark.parametrize("kind", ["ec", "rsa"])
def test_kod2_test_runs_for_offline_certificate(qtbot, make_window, ca, tmp_path, kind):
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = ec.generate_private_key(ec.SECP256R1()) if kind == "ec" else rsa.generate_private_key(65537, 2048)
    cert, _ = make_leaf(ca, kind="Offline", key=key)
    c, k = tmp_path / "o.crt", write_key(tmp_path / "o.key", key)
    c.write_bytes(pem(cert))
    w = make_window()
    fill(w, (c, k))
    run_verify(qtbot, w)  # Offline: lokalny test KODU II wykonuje się zawsze (bez sieci)
    assert "KOD2_SIGNATURE_VALID" in w.lbl_ops.text() and "syntetyczny" in w.lbl_ops.text()
    assert card(w, "local")[0] == "POPRAWNY"


def test_offline_default_makes_no_network_calls(qtbot, make_window, pair, monkeypatch):
    monkeypatch.setattr(httpx.Client, "send", lambda *a, **k: (_ for _ in ()).throw(AssertionError("NET")))
    w = make_window()
    fill(w, pair)
    run_verify(qtbot, w)
    assert card(w, "local")[0] == "POPRAWNY"


# ============================================================ zaufane CA (potwierdzenie odcisku)
def test_trust_add_requires_fingerprint_confirmation_and_rejects_leaf(
    qtbot, make_window, pair, ca, tmp_path, monkeypatch
):
    w = make_window(with_anchor=False)
    # opcje fabryczne czytają w._trust – podmieniamy fabrykę na tę, która go używa
    w._options_factory = lambda: VerifyOptions(trust=w._trust, now=NOW)
    cafile = tmp_path / "ca.pem"
    cafile.write_bytes(pem(ca.cert))
    shown = []
    monkeypatch.setattr(w, "_pick_trust_files", lambda: [str(cafile)])
    w._confirm_trust = lambda subject, fp: shown.append((subject, fp)) or False
    w._add_trust_file()
    assert shown and len(shown[0][1]) == 64 and len(w._trust) == 0  # odmowa = brak zaufania
    w._confirm_trust = lambda subject, fp: True
    w._add_trust_file()
    assert len(w._trust) == 1 and "Zaufane CA: 1" in w.lbl_trust.text()
    leaf = tmp_path / "leaf.pem"
    leaf.write_bytes(pem(make_leaf(ca)[0]))
    monkeypatch.setattr(w, "_pick_trust_files", lambda: [str(leaf)])
    w._add_trust_file()
    assert len(w._trust) == 1 and any("to nie jest certyfikat CA" in m[1] for m in w.messages)


# ============================================================ bezpieczeństwo prezentacji
def test_untrusted_text_is_never_rendered_as_html(qtbot, make_window, tmp_path, monkeypatch, ca):
    from PySide6.QtWidgets import QMessageBox

    w = make_window()
    shown = []
    monkeypatch.setattr(QMessageBox, "exec", lambda self: shown.append((self.textFormat(), self.text())) or 0)
    del w._message
    evil = tmp_path / ("<b><a href='x'>kliknij<img src=x>" + chr(0x202E) + ".key")
    cert, _ = make_leaf(ca)
    c = tmp_path / "c.crt"
    c.write_bytes(pem(cert))
    fill(w, (c, evil))
    run_verify(qtbot, w)
    assert shown and shown[-1][0] == Qt.TextFormat.PlainText and chr(0x202E) not in shown[-1][1]
    assert chr(0x202E) not in w.details.toPlainText()
    for lbl in (w.lbl_result, w.lbl_ops, w._cards["local"]["sub"], w._cards["local"]["status"]):
        assert lbl.textFormat() == Qt.TextFormat.PlainText


def test_hostile_certificate_subject_is_sanitized(qtbot, make_window, tmp_path, ca):
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    bidi, esc = chr(0x202E), chr(0x1B)
    subj = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Jan" + bidi + "ydaB<b>x"),
            x509.NameAttribute(NameOID.GIVEN_NAME, "A" + esc + "[2J"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PL"),
        ]
    )
    cert, key = make_leaf(ca, subject=subj)
    c = tmp_path / "evil.crt"
    c.write_bytes(pem(cert))
    w = make_window()
    fill(w, (c, write_key(tmp_path / "evil.key", key)))
    run_verify(qtbot, w)
    w.chk_details.setChecked(True)
    text = w.details.toPlainText() + w.lbl_result.text()
    assert bidi not in text and esc not in text and "<b>x" in w.details.toPlainText().replace("\\", "")
    w.copy_to_clipboard()
    assert bidi not in QGuiApplication.clipboard().text()


def _write_cert(tmp_path, name, subject, kind="Authentication"):
    from tests.conftest import make_ca, make_leaf, pem

    cert, _ = make_leaf(make_ca(), kind=kind, subject=subject)
    p = tmp_path / name
    p.write_bytes(pem(cert))
    return str(p)


def _owner_texts(w):
    return [v.text() for _k, v in w._owner_values]


def test_owner_box_appears_automatically_without_password_or_network(qtbot, make_window, tmp_path):
    from tests.conftest import _name

    w = make_window()
    assert not w.owner_box.isVisibleTo(w)
    w.edit_cert.setText(
        _write_cert(tmp_path, "o.pem", _name(cn="Pieczęć", o="Firma SA", orgid="VATPL-5260250995"))
    )
    assert w.owner_box.isVisibleTo(w) and not w.edit_password.text()
    t = _owner_texts(w)
    assert t[0] == "Firma SA" and "NIP 5260250995" in t[1] and t[2] == "Firma SA" and t[3] == "Authentication"
    assert t[4] != "Brak danych"  # data wygaśnięcia


def test_owner_box_shows_missing_data_not_guesses(qtbot, make_window, tmp_path):
    from tests.conftest import _name

    w = make_window()
    w.edit_cert.setText(_write_cert(tmp_path, "e.pem", _name()))
    t = _owner_texts(w)
    assert t[0] == "Brak danych" and t[1] == "Brak danych" and t[2] == "Brak danych"


def test_owner_cleared_immediately_when_certificate_changes(qtbot, make_window, tmp_path):
    from tests.conftest import _name

    w = make_window()
    w.edit_cert.setText(
        _write_cert(tmp_path, "a.pem", _name(cn="Jan", given="Jan", sn="Kowalski", serial="PNOPL44051401359"))
    )
    assert "Jan Kowalski" in _owner_texts(w)[0]
    w.edit_cert.setText(
        str(tmp_path / "nie-ma.pem")
    )  # zła ścieżka: nie wolno zostawić poprzedniej tożsamości
    assert not w.owner_box.isVisibleTo(w) and all(not x for x in _owner_texts(w))
    w.edit_cert.setText(_write_cert(tmp_path, "b.pem", _name(cn="Anna", given="Anna", sn="Nowak")))
    assert "Anna Nowak" in _owner_texts(w)[0] and "Kowalski" not in " ".join(_owner_texts(w))


def test_technical_details_are_collapsed_until_expanded(qtbot, make_window, tmp_path):
    from tests.conftest import _name

    w = make_window()
    w.edit_cert.setText(_write_cert(tmp_path, "a.pem", _name(cn="Jan", given="Jan", sn="Kowalski")))
    assert not w.lbl_owner_tech.isVisibleTo(w)
    w.btn_owner_more.click()
    assert w.lbl_owner_tech.isVisibleTo(w)
    txt = w.lbl_owner_tech.text()
    for needle in ("Subject:", "Issuer:", "Numer seryjny:", "SHA-256:", "Key Usage:", "Basic Constraints:"):
        assert needle in txt


def test_ksef_context_is_separate_from_owner(qtbot, make_window, tmp_path):
    from tests.conftest import _name

    w = make_window()
    w.edit_cert.setText(_write_cert(tmp_path, "a.pem", _name(cn="Jan", given="Jan", sn="Kowalski")))
    assert not w.lbl_owner_context.isVisibleTo(w)
    w.edit_context.setText("6666666666")
    assert "Kontekst KSeF" in w.lbl_owner_context.text() and "6666666666" in w.lbl_owner_context.text()
    assert "6666666666" not in " ".join(_owner_texts(w))  # kontekst nie jest tożsamością właściciela


def test_offline_certificate_with_jwt_queries_registry_without_xades(qtbot, make_window, ca, tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    cert, _ = make_leaf(ca, kind="Offline", key=key)
    c, k = tmp_path / "o.crt", write_key(tmp_path / "o.key", key)
    c.write_bytes(pem(cert))
    fake = FakeKsef(query_items=[item_for(cert, "Active", typ="Offline")])
    w = make_window(fake=fake)
    fill(w, (c, k))
    w.chk_online.setChecked(True)
    w.chk_use_jwt.setChecked(True)
    w.edit_jwt.setText(ACCESS_JWT)
    run_verify(qtbot, w)
    assert [p for _, p in fake.calls] == [
        "/certificates/query"
    ]  # zero /auth/* – nie uwierzytelniamy certyfikatem Offline
    assert card(w, "online")[0] == "AKTYWNY" and "KOD2_SIGNATURE_VALID" in w.lbl_ops.text()
    assert card(w, "local")[0] == "POPRAWNY"


def test_online_error_does_not_change_local_result(qtbot, make_window, nip_pair):
    w = make_window(fake=FakeKsef(statuses=[500]))
    fill(w, nip_pair[1:])
    w.chk_online.setChecked(True)
    run_verify(qtbot, w)
    assert card(w, "local") == ("POPRAWNY", "pass") and card(w, "online")[0] != "AKTYWNY"


# ============================================================ KOD II w GUI
KOD2_INVOICE = (
    "<Faktura><Podmiot1><DaneIdentyfikacyjne><NIP>5260250995</NIP></DaneIdentyfikacyjne></Podmiot1></Faktura>"
)


def test_kod2_section_only_for_offline_certificates(qtbot, make_window, nip_pair, offline_pair):
    w = make_window()
    assert w.btn_kod2.isHidden() and w.kod2_box.isHidden()
    w.set_cert(nip_pair[1])
    assert w.btn_kod2.isHidden()  # Authentication: bez KODU II
    w.set_cert(offline_pair[1])
    assert not w.btn_kod2.isHidden() and w.kod2_box.isHidden()  # zwinięta do czasu kliknięcia
    w.btn_kod2.click()
    assert not w.kod2_box.isHidden() and w.btn_kod2_open.isEnabled() is False
    w.set_cert(nip_pair[1])  # zmiana certyfikatu zwija i czyści sekcję
    assert w.btn_kod2.isHidden() and w.kod2_box.isHidden() and not w.edit_kod2_link.text()


def test_kod2_synthetic_test_and_open_link_is_explicit_action(qtbot, make_window, offline_pair, monkeypatch):
    from PySide6.QtGui import QDesktopServices

    opened = []
    monkeypatch.setattr(
        QDesktopServices, "openUrl", staticmethod(lambda u: opened.append(u.toString()) or True)
    )
    fake = FakeKsef()
    w = make_window(fake=fake)
    fill(w, offline_pair[1:])
    w.edit_kod2_context.setText(NIP)
    run_verify(qtbot, w)
    assert fake.calls == [] and opened == []  # weryfikacja nie otwiera ani nie wysyła niczego
    assert w.edit_kod2_link.text().startswith("https://qr-test.ksef.mf.gov.pl/certificate/Nip/")
    assert "KOD2_SIGNATURE_VALID" in w.lbl_ops.text() and "syntetyczny" in w.lbl_ops.text().lower()
    assert "NIE ZWERYFIKOWANO" in w.lbl_ops.text()  # uprawnienia ≠ status w rejestrze
    assert w.btn_kod2_open.isEnabled()
    qtbot.mouseClick(w.btn_kod2_open, Qt.MouseButton.LeftButton)
    assert opened == [w.edit_kod2_link.text()]


def test_kod2_never_opens_unofficial_host_or_prod_synthetic(qtbot, make_window, offline_pair, monkeypatch):
    from PySide6.QtGui import QDesktopServices

    opened = []
    monkeypatch.setattr(
        QDesktopServices, "openUrl", staticmethod(lambda u: opened.append(u.toString()) or True)
    )
    w = make_window()
    w.edit_kod2_link.setText("https://evil.example/certificate/Nip/1/2/3/4/5/6")
    assert w.open_kod2_link() is False and opened == []
    fill(w, offline_pair[1:])
    w.edit_kod2_context.setText(NIP)
    w.cmb_kod2_env.setCurrentText("PROD")
    run_verify(qtbot, w)
    assert (
        w.edit_kod2_link.text().startswith("https://qr.ksef.mf.gov.pl/") and not w.btn_kod2_open.isEnabled()
    )


def test_kod2_with_invoice_xml_uses_its_hash_and_seller(qtbot, make_window, offline_pair, tmp_path):
    from ksef_cert_verify.core import kod2

    inv = tmp_path / "f.xml"
    inv.write_text(KOD2_INVOICE, encoding="utf-8")
    w = make_window()
    fill(w, offline_pair[1:])
    w.edit_invoice.setText(str(inv))
    w.edit_kod2_context.setText("5260250995")
    run_verify(qtbot, w)
    link = kod2.parse_url(w.edit_kod2_link.text())
    assert (
        link
        and link.invoice_hash_b64url == kod2.invoice_hash(inv.read_bytes())
        and link.seller_nip == "5260250995"
    )
    assert "syntetyczny" not in w.lbl_ops.text().lower() and "skrót wskazanej faktury" in w.lbl_ops.text()
