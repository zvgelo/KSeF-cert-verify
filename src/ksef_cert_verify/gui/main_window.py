"""Główne okno GUI (PySide6): weryfikacja pary certyfikat + klucz prywatny + hasło.

Trzy niezależne wyniki: LOCAL (zestaw cert+klucz+hasło), TRUST (zaufanie i profil KSeF) i ONLINE (status i uwierzytelnienie
w KSeF). Wyniki online nie wpływają na wyniki lokalne. Silnik jest ten sam co w CLI (`operations`, `core.report`).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from PySide6.QtCore import QSettings, Qt, QThreadPool, QUrl
from PySide6.QtGui import QAction, QDesktopServices, QDragEnterEvent, QDropEvent, QGuiApplication, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from ksef_cert_verify import __version__
from ksef_cert_verify.branding import (
    DISCLAIMER,
    LICENSE_NAME,
    PRODUCT_DESCRIPTION,
    PRODUCT_NAME,
    PRODUCT_SUBTITLE,
    REPOSITORY_URL,
)
from ksef_cert_verify.core.certificate_classifier import classify
from ksef_cert_verify.core.certificate_loader import LoaderError, load_file
from ksef_cert_verify.core.certificate_parser import fingerprint, parse_certificate
from ksef_cert_verify.core.models import GROUPS, CertReport, CertType, Check, CheckStatus, FileReport, Verdict
from ksef_cert_verify.core.report import VerifyOptions, build_json, dumps
from ksef_cert_verify.core.trust_store import TrustStore
from ksef_cert_verify.ksef_api.jwt_utils import describe, inspect_jwt
from ksef_cert_verify.operations import (
    CachedPassword,
    Kod2Setup,
    OnlineSession,
    OnlineSetup,
    run_kod2_test,
    verify_with_online,
)

from . import icons
from .theme import SPACE, build_qss, color
from .workers import JobTask

VERDICT_PL = {
    Verdict.VALID: "POPRAWNY",
    Verdict.INVALID: "NIEPOPRAWNY",
    Verdict.INDETERMINATE: "NIEJEDNOZNACZNY",
}
CHECK_WORD = {
    CheckStatus.PASS: "OK",
    CheckStatus.FAIL: "BŁĄD",
    CheckStatus.WARNING: "UWAGA",
    CheckStatus.UNKNOWN: "NIEUSTALONE",
    CheckStatus.NOT_CHECKED: "NIE SPRAWDZONO",
}
DETAIL_SYMBOL = {
    CheckStatus.PASS: "✓",
    CheckStatus.FAIL: "✗",
    CheckStatus.WARNING: "!",
    CheckStatus.UNKNOWN: "?",
    CheckStatus.NOT_CHECKED: "–",
}
CHECK_LABEL = {
    "parsing": "Odczyt certyfikatu",
    "validity": "Ważność czasowa",
    "inputs": "Kompletność danych",
    "key_decrypt": "Odszyfrowanie klucza prywatnego",
    "key_match": "Dopasowanie klucza do certyfikatu",
    "signature_test": "Test podpisu kryptograficznego",
    "crypto": "Podpis wystawcy i algorytmy",
    "trust": "Zaufany urząd certyfikacji",
    "classification": "Rozpoznany typ certyfikatu",
    "profile": "Zgodność z profilem KSeF",
    "online": "Status w API KSeF",
}
SECTIONS = [
    ("local", "LOCAL", "Zestaw certyfikatu i klucza"),
    ("trust", "TRUST", "Zaufanie i profil KSeF"),
    ("online", "ONLINE", "Status i uwierzytelnienie w KSeF"),
]
ONLINE_PL = {
    "NOT_CHECKED": "NIE SPRAWDZONO",
    "Active": "AKTYWNY",
    "Blocked": "ZABLOKOWANY",
    "Revoked": "UNIEWAŻNIONY",
    "Expired": "WYGASŁY",
    "NOT_FOUND": "NIE ZNALEZIONO",
    "UNKNOWN": "NIEUSTALONY",
}
THEME_LABEL = {"system": "Motyw: systemowy", "light": "Motyw: jasny", "dark": "Motyw: ciemny"}
MODE_LOCAL, MODE_ONLINE, MODE_AUTH, MODE_KOD2 = "local", "online", "auth", "kod2"

_UNSAFE_RANGES = [
    (0x00, 0x08),
    (0x0B, 0x1F),
    (0x7F, 0x9F),
    (0x2028, 0x2029),
    (0x202A, 0x202E),
    (0x2066, 0x2069),
]
# Zakresy budowane z liczb (a nie z literalnych znaków bidi w źródle – zabezpieczenie przed „Trojan Source”).
_UNSAFE = re.compile("[" + "".join(f"{chr(a)}-{chr(b)}" for a, b in _UNSAFE_RANGES) + "]")


def clean(text: object) -> str:
    """Usuwa znaki sterujące i bidi z tekstu pochodzącego z niezaufanych plików (zostawia \\n i \\t)."""
    return _UNSAFE.sub("?", str(text))


def _local_date(iso: str) -> str:
    dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    return dt.astimezone().strftime("%Y-%m-%d %H:%M")


def _na(v: object) -> str:
    return clean(v) if v else "Brak danych"


def subject_label(c: CertReport) -> str:
    s = c.info.subject_info
    name = " ".join([*s.given_names, s.surname or ""]).strip()
    return clean(name or s.organization or s.common_name or "Brak danych")


def row_summary(key: str, chk: Check, c: CertReport) -> str:
    if key == "classification":
        return f"Typ: {c.cert_type.value}" if c.cert_type.value != "UNKNOWN" else "Typ nieustalony (Unknown)"
    return chk.summary


def trust_word(c: CertReport) -> tuple[str, str]:
    return {
        "CONFIRMED": ("POTWIERDZONE", "pass"),
        "UNCONFIRMED": ("NIEPOTWIERDZONE", "warn"),
        "FAILED": ("ODRZUCONE", "fail"),
    }[c.trust_result()]


def local_word(c: CertReport) -> tuple[str, str]:
    v = c.local_result()
    return VERDICT_PL[v], {Verdict.VALID: "pass", Verdict.INVALID: "fail", Verdict.INDETERMINATE: "warn"}[v]


def online_word(c: CertReport) -> tuple[str, str]:
    st = c.online_status
    state = {
        "Active": "pass",
        "Blocked": "fail",
        "Revoked": "fail",
        "Expired": "fail",
        "UNKNOWN": "warn",
    }.get(st, "unk")
    return ONLINE_PL.get(st, st), state


def cert_details_text(fr: FileReport, c: CertReport, expanded: bool) -> str:
    i, s = c.info, c.info.subject_info
    lw, _ = local_word(c)
    tw, _ = trust_word(c)
    lines = [
        f"Plik:            {fr.path}",
        f"Typ:             {c.cert_type.value.upper()}",
        "",
        f"Zestaw certyfikatu i klucza – {lw}",
        f"Zaufanie do certyfikatu – {tw}",
        f"Status KSeF:     {ONLINE_PL.get(c.online_status, c.online_status)}",
        f"Pełna walidacja: {VERDICT_PL[c.verdict]}",
        "",
    ]
    for gkey, gname, gtitle in SECTIONS:
        lines.append(f"{gname} – {gtitle}:")
        for key in GROUPS[gkey]:
            chk = c.checks[key]
            lines.append(
                f"  {DETAIL_SYMBOL[chk.status]} {CHECK_LABEL[key]}: {CHECK_WORD[chk.status]} – {row_summary(key, chk, c)}"
            )
            if expanded or chk.status in (CheckStatus.FAIL, CheckStatus.WARNING, CheckStatus.UNKNOWN):
                lines.extend(f"      • {f.message}" for f in chk.findings)
        if gkey == "online":
            auth = c.operations.get("authentication")
            if auth:
                lines.append(f"  Uwierzytelnienie: {auth['code']} – {auth['message']}")
                lines.extend(
                    f"      • {st['name']}: {st['status']} – {st['message']}" for st in auth["steps"]
                )
            kod = c.operations.get("kod2")
            if kod:
                lines.append(f"  KOD II: {kod['code']} – {kod['message']}")
        lines.append("")
    lines += [
        f"Podmiot:         {subject_label(c)}",
        f"NIP:             {_na(s.nip)}",
        f"PESEL:           {_na(s.pesel)}",
        f"Kraj:            {_na(s.country)}",
        f"Ważny od:        {_local_date(i.not_before)}",
        f"Ważny do:        {_local_date(i.not_after)}  (dni do końca: {c.days_remaining})",
        f"Algorytm klucza: {i.key_algorithm}",
        f"Odcisk SHA-256:  {i.fingerprint_sha256}",
    ]
    if expanded:
        lines += [
            "",
            f"Subject:         {i.subject}",
            f"Issuer:          {i.issuer}",
            f"Numer seryjny:   {i.serial_hex}",
            f"Algorytm podpisu:{i.signature_algorithm}",
            f"Key Usage:       {', '.join(i.key_usage) or 'Brak'}",
            f"Ext. Key Usage:  {', '.join(i.extended_key_usage) or 'Brak'}",
            f"Basic Constraints: {i.basic_constraints or 'Brak'}",
            f"SKI:             {i.ski or 'Brak'}",
            f"AKI:             {i.aki or 'Brak'}",
            "Rozszerzenia:    "
            + ", ".join(f"{e.name}{' (krytyczne)' if e.critical else ''}" for e in i.extensions),
        ]
    if c.online_status == "NOT_CHECKED":
        lines += [
            "",
            "Wynik lokalny nie oznacza aktywnego statusu certyfikatu w KSeF ani potwierdzenia przez MF.",
        ]
    return clean("\n".join(lines))


def _repolish(w: QWidget) -> None:
    w.style().unpolish(w)
    w.style().polish(w)
    w.update()


JWT_HELP = (
    "JWT (accessToken) to krótkotrwały token dostępu do API KSeF, który API wydaje po udanym uwierzytelnieniu "
    "(certyfikatem lub tokenem KSeF). Skopiuj go z własnego procesu uwierzytelnienia. To NIE jest token KSeF. "
    "Program sprawdza tylko strukturę i termin ważności – autentyczność weryfikuje dopiero API. Token nie jest zapisywany."
)


class MainWindow(QMainWindow):
    def __init__(
        self,
        options_factory: Callable[[], VerifyOptions] | None = None,
        settings: QSettings | None = None,
        online_transport: Any = None,
    ) -> None:
        super().__init__()
        self.setWindowTitle(f"{PRODUCT_NAME} {__version__}")
        self.setWindowIcon(icons.app_icon())
        self.setAcceptDrops(True)
        self.resize(1260, 800)
        self.setMinimumSize(980, 640)
        self._settings = (
            settings if settings is not None else QSettings("KSeF-cert-verify", "gui")
        )  # identyfikator wewnętrzny – nie zmieniać (zgodność ustawień)
        self._trust = TrustStore.from_paths([])
        self._options_factory = options_factory or (lambda: VerifyOptions(trust=self._trust))
        self._online_transport = online_transport  # tylko testy (MockTransport)
        self._report: FileReport | None = None
        self._session: OnlineSession | None = None
        self._task: JobTask | None = None
        self._last_options: VerifyOptions | None = None
        self._pool = QThreadPool.globalInstance()
        self._theme_mode = self._load_theme_mode()
        self._icon_slots: list[tuple[Callable[[QIcon], None], str, str, int]] = []
        self._cert_type: CertType | None = None
        self._cert_nip: str | None = None
        self._build_ui()
        self.apply_theme()
        self._on_mode_changed()
        self._set_idle()
        self._update_trust_label()

    # ---------- motyw i ikony ----------
    def _load_theme_mode(self) -> str:
        try:
            v = str(self._settings.value("theme", "system"))
        except Exception:
            v = "system"
        return v if v in THEME_LABEL else "system"

    def effective_theme(self) -> str:
        if self._theme_mode in ("light", "dark"):
            return self._theme_mode
        try:
            scheme = QGuiApplication.styleHints().colorScheme()
            return "dark" if scheme == Qt.ColorScheme.Dark else "light"
        except Exception:
            return "light"

    def apply_theme(self) -> None:
        qss = build_qss(self.effective_theme())  # type: ignore[arg-type]
        app = QApplication.instance()
        if isinstance(app, QApplication):
            app.setStyleSheet(qss)  # także okna dialogowe (QMessageBox, QInputDialog…)
        self.setStyleSheet(qss)
        self.btn_theme.setText(THEME_LABEL[self._theme_mode])
        self._refresh_icons()
        for w in self.findChildren(QWidget):
            _repolish(w)

    def cycle_theme(self) -> None:
        order = ["system", "light", "dark"]
        self._theme_mode = order[(order.index(self._theme_mode) + 1) % 3]
        try:
            self._settings.setValue(
                "theme", self._theme_mode
            )  # jedyna rzecz zapisywana (nigdy hasło ani token)
        except Exception:  # nosec B110 - ustawienie kosmetyczne (AppUserModelID/zapis motywu), brak wpływu na bezpieczeństwo
            pass
        self.apply_theme()

    def _bind_icon(
        self, setter: Callable[[Any], None], name: str, role: str = "text", size: int = 18
    ) -> None:
        self._icon_slots.append((setter, name, role, size))
        setter(icons.icon(name, color(self.effective_theme(), role), size))

    def _refresh_icons(self) -> None:
        mode = self.effective_theme()
        for setter, name, role, size in self._icon_slots:
            setter(icons.icon(name, color(mode, role), size))

    def _set_label_icon(self, label: QLabel, name: str, role: str, size: int = 18) -> None:
        dpr = self.devicePixelRatioF() if self.isVisible() else 2.0
        label.setPixmap(icons.pixmap(name, color(self.effective_theme(), role), size, max(dpr, 1.0)))

    # ---------- UI ----------
    def _field(
        self, label: str, name: str, placeholder: str, icon_name: str
    ) -> tuple[QLineEdit, QPushButton]:
        lbl = QLabel(label)
        lbl.setProperty("role", "field")
        row = QHBoxLayout()
        edit = QLineEdit()
        edit.setObjectName(f"edit_{name}")
        edit.setPlaceholderText(placeholder)
        edit.setClearButtonEnabled(True)
        btn = QPushButton("Wybierz…")
        btn.setObjectName(f"btn_{name}")
        self._bind_icon(btn.setIcon, icon_name)
        row.addWidget(edit, 1)
        row.addWidget(btn)
        self._panel_layout.addWidget(lbl)
        self._panel_layout.addLayout(row)
        return edit, btn

    def _build_ui(self) -> None:
        root = QWidget()
        root.setObjectName("root")
        outer = QHBoxLayout(root)
        m = SPACE["lg"]
        outer.setContentsMargins(m, m, m, m)
        outer.setSpacing(SPACE["lg"])

        # ===== lewy panel: dane wejściowe, tryb, opcje =====
        panel = QFrame()
        panel.setObjectName("panel")
        inner = QWidget()
        self._panel_layout = QVBoxLayout(inner)
        pl = self._panel_layout
        pl.setContentsMargins(SPACE["lg"], SPACE["lg"], SPACE["lg"], SPACE["lg"])
        pl.setSpacing(SPACE["sm"])

        head = QHBoxLayout()
        logo = QLabel()
        logo.setPixmap(icons.app_icon().pixmap(40, 40))
        head.addWidget(logo)
        titles = QVBoxLayout()
        title = QLabel(PRODUCT_NAME)
        title.setObjectName("appTitle")
        sub = QLabel(PRODUCT_SUBTITLE)
        sub.setProperty("role", "muted")
        titles.addWidget(title)
        titles.addWidget(sub)
        head.addLayout(titles, 1)
        pl.addLayout(head)
        pl.addSpacing(SPACE["md"])

        self.edit_cert, self.btn_cert = self._field(
            "Certyfikat", "cert", "np. KSeF_Ksiegowosc.crt", "folder-open"
        )
        self.lbl_cert_type = QLabel("")
        self.lbl_cert_type.setObjectName("lbl_cert_type")
        self.lbl_cert_type.setProperty("role", "chip")
        self.lbl_cert_type.setTextFormat(Qt.TextFormat.PlainText)
        self.lbl_cert_type.setVisible(False)
        chip_row = QHBoxLayout()
        chip_row.addWidget(self.lbl_cert_type)
        chip_row.addStretch(1)
        pl.addLayout(chip_row)
        self.edit_key, self.btn_key = self._field("Klucz prywatny", "key", "np. KSeF_Ksiegowosc.key", "key")

        pw_label = QLabel("Hasło do klucza")
        pw_label.setProperty("role", "field")
        pl.addWidget(pw_label)
        pw_row = QHBoxLayout()
        self.edit_password = QLineEdit()
        self.edit_password.setObjectName("edit_password")
        self.edit_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.edit_password.setPlaceholderText("Hasło zabezpieczające klucz")
        self.edit_password.setAcceptDrops(False)
        self.btn_show_password = QPushButton("")
        self.btn_show_password.setObjectName("btn_show_password")
        self.btn_show_password.setCheckable(True)
        self.btn_show_password.setToolTip("Pokaż lub ukryj wpisane hasło")
        self.btn_show_password.setAccessibleName("Pokaż hasło")
        self._bind_icon(self.btn_show_password.setIcon, "eye")
        self.btn_paste_password = QPushButton("")
        self.btn_paste_password.setObjectName("btn_paste_password")
        self.btn_paste_password.setToolTip("Wklej hasło ze schowka")
        self.btn_paste_password.setAccessibleName("Wklej hasło")
        self._bind_icon(self.btn_paste_password.setIcon, "clipboard")
        pw_row.addWidget(self.edit_password, 1)
        pw_row.addWidget(self.btn_show_password)
        pw_row.addWidget(self.btn_paste_password)
        pl.addLayout(pw_row)
        note = QLabel("Hasło nie jest zapisywane i jest czyszczone po każdej weryfikacji.")
        note.setProperty("role", "muted")
        note.setWordWrap(True)
        pl.addWidget(note)
        pl.addSpacing(SPACE["md"])

        # --- tryb ---
        mode_title = QLabel("Tryb")
        mode_title.setObjectName("sectionTitle")
        pl.addWidget(mode_title)
        self.mode_group = QButtonGroup(self)
        self.rad_local = QRadioButton("Weryfikacja lokalna")
        self.rad_online = QRadioButton("Weryfikacja lokalna + status online")
        self.rad_auth = QRadioButton("Test uwierzytelnienia online (Authentication)")
        self.rad_kod2 = QRadioButton("Test podpisu KODU II (Offline)")
        for rid, rad, name in (
            (MODE_LOCAL, self.rad_local, "rad_local"),
            (MODE_ONLINE, self.rad_online, "rad_online"),
            (MODE_AUTH, self.rad_auth, "rad_auth"),
            (MODE_KOD2, self.rad_kod2, "rad_kod2"),
        ):
            rad.setObjectName(name)
            rad.setProperty("mode", rid)
            self.mode_group.addButton(rad)
            pl.addWidget(rad)
        self.rad_local.setChecked(True)
        self.mode_group.buttonToggled.connect(lambda *_: self._on_mode_changed())

        # --- opcje online ---
        self.online_box = QFrame()
        self.online_box.setObjectName("online_box")
        ob = QVBoxLayout(self.online_box)
        ob.setContentsMargins(0, SPACE["sm"], 0, 0)
        ob.setSpacing(SPACE["sm"])
        env_row = QHBoxLayout()
        env_lbl = QLabel("Środowisko")
        env_lbl.setProperty("role", "field")
        self.cmb_env = QComboBox()
        self.cmb_env.setObjectName("cmb_env")
        self.cmb_env.addItems(["TEST", "DEMO", "PROD"])
        self.cmb_env.currentTextChanged.connect(lambda _t: self._update_prod_warning())
        env_row.addWidget(env_lbl)
        env_row.addWidget(self.cmb_env, 1)
        ob.addLayout(env_row)
        self.lbl_prod = QLabel(
            "PRODUKCJA: operacje online wymagają świadomego potwierdzenia przed wykonaniem."
        )
        self.lbl_prod.setObjectName("lbl_prod")
        self.lbl_prod.setProperty("role", "warnNote")
        self.lbl_prod.setWordWrap(True)
        self.lbl_prod.setVisible(False)
        ob.addWidget(self.lbl_prod)
        ctx_lbl = QLabel("Kontekst uwierzytelnienia (NIP)")
        ctx_lbl.setProperty("role", "field")
        self.edit_context = QLineEdit()
        self.edit_context.setObjectName("edit_context")
        self.edit_context.setPlaceholderText("domyślnie NIP z certyfikatu")
        self.edit_context.setMaxLength(10)
        ob.addWidget(ctx_lbl)
        ob.addWidget(self.edit_context)
        self.chk_auto_auth = QCheckBox("Automatyczne uwierzytelnienie w KSeF")
        self.chk_auto_auth.setObjectName("chk_auto_auth")
        self.chk_auto_auth.setChecked(True)
        self.chk_auto_auth.setToolTip(
            "Program pobierze challenge, podpisze AuthTokenRequest (XAdES) certyfikatem i kluczem, odbierze accessToken "
            "i użyje go do zapytania o status. Dostępne tylko dla certyfikatu Authentication."
        )
        ob.addWidget(self.chk_auto_auth)
        self.btn_advanced = QPushButton("Zaawansowane")
        self.btn_advanced.setObjectName("btn_advanced")
        self.btn_advanced.setCheckable(True)
        self.btn_advanced.setProperty("flat", True)
        self._bind_icon(self.btn_advanced.setIcon, "sliders", "accent", 16)
        ob.addWidget(self.btn_advanced)
        self.adv_box = QFrame()
        self.adv_box.setObjectName("adv_box")
        ab = QVBoxLayout(self.adv_box)
        ab.setContentsMargins(0, 0, 0, 0)
        ab.setSpacing(SPACE["sm"])
        self.chk_use_jwt = QCheckBox("Użyj istniejącego tokena JWT")
        self.chk_use_jwt.setObjectName("chk_use_jwt")
        ab.addWidget(self.chk_use_jwt)
        self.edit_jwt = QLineEdit()
        self.edit_jwt.setObjectName("edit_jwt")
        self.edit_jwt.setEchoMode(QLineEdit.EchoMode.Password)
        self.edit_jwt.setPlaceholderText("accessToken (JWT)")
        self.edit_jwt.setAcceptDrops(False)
        self.edit_jwt.setEnabled(False)
        ab.addWidget(self.edit_jwt)
        self.lbl_jwt_state = QLabel("")
        self.lbl_jwt_state.setObjectName("lbl_jwt_state")
        self.lbl_jwt_state.setProperty("role", "muted")
        self.lbl_jwt_state.setWordWrap(True)
        self.lbl_jwt_state.setTextFormat(Qt.TextFormat.PlainText)
        ab.addWidget(self.lbl_jwt_state)
        jwt_help = QLabel(JWT_HELP)
        jwt_help.setObjectName("lbl_jwt_help")
        jwt_help.setProperty("role", "muted")
        jwt_help.setWordWrap(True)
        ab.addWidget(jwt_help)
        self.adv_box.setVisible(False)
        ob.addWidget(self.adv_box)
        pl.addWidget(self.online_box)
        self.chk_use_jwt.toggled.connect(self._on_jwt_toggled)
        self.edit_jwt.textChanged.connect(self._on_jwt_changed)
        self.btn_advanced.toggled.connect(self.adv_box.setVisible)

        pl.addSpacing(SPACE["md"])
        self.btn_verify = QPushButton("Weryfikuj")
        self.btn_verify.setObjectName("btn_verify")
        self.btn_verify.setProperty("primary", True)
        self.btn_verify.setDefault(True)
        self._bind_icon(self.btn_verify.setIcon, "play", "accent_text", 18)
        pl.addWidget(self.btn_verify)

        self.btn_trust = QToolButton()
        self.btn_trust.setObjectName("btn_trust")
        self.btn_trust.setText("Zaufane CA…")
        self.btn_trust.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.btn_trust.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self._bind_icon(self.btn_trust.setIcon, "plus-shield")
        menu = QMenu(self.btn_trust)
        a1, a2 = QAction("Dodaj plik CA…", self), QAction("Dodaj katalog z CA…", self)
        a1.triggered.connect(self._add_trust_file)
        a2.triggered.connect(self._add_trust_dir)
        menu.addAction(a1)
        menu.addAction(a2)
        self.btn_trust.setMenu(menu)
        self.lbl_trust = QLabel("")
        self.lbl_trust.setObjectName("lbl_trust")
        self.lbl_trust.setProperty("role", "muted")
        self.lbl_trust.setWordWrap(True)
        self.lbl_trust.setTextFormat(Qt.TextFormat.PlainText)
        trust_row = QHBoxLayout()
        trust_row.addWidget(self.btn_trust)
        trust_row.addWidget(self.lbl_trust, 1)
        pl.addSpacing(SPACE["sm"])
        pl.addLayout(trust_row)
        pl.addStretch(1)
        bottom = QHBoxLayout()
        self.btn_theme = QPushButton("")
        self.btn_theme.setObjectName("btn_theme")
        self._bind_icon(self.btn_theme.setIcon, "contrast")
        self.btn_about = QPushButton("O programie")
        self.btn_about.setObjectName("btn_about")
        self._bind_icon(self.btn_about.setIcon, "info")
        bottom.addWidget(self.btn_theme, 1)
        bottom.addWidget(self.btn_about)
        pl.addLayout(bottom)

        scroll = QScrollArea()
        scroll.setObjectName("left_scroll")
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(inner)
        pwrap = QVBoxLayout(panel)
        pwrap.setContentsMargins(0, 0, 0, 0)
        pwrap.addWidget(scroll)
        panel.setFixedWidth(430)
        outer.addWidget(panel)

        # ===== prawy panel: podsumowanie + sekcje =====
        results = QFrame()
        results.setObjectName("results")
        rv = QVBoxLayout(results)
        rv.setContentsMargins(SPACE["lg"], SPACE["lg"], SPACE["lg"], SPACE["lg"])
        rv.setSpacing(SPACE["md"])

        cards = QHBoxLayout()
        cards.setSpacing(SPACE["md"])
        self._cards: dict[str, dict[str, QWidget]] = {}
        for gkey, gname, gtitle in SECTIONS:
            card = QFrame()
            card.setObjectName(f"card_{gkey}")
            card.setProperty("role", "card")
            card.setProperty("state", "unk")
            cl = QVBoxLayout(card)
            cl.setContentsMargins(SPACE["md"], SPACE["md"], SPACE["md"], SPACE["md"])
            cl.setSpacing(SPACE["xs"])
            top = QHBoxLayout()
            ico = QLabel()
            ico.setObjectName(f"ico_{gkey}")
            ttl = QLabel(f"{gname} · {gtitle}")
            ttl.setProperty("role", "cardTitle")
            ttl.setWordWrap(True)
            top.addWidget(ico)
            top.addWidget(ttl, 1)
            st = QLabel("")
            st.setObjectName(f"st_{gkey}")
            st.setProperty("role", "cardStatus")
            st.setProperty("state", "unk")
            st.setTextFormat(Qt.TextFormat.PlainText)
            sb = QLabel("")
            sb.setObjectName(f"sub_{gkey}")
            sb.setProperty("role", "muted")
            sb.setWordWrap(True)
            sb.setTextFormat(Qt.TextFormat.PlainText)
            cl.addLayout(top)
            cl.addWidget(st)
            cl.addWidget(sb)
            cl.addStretch(1)
            cards.addWidget(card, 1)
            self._cards[gkey] = {"card": card, "ico": ico, "status": st, "sub": sb}
        rv.addLayout(cards)

        self.lbl_result = QLabel("")
        self.lbl_result.setObjectName("lbl_result")
        self.lbl_result.setTextFormat(Qt.TextFormat.PlainText)
        self.lbl_result.setWordWrap(True)
        self.lbl_result.setProperty("role", "muted")
        rv.addWidget(self.lbl_result)

        self.cmb_cert = QComboBox()
        self.cmb_cert.setObjectName("cmb_cert")
        self.cmb_cert.setVisible(False)
        self.cmb_cert.currentIndexChanged.connect(lambda _i: self._show_selected())
        rv.addWidget(self.cmb_cert)

        self._rows: dict[str, dict[str, QLabel]] = {}
        sections_host = QFrame()
        sv = QVBoxLayout(sections_host)
        sv.setContentsMargins(0, 0, 0, 0)
        sv.setSpacing(SPACE["xs"])
        for gkey, gname, gtitle in SECTIONS:
            hdr = QLabel(f"{gname}  ·  {gtitle}")
            hdr.setObjectName(f"hdr_{gkey}")
            hdr.setProperty("role", "sectionHeader")
            sv.addWidget(hdr)
            grid_host = QFrame()
            grid = QGridLayout(grid_host)
            grid.setContentsMargins(0, 0, 0, 0)
            grid.setHorizontalSpacing(SPACE["md"])
            grid.setVerticalSpacing(SPACE["xs"])
            grid.setColumnStretch(3, 1)
            for r, key in enumerate(GROUPS[gkey]):
                ico = QLabel()
                ico.setObjectName(f"icon_{key}")
                ico.setFixedWidth(20)
                badge = QLabel("")
                badge.setObjectName(f"badge_{key}")
                badge.setProperty("badge", "unk")
                badge.setMinimumWidth(140)
                badge.setWordWrap(False)
                badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
                name_lbl = QLabel(CHECK_LABEL[key])
                name_lbl.setProperty("role", "checkTitle")
                name_lbl.setMinimumWidth(230)
                summ = QLabel("")
                summ.setObjectName(f"summary_{key}")
                summ.setWordWrap(True)
                summ.setTextFormat(Qt.TextFormat.PlainText)
                summ.setProperty("role", "muted")
                summ.setMinimumHeight(34)
                for col, w in enumerate((ico, badge, name_lbl, summ)):
                    grid.addWidget(w, r, col)
                self._rows[key] = {"icon": ico, "badge": badge, "summary": summ}
            sv.addWidget(grid_host)
            if gkey == "online":
                self.lbl_ops = QLabel("")
                self.lbl_ops.setObjectName("lbl_ops")
                self.lbl_ops.setWordWrap(True)
                self.lbl_ops.setTextFormat(Qt.TextFormat.PlainText)
                self.lbl_ops.setProperty("role", "muted")
                sv.addWidget(self.lbl_ops)
            rule = QFrame()
            rule.setProperty("role", "rule")
            sv.addWidget(rule)
        self._badges = {k: v["badge"] for k, v in self._rows.items()}
        self._summaries = {k: v["summary"] for k, v in self._rows.items()}
        sections_scroll = QScrollArea()
        sections_scroll.setObjectName("sections_scroll")
        sections_scroll.setWidgetResizable(True)
        sections_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        sections_scroll.setFrameShape(QFrame.Shape.NoFrame)
        sections_scroll.setWidget(
            sections_host
        )  # wiersze nie są ściskane – przewijanie zamiast nakładania tekstu
        rv.addWidget(sections_scroll, 3)

        self.details = QPlainTextEdit()
        self.details.setObjectName("details")
        self.details.setReadOnly(True)
        self.details.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.details.setVisible(False)
        rv.addWidget(self.details, 2)

        actions = QHBoxLayout()
        self.chk_details = QCheckBox("Szczegóły")
        self.chk_details.setObjectName("chk_details")
        self.btn_export = QPushButton("Eksport JSON")
        self.btn_export.setObjectName("btn_export")
        self._bind_icon(self.btn_export.setIcon, "file-json")
        self.btn_copy = QPushButton("Kopiuj do schowka")
        self.btn_copy.setObjectName("btn_copy")
        self._bind_icon(self.btn_copy.setIcon, "copy")
        actions.addWidget(self.chk_details)
        actions.addStretch(1)
        actions.addWidget(self.btn_export)
        actions.addWidget(self.btn_copy)
        rv.addLayout(actions)
        outer.addWidget(results, 1)

        self.setCentralWidget(root)
        self.statusBar().showMessage("Gotowe.")

        self.btn_cert.clicked.connect(self.choose_cert)
        self.btn_key.clicked.connect(self.choose_key)
        self.btn_verify.clicked.connect(self.start_verification)
        self.btn_show_password.toggled.connect(self._toggle_password)
        self.btn_paste_password.clicked.connect(self.paste_password)
        self.btn_theme.clicked.connect(self.cycle_theme)
        self.btn_about.clicked.connect(self.show_about)
        self.btn_export.clicked.connect(self.export_json)
        self.btn_copy.clicked.connect(self.copy_to_clipboard)
        self.chk_details.toggled.connect(self._toggle_details)
        self.edit_password.returnPressed.connect(self.start_verification)
        self.edit_cert.editingFinished.connect(self._inspect_cert)
        self.btn_export.setEnabled(False)
        self.btn_copy.setEnabled(False)
        for a, b in (
            (self.edit_cert, self.btn_cert),
            (self.btn_cert, self.edit_key),
            (self.edit_key, self.btn_key),
            (self.btn_key, self.edit_password),
            (self.edit_password, self.btn_show_password),
            (self.btn_show_password, self.btn_paste_password),
            (self.btn_paste_password, self.rad_local),
        ):
            self.setTabOrder(a, b)

    # ---------- tryb i opcje online ----------
    def current_mode(self) -> str:
        for rad in (self.rad_local, self.rad_online, self.rad_auth, self.rad_kod2):
            if rad.isChecked():
                return str(rad.property("mode"))
        return MODE_LOCAL

    def _on_mode_changed(self) -> None:
        mode = self.current_mode()
        online = mode in (MODE_ONLINE, MODE_AUTH)
        self.online_box.setVisible(online)
        self._update_prod_warning()
        auth_ok = self._cert_type in (None, CertType.AUTHENTICATION, CertType.UNKNOWN)
        self.chk_auto_auth.setEnabled(auth_ok and not self.chk_use_jwt.isChecked())
        self.rad_auth.setEnabled(auth_ok)
        self.rad_kod2.setEnabled(self._cert_type in (None, CertType.OFFLINE, CertType.UNKNOWN))
        if mode == MODE_AUTH:
            self.chk_use_jwt.setChecked(False)
            self.chk_auto_auth.setChecked(True)

    def _update_prod_warning(self) -> None:
        self.lbl_prod.setVisible(self.online_box.isVisible() and self.cmb_env.currentText() == "PROD")

    def _on_jwt_toggled(self, on: bool) -> None:
        self.edit_jwt.setEnabled(on)
        self.chk_auto_auth.setEnabled(not on and self.rad_auth.isEnabled())
        if on:
            self.chk_auto_auth.setChecked(False)
        self._on_jwt_changed(self.edit_jwt.text())

    def _on_jwt_changed(self, text: str) -> None:
        if not self.chk_use_jwt.isChecked() or not text.strip():
            self.lbl_jwt_state.setText("")
            return
        self.lbl_jwt_state.setText(clean(describe(inspect_jwt(text))))

    def _inspect_cert(self) -> None:
        """Rozpoznaje typ certyfikatu (bez hasła) i dostosowuje dostępne tryby."""
        path = self.edit_cert.text().strip()
        self._cert_type, self._cert_nip = None, None
        self.lbl_cert_type.setVisible(False)
        if path and Path(path).suffix.lower() not in (".p12", ".pfx") and Path(path).is_file():
            try:
                certs = load_file(Path(path)).certificates
                leaf = next((c for c in certs if not _is_ca(c)), certs[0])
                self._cert_type = classify(leaf)[0]
                info, _ = parse_certificate(leaf)
                self._cert_nip = info.subject_info.nip
                label = {"Authentication": "Authentication", "Offline": "Offline"}.get(
                    self._cert_type.value, "Typ nieustalony"
                )
                self.lbl_cert_type.setText(f"Typ: {label}")
                self.lbl_cert_type.setVisible(True)
                if self._cert_nip and not self.edit_context.text():
                    self.edit_context.setPlaceholderText(f"NIP z certyfikatu: {self._cert_nip}")
            except (LoaderError, ValueError):
                self._cert_type = None
        self._on_mode_changed()
        if not self.rad_auth.isEnabled() and self.rad_auth.isChecked():
            self.rad_local.setChecked(True)
        if not self.rad_kod2.isEnabled() and self.rad_kod2.isChecked():
            self.rad_local.setChecked(True)

    # ---------- dialogi (wydzielone, aby dały się podmienić w testach) ----------
    def _pick_cert(self) -> str:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Wybierz certyfikat",
            "",
            "Certyfikaty (*.crt *.cer *.pem *.der *.p12 *.pfx);;Wszystkie pliki (*)",
        )
        return path

    def _pick_key(self) -> str:
        path, _ = QFileDialog.getOpenFileName(
            self, "Wybierz klucz prywatny", "", "Klucze prywatne (*.key *.pem);;Wszystkie pliki (*)"
        )
        return path

    def _pick_save_path(self) -> str:
        path, _ = QFileDialog.getSaveFileName(self, "Eksport JSON", "wynik.json", "JSON (*.json)")
        return path

    def _message(self, title: str, text: str, warning: bool = False) -> None:
        box = QMessageBox(
            QMessageBox.Icon.Warning if warning else QMessageBox.Icon.Information,
            title,
            clean(text),
            parent=self,
        )
        box.setWindowIcon(icons.app_icon())
        box.setTextFormat(Qt.TextFormat.PlainText)  # nigdy nie interpretuj nazw plików/komunikatów jako HTML
        box.exec()

    def about_text(self) -> str:
        """Treść „O programie” jako zwykły tekst (do schowka/testów)."""
        return (
            f"{PRODUCT_NAME}\n{PRODUCT_DESCRIPTION}\nWersja: {__version__}\n"
            f"Repozytorium: GitHub – {REPOSITORY_URL}\nLicencja: {LICENSE_NAME}\n\n{DISCLAIMER}"
        )

    def open_repository(self) -> bool:
        """Otwiera stały adres repozytorium w domyślnej przeglądarce (nie czyta lokalnego `git remote`)."""
        return bool(QDesktopServices.openUrl(QUrl(REPOSITORY_URL)))

    def build_about_dialog(self) -> QDialog:
        dlg = QDialog(self)
        dlg.setObjectName("aboutDialog")
        dlg.setWindowTitle(f"O programie – {PRODUCT_NAME}")
        dlg.setWindowIcon(icons.app_icon())
        dlg.setMinimumWidth(520)
        lay = QVBoxLayout(dlg)
        lay.setContentsMargins(SPACE["xl"], SPACE["xl"], SPACE["xl"], SPACE["lg"])
        lay.setSpacing(SPACE["md"])

        head = QHBoxLayout()
        head.setSpacing(SPACE["lg"])
        logo = QLabel()
        logo.setPixmap(icons.app_icon().pixmap(72, 72))
        head.addWidget(logo, 0, Qt.AlignmentFlag.AlignTop)
        titles = QVBoxLayout()
        name = QLabel(PRODUCT_NAME)
        name.setObjectName("aboutName")
        desc = QLabel(PRODUCT_DESCRIPTION)
        desc.setObjectName("aboutDescription")
        desc.setWordWrap(True)
        desc.setProperty("role", "muted")
        titles.addWidget(name)
        titles.addWidget(desc)
        head.addLayout(titles, 1)
        lay.addLayout(head)

        grid = QGridLayout()
        grid.setHorizontalSpacing(SPACE["lg"])
        grid.setVerticalSpacing(SPACE["sm"])
        grid.setColumnStretch(1, 1)

        def row(r: int, label: str, widget: QWidget) -> None:
            lbl = QLabel(label)
            lbl.setProperty("role", "field")
            grid.addWidget(lbl, r, 0, Qt.AlignmentFlag.AlignTop)
            grid.addWidget(widget, r, 1)

        version = QLabel(__version__)
        version.setObjectName("aboutVersion")
        version.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        row(0, "Wersja", version)
        self.btn_repo = QPushButton(f"GitHub – {REPOSITORY_URL.removeprefix('https://')}")
        self.btn_repo.setObjectName("btn_repo")
        self.btn_repo.setProperty("role", "link")
        self.btn_repo.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_repo.setToolTip(f"Otwórz w przeglądarce: {REPOSITORY_URL}")
        self.btn_repo.setAccessibleName("Repozytorium GitHub")
        self._bind_icon(self.btn_repo.setIcon, "github", "accent", 18)
        self.btn_repo.clicked.connect(self.open_repository)
        row(1, "Repozytorium", self.btn_repo)
        lic = QLabel(LICENSE_NAME)
        lic.setObjectName("aboutLicense")
        row(2, "Licencja", lic)
        lay.addLayout(grid)

        note = QLabel(DISCLAIMER)
        note.setObjectName("aboutDisclaimer")
        note.setWordWrap(True)
        note.setProperty("role", "muted")
        note.setTextFormat(Qt.TextFormat.PlainText)
        lay.addWidget(note)

        close = QPushButton("Zamknij")
        close.setObjectName("btn_about_close")
        close.setDefault(True)
        close.setFocus()  # fokus nie ląduje od razu na odnośniku
        close.clicked.connect(dlg.accept)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(close)
        lay.addLayout(buttons)
        return dlg

    def show_about(self) -> None:
        """Okno „O programie” w stylu aplikacji (QSS ustawiony na poziomie QApplication)."""
        dlg = self.build_about_dialog()
        try:
            dlg.exec()
        finally:
            # zwolnij dialog i powiązane sloty ikon (bez wycieku przy wielokrotnym otwieraniu)
            repo_btn = self.btn_repo
            self._icon_slots = [
                s for s in self._icon_slots if getattr(s[0], "__self__", None) is not repo_btn
            ]
            dlg.deleteLater()

    def _confirm_prod(self) -> bool:
        """Świadome potwierdzenie PROD: trzeba wpisać słowo PROD."""
        dlg = QInputDialog(self)
        dlg.setWindowTitle("Środowisko produkcyjne")
        dlg.setLabelText(
            "Wybrano środowisko PRODUKCYJNE KSeF. Operacje online zostaną wykonane na prawdziwym systemie.\n"
            "Aby kontynuować, wpisz PROD."
        )
        dlg.setWindowIcon(icons.app_icon())
        return bool(dlg.exec()) and dlg.textValue().strip() == "PROD"

    def _confirm_trust(self, subject: str, fp: str) -> bool:
        box = QMessageBox(
            QMessageBox.Icon.Question,
            "Zaufać temu CA?",
            clean(
                f"Subject: {subject}\nSHA-256: {fp}\n\nSprawdź odcisk z zaufanym źródłem (innym kanałem) przed potwierdzeniem."
            ),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            self,
        )
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        return box.exec() == QMessageBox.StandardButton.Yes

    def _pick_trust_files(self) -> list[str]:
        files, _ = QFileDialog.getOpenFileNames(
            self, "Zaufane CA", "", "Certyfikaty (*.pem *.crt *.cer *.der)"
        )
        return files

    def _pick_trust_dir(self) -> str:
        return QFileDialog.getExistingDirectory(self, "Katalog z zaufanymi CA")

    # ---------- pola ----------
    def choose_cert(self) -> None:
        if p := self._pick_cert():
            self.set_cert(p)

    def choose_key(self) -> None:
        if p := self._pick_key():
            self.set_key(p)

    def set_cert(self, path: str | Path) -> None:
        self.edit_cert.setText(str(path))
        self._inspect_cert()
        self._set_idle()

    def set_key(self, path: str | Path) -> None:
        self.edit_key.setText(str(path))
        self._set_idle()

    def _toggle_password(self, shown: bool) -> None:
        self.edit_password.setEchoMode(QLineEdit.EchoMode.Normal if shown else QLineEdit.EchoMode.Password)
        self.btn_show_password.setText("")
        self._icon_swap(self.btn_show_password, "eye-off" if shown else "eye")

    def _icon_swap(self, btn: QPushButton, name: str) -> None:
        self._icon_slots = [
            s
            for s in self._icon_slots
            if getattr(s[0], "__self__", None) is not btn or s[0].__name__ != "setIcon"
        ]
        self._bind_icon(btn.setIcon, name)

    def paste_password(self) -> None:
        """Wkleja hasło i od razu czyści schowek (hasło nie powinno w nim zostawać)."""
        clip = QGuiApplication.clipboard()
        text = clip.text()
        if text:
            self.edit_password.setText(text.rstrip("\r\n"))
            clip.clear()

    @staticmethod
    def classify_dropped(path: Path) -> str:
        """'key' | 'cert' – po rozszerzeniu i (dla .pem) po zawartości."""
        ext = path.suffix.lower()
        if ext == ".key":
            return "key"
        if ext in (".p12", ".pfx", ".crt", ".cer", ".der"):
            return "cert"
        try:
            head = path.read_bytes()[:4096]
        except OSError:
            return "cert"
        return "key" if b"PRIVATE KEY-----" in head else "cert"

    def add_files(self, paths: Sequence[str | Path]) -> None:
        for p in paths:
            path = Path(p)
            if path.is_dir():
                continue
            (self.set_key if self.classify_dropped(path) == "key" else self.set_cert)(path)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:  # noqa: N802
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:  # noqa: N802
        paths = [u.toLocalFile() for u in event.mimeData().urls() if u.isLocalFile()]
        if paths:
            self.add_files(paths)
            event.acceptProposedAction()

    # ---------- zaufane CA ----------
    def _add_trust_file(self) -> None:
        for f in self._pick_trust_files():
            self._add_trust_path(Path(f))
        self._after_trust_change()

    def _add_trust_dir(self) -> None:
        d = self._pick_trust_dir()
        if d:
            for f in sorted(Path(d).iterdir()):
                if f.is_file() and f.suffix.lower() in (".pem", ".crt", ".cer", ".der"):
                    self._add_trust_path(f)
        self._after_trust_change()

    def _add_trust_path(self, path: Path) -> None:
        """Dodaje CA do sesji dopiero po potwierdzeniu odcisku (nigdy automatycznie)."""
        from cryptography import x509

        try:
            certs = load_file(path).certificates
        except LoaderError as exc:
            self._trust.warnings.append(f"Pominięto {path.name}: {exc.message}")
            return
        for c in certs:
            try:
                is_ca = c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            except x509.ExtensionNotFound:
                is_ca = False
            if not is_ca:
                self._trust.warnings.append(
                    f"Pominięto {path.name}: to nie jest certyfikat CA (BasicConstraints CA=TRUE)."
                )
                continue
            if self._confirm_trust(c.subject.rfc4514_string(), fingerprint(c)):
                self._trust.add(c, str(path))

    def _after_trust_change(self) -> None:
        self._update_trust_label()
        if self._trust.warnings:
            self._message("Zaufane CA", "\n".join(self._trust.warnings), warning=True)
            self._trust.warnings.clear()
        if self._report is not None:  # wynik zależy od zaufanych CA – unieważnij
            self._set_idle()

    def _update_trust_label(self) -> None:
        try:
            n = len(self._options_factory().trust)
        except Exception:
            n = len(self._trust)
        self.lbl_trust.setText(
            f"Zaufane CA: {n}" if n else "Zaufane CA: 0 – zaufanie do wystawcy nie zostanie potwierdzone"
        )

    # ---------- stan prezentacji ----------
    def _set_card(self, gkey: str, status: str, state: str, sub: str, icon_name: str) -> None:
        w = self._cards[gkey]
        w["status"].setText(clean(status))  # type: ignore[attr-defined]
        for widget in (w["card"], w["status"]):
            widget.setProperty("state", state)
            _repolish(widget)
        w["sub"].setText(clean(sub))  # type: ignore[attr-defined]
        self._set_label_icon(w["ico"], icon_name, state, 22)  # type: ignore[arg-type]

    def _set_row(self, key: str, status: CheckStatus | None, summary: str) -> None:
        r = self._rows[key]
        badge = r["badge"]
        if status is None:
            badge.setText("")
            badge.setProperty("badge", "unk")
            r["icon"].clear()
        else:
            name, role = icons.STATUS_ICON[status.value]
            if key == "online" and status is CheckStatus.NOT_CHECKED:
                name = "cloud-off"
            badge.setText(CHECK_WORD[status])
            badge.setProperty("badge", {"pass": "pass", "fail": "fail", "warn": "warn", "unk": "unk"}[role])
            self._set_label_icon(r["icon"], name, role)
        r["summary"].setText(clean(summary))
        _repolish(badge)

    def _set_idle(self) -> None:
        self._report = None
        self._session = None
        self.cmb_cert.setVisible(False)
        self.lbl_result.setText("")
        self.lbl_ops.setText("")
        self.details.setPlainText("")
        for key in self._rows:
            self._set_row(key, None, "")
        have_cert = bool(self.edit_cert.text().strip())
        have_key = bool(self.edit_key.text().strip())
        if not have_cert or not have_key:
            missing = ", ".join(
                n for n, ok in (("certyfikat", have_cert), ("klucz prywatny", have_key)) if not ok
            )
            msg = f"Wskaż: {missing}, a następnie podaj hasło."
        else:
            msg = "Podaj hasło do klucza i naciśnij Weryfikuj."
        self._set_card("local", "GOTOWE", "unk", msg, "help-circle")
        self._set_card(
            "trust", "—", "unk", "Zaufanie do wystawcy zostanie sprawdzone po weryfikacji.", "shield-alert"
        )
        self._set_card(
            "online", "NIE SPRAWDZONO", "unk", "Tryb offline – bez połączeń sieciowych.", "cloud-off"
        )
        self.btn_export.setEnabled(False)
        self.btn_copy.setEnabled(False)

    # ---------- weryfikacja ----------
    def _online_setup(self) -> OnlineSetup | None:
        mode = self.current_mode()
        if mode not in (MODE_ONLINE, MODE_AUTH):
            return None
        env = self.cmb_env.currentText()
        use_jwt = self.chk_use_jwt.isChecked()
        return OnlineSetup(
            environment=env,
            mode="jwt" if use_jwt else "auto",
            jwt=self.edit_jwt.text().strip() if use_jwt else None,
            allow_prod=False,  # ustawiane po potwierdzeniu
            context_value=self.edit_context.text().strip() or None,
            transport=self._online_transport,
            poll_interval=0 if self._online_transport is not None else 2.0,
        )

    def start_verification(self) -> None:
        if self._task is not None:
            return
        cert = self.edit_cert.text().strip()
        key = self.edit_key.text().strip()
        if not cert:
            self._set_card(
                "local",
                "BRAK CERTYFIKATU",
                "warn",
                "Wybierz plik certyfikatu (.crt, .cer, .pem, .der).",
                "alert-triangle",
            )
            return
        is_p12 = Path(cert).suffix.lower() in (".p12", ".pfx")
        if not key and not is_p12:
            self._set_card(
                "local",
                "BRAK KLUCZA",
                "warn",
                "Pełna weryfikacja wymaga pliku klucza (.key) i hasła.",
                "alert-triangle",
            )
            return
        mode = self.current_mode()
        setup = self._online_setup()
        if setup is not None:
            if setup.mode == "jwt" and not self.edit_jwt.text().strip():
                self._message(
                    "Token JWT",
                    "Zaznaczono „Użyj istniejącego tokena JWT”, ale pole tokena jest puste.",
                    True,
                )
                return
            if setup.environment == "PROD":
                if not self._confirm_prod():
                    self.statusBar().showMessage("PROD nie został potwierdzony – operacja anulowana.", 5000)
                    return
                setup.allow_prod = True
        options = self._options_factory()
        if options.now is None:
            options.now = datetime.now(UTC)
        self._last_options = options
        password = self.edit_password.text() or None
        self.edit_password.clear()  # hasło nie zostaje w interfejsie po użyciu
        secret = [password]  # uchwyt czyszczony po zakończeniu zadania (nie zmienna domknięcia)
        provider = CachedPassword(lambda _p, retry: None if retry else secret[0])
        cert_p, key_p = Path(cert), (Path(key) if key else None)
        kod2_env = self.cmb_env.currentText() if self.online_box.isVisible() else "TEST"

        def job() -> tuple[FileReport, OnlineSession | None]:
            if mode == MODE_KOD2 and key_p is not None:
                # `kod2_env` odczytane PRZED startem zadania – widżetów Qt nie wolno czytać w wątku roboczym
                return run_kod2_test(
                    cert_p, key_p, options, provider, Kod2Setup(kod2_env, "Nip", None, None)
                ), None
            return verify_with_online(
                cert_p, key_p, options, provider, setup, query_status=(mode != MODE_AUTH)
            )

        password = None
        self._report = None
        for w in (self.btn_verify, self.btn_cert, self.btn_key):
            w.setEnabled(False)
        self._set_card("local", "TRWA…", "unk", "Analiza działa w tle.", "help-circle")
        self.statusBar().showMessage("Trwa weryfikacja…")

        def clear_secrets() -> None:
            secret[0] = None
            provider.clear()

        task = JobTask(job, clear_secrets)
        task.signals.done.connect(self._on_done)
        task.signals.finished.connect(self._on_finished)
        self._task = task
        self._pool.start(task)

    def _on_done(self, result: object) -> None:
        if isinstance(result, Exception):
            from ksef_cert_verify.core.models import FileError

            self._report = FileReport(
                self.edit_cert.text(),
                None,
                error=FileError("INTERNAL_ERROR", f"Błąd wewnętrzny: {result}", "runtime"),
            )
        else:
            self._report, self._session = result  # type: ignore[misc]
        self._populate_results()

    def _on_finished(self) -> None:
        self._task = None
        for w in (self.btn_verify, self.btn_cert, self.btn_key):
            w.setEnabled(True)
        self.statusBar().showMessage("Weryfikacja zakończona.", 5000)

    def wait_until_idle(self, timeout_ms: int = 10000) -> bool:
        return self._pool.waitForDone(timeout_ms)

    # ---------- wynik ----------
    def _populate_results(self) -> None:
        rep = self._report
        if rep is None:
            return
        self.cmb_cert.blockSignals(True)
        self.cmb_cert.clear()
        self.cmb_cert.blockSignals(False)
        if rep.error:
            self.cmb_cert.setVisible(False)
            kind = "BŁĄD" if rep.error.kind == "runtime" else "NIEPOPRAWNY"
            self._set_card("local", kind, "fail", rep.error.message, "x-circle")
            self._set_card("trust", "—", "unk", "", "shield-alert")
            self._set_card("online", "NIE SPRAWDZONO", "unk", "", "cloud-off")
            for key in self._rows:
                self._set_row(key, None, "")
            self.lbl_result.setText("")
            self.lbl_ops.setText("")
            self.details.setPlainText(clean(f"Plik: {rep.path}\nKod: {rep.error.code}\n{rep.error.message}"))
            self.btn_export.setEnabled(True)
            self.btn_copy.setEnabled(True)
            if rep.error.kind == "runtime":
                self._message("Błąd pliku", f"{Path(rep.path).name}: {rep.error.message}", warning=True)
            return
        for c in rep.certificates:
            self.cmb_cert.addItem(clean(f"{subject_label(c)} – {c.cert_type.value}"))
        self.cmb_cert.setVisible(len(rep.certificates) > 1)
        self.btn_export.setEnabled(True)
        self.btn_copy.setEnabled(True)
        self._show_selected()

    def _selected(self) -> tuple[FileReport | None, CertReport | None]:
        rep = self._report
        if rep is None or rep.error or not rep.certificates:
            return rep, None
        idx = max(0, self.cmb_cert.currentIndex())
        return rep, rep.certificates[min(idx, len(rep.certificates) - 1)]

    def _show_selected(self) -> None:
        rep, cert = self._selected()
        if rep is None or cert is None:
            return
        lw, lstate = local_word(cert)
        local_icon = {"pass": "check-circle", "fail": "x-circle", "warn": "alert-triangle"}[lstate]
        local_sub = {
            "pass": "Odszyfrowanie, dopasowanie pary i test podpisu przeszły.",
            "fail": self._first_reason(cert, GROUPS["local"], CheckStatus.FAIL),
            "warn": self._first_reason(cert, GROUPS["local"], None),
        }[lstate]
        self._set_card("local", lw, lstate, local_sub, local_icon)
        tw, tstate = trust_word(cert)
        trust_icon = {"pass": "shield-check", "warn": "shield-alert", "fail": "shield-x"}[tstate]
        trust_sub = {
            "pass": "Łańcuch kończy się w zaufanym CA; profil KSeF spełniony.",
            "warn": self._first_reason(cert, GROUPS["trust"], None),
            "fail": self._first_reason(cert, GROUPS["trust"], CheckStatus.FAIL),
        }[tstate]
        self._set_card("trust", tw, tstate, trust_sub, trust_icon)
        ow, ostate = online_word(cert)
        online_icon = {"pass": "cloud-check", "fail": "x-circle", "warn": "cloud-alert", "unk": "cloud-off"}[
            ostate
        ]
        auth = cert.operations.get("authentication")
        online_sub = cert.checks["online"].summary
        if auth:
            online_sub = f"{auth['code']}: {auth['message']}"
        self._set_card("online", ow, ostate, online_sub, online_icon)
        for key in self._rows:
            chk = cert.checks[key]
            self._set_row(key, chk.status, row_summary(key, chk, cert))
        ops: list[str] = []
        if auth:
            ops.append(f"Uwierzytelnienie: {auth['authentication']} · Autoryzacja: {auth['authorization']}")
            ops.extend(f"• {st['name']}: {st['status']} – {st['message']}" for st in auth["steps"])
        kod = cert.operations.get("kod2")
        if kod:
            ops.append(f"Test KODU II: {kod['code']} – {kod['message']}")
            if kod.get("url"):
                ops.append("Link syntetyczny (dane testowe) – nie używać i nie wysyłać do KSeF.")
        self.lbl_ops.setText(clean("\n".join(ops)))
        self.lbl_result.setText(
            f"Zestaw certyfikatu i klucza – {lw}   ·   Zaufanie do certyfikatu – {tw}   ·   "
            f"Pełna walidacja: {VERDICT_PL[cert.verdict]}   ·   Podmiot: {subject_label(cert)}"
        )
        rep_notes = ("\n\nUwagi: " + "; ".join(rep.notes)) if rep.notes else ""
        self.details.setPlainText(
            cert_details_text(rep, cert, self.chk_details.isChecked()) + clean(rep_notes)
        )

    @staticmethod
    def _first_reason(cert: CertReport, keys: list[str], status: CheckStatus | None) -> str:
        for k in keys:
            chk = cert.checks[k]
            hit = (
                chk.status is status
                if status
                else chk.status in (CheckStatus.UNKNOWN, CheckStatus.NOT_CHECKED)
            )
            if hit:
                return f"{CHECK_LABEL[k]}: {row_summary(k, chk, cert)}"
        return ""

    def _toggle_details(self, shown: bool) -> None:
        self.details.setVisible(shown)
        self._show_selected()

    # ---------- eksport ----------
    def export_document(self) -> dict | None:
        """Ten sam dokument co `ksef-cert-verify verify --json` (przy tych samych ścieżkach i zegarze)."""
        if self._report is None or self._last_options is None:
            return None
        return build_json([self._report], self._last_options, __version__)

    def export_json(self) -> None:
        doc = self.export_document()
        if doc is None:
            self._message("Eksport", "Brak wyników do wyeksportowania.", True)
            return
        path = self._pick_save_path()
        if not path:
            return
        try:
            Path(path).write_text(dumps(doc) + "\n", encoding="utf-8")
        except OSError as exc:
            self._message("Eksport", f"Nie udało się zapisać pliku: {exc.strerror or exc}", True)
            return
        self.statusBar().showMessage(f"Zapisano: {path}", 5000)

    def copy_to_clipboard(self) -> None:
        rep, cert = self._selected()
        if rep is None:
            return
        text = (
            cert_details_text(rep, cert, True)
            if cert is not None
            else clean(f"Plik: {rep.path}\nBłąd: {rep.error.message if rep.error else ''}")
        )
        QGuiApplication.clipboard().setText(text)
        self.statusBar().showMessage("Skopiowano do schowka.", 3000)


def _is_ca(cert: Any) -> bool:
    from cryptography import x509

    try:
        return bool(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        return False
