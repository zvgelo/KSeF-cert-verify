"""System projektowy GUI: tokeny kolorów, odstępów i typografii + generator QSS (jasny/ciemny motyw).

Zasady: jeden promień zaokrąglenia, cienkie obwódki zamiast cieni, status zawsze z symbolem i słowem
(kolor jest tylko wzmocnieniem), kontrast tekstu ≥ 4.5:1 w obu motywach.
"""

from __future__ import annotations

from typing import Literal

Mode = Literal["light", "dark"]

SPACE = {"xs": 4, "sm": 8, "md": 12, "lg": 20, "xl": 28}
RADIUS = 6
FONT_FAMILIES = ["Segoe UI Variable Text", "Segoe UI", "Noto Sans", "Cantarell", "Ubuntu", "DejaVu Sans"]
MONO_FAMILIES = ["Cascadia Mono", "Consolas", "DejaVu Sans Mono", "Noto Sans Mono"]
SCALE = {"caption": 12, "body": 13, "title": 15, "verdict": 24}

PALETTES: dict[str, dict[str, str]] = {
    "light": {
        "bg": "#F3F5F8",
        "surface": "#FFFFFF",
        "surface_alt": "#EDF0F5",
        "border": "#D5DBE4",
        "text": "#17212E",
        "muted": "#566274",
        "accent": "#2557D6",
        "accent_text": "#FFFFFF",
        "accent_hover": "#1E47B3",
        "focus": "#2557D6",
        "pass_fg": "#17673F",
        "pass_bg": "#E3F4EA",
        "fail_fg": "#A8231A",
        "fail_bg": "#FBE7E5",
        "warn_fg": "#8A5200",
        "warn_bg": "#FCF0D9",
        "unk_fg": "#4A5568",
        "unk_bg": "#E6EAF0",
        "disabled": "#9AA5B4",
    },
    "dark": {
        "bg": "#0F141B",
        "surface": "#171E27",
        "surface_alt": "#1E2733",
        "border": "#2A3646",
        "text": "#E6EBF2",
        "muted": "#9AA7B8",
        "accent": "#6C95FF",
        "accent_text": "#0B1220",
        "accent_hover": "#8AAAFF",
        "focus": "#8AAAFF",
        "pass_fg": "#6FD3A0",
        "pass_bg": "#13301F",
        "fail_fg": "#FF8E85",
        "fail_bg": "#3A1714",
        "warn_fg": "#F2C265",
        "warn_bg": "#35280C",
        "unk_fg": "#B7C2D3",
        "unk_bg": "#232D3B",
        "disabled": "#5B6879",
    },
}

# Dla widgetów ustawianych kodem (np. kolor tekstu w tabeli).
STATUS_KEY = {
    "PASS": "pass",
    "FAIL": "fail",
    "WARNING": "warn",
    "UNKNOWN": "unk",
    "NOT_CHECKED": "unk",
    "VALID": "pass",
    "INVALID": "fail",
    "INDETERMINATE": "warn",
}


def color(mode: str, role: str) -> str:
    """Kolor ikony/tekstu dla roli: pass/fail/warn/unk (kolor pierwszoplanowy), text, muted, accent."""
    c = PALETTES[mode]
    return c.get(role + "_fg", c.get(role, c["text"]))


def build_qss(mode: Mode) -> str:
    c = PALETTES[mode]
    r, sp = RADIUS, SPACE
    fam = ", ".join(f'"{f}"' for f in FONT_FAMILIES)
    mono = ", ".join(f'"{f}"' for f in MONO_FAMILIES)
    badge = "".join(
        f'QLabel[badge="{k}"] {{ color: {c[k + "_fg"]}; background: {c[k + "_bg"]}; }}\n'
        for k in ("pass", "fail", "warn", "unk")
    )
    banner = "".join(
        f'QFrame#banner[state="{k}"] {{ background: {c[k + "_bg"]}; border: 1px solid {c[k + "_fg"]}; }}\n'
        f'QFrame#banner[state="{k}"] QLabel#bannerVerdict {{ color: {c[k + "_fg"]}; }}\n'
        for k in ("pass", "fail", "warn", "unk")
    )
    return f"""
* {{ font-family: {fam}; font-size: {SCALE["body"]}px; color: {c["text"]}; }}
QMainWindow, QWidget#root {{ background: {c["bg"]}; }}
QFrame#panel, QFrame#results {{ background: {c["surface"]}; border: 1px solid {c["border"]}; border-radius: {r}px; }}
QLabel {{ background: transparent; }}
QLabel#appTitle {{ font-size: {SCALE["title"] + 2}px; font-weight: 600; }}
QLabel#sectionTitle {{ font-size: {SCALE["title"]}px; font-weight: 600; }}
QLabel[role="muted"] {{ color: {c["muted"]}; font-size: {SCALE["caption"]}px; }}
QLabel[role="field"] {{ font-weight: 600; }}
QLabel#bannerVerdict {{ font-size: {SCALE["verdict"]}px; font-weight: 700; }}
QLabel#bannerMessage {{ color: {c["text"]}; }}
QLabel[role="checkTitle"] {{ font-weight: 600; }}
QLabel[badge] {{ border-radius: {r - 2}px; padding: 2px {sp["sm"]}px; font-weight: 600; font-size: {SCALE["caption"]}px; }}
{badge}
{banner}
QFrame#banner[state="idle"] {{ background: {c["surface_alt"]}; border: 1px solid {c["border"]}; }}
QFrame#banner {{ border-radius: {r}px; }}
QFrame[role="checkRow"] {{ border: none; border-bottom: 1px solid {c["border"]}; background: transparent; }}
QFrame#checkRowLast {{ border-bottom: none; }}
QLineEdit, QComboBox {{
    background: {c["surface"]}; border: 1px solid {c["border"]}; border-radius: {r}px;
    padding: 6px {sp["sm"]}px; min-height: 20px; selection-background-color: {c["accent"]}; selection-color: {c["accent_text"]};
}}
QLineEdit:focus, QComboBox:focus {{ border: 2px solid {c["focus"]}; padding: 5px {sp["sm"] - 1}px; }}
QLineEdit:disabled, QComboBox:disabled {{ color: {c["disabled"]}; background: {c["surface_alt"]}; }}
QComboBox QAbstractItemView {{ background: {c["surface"]}; border: 1px solid {c["border"]}; selection-background-color: {c["accent"]}; selection-color: {c["accent_text"]}; }}
QPushButton, QToolButton {{
    background: {c["surface"]}; border: 1px solid {c["border"]}; border-radius: {r}px; padding: 6px {sp["md"]}px; min-height: 20px;
}}
QPushButton:hover, QToolButton:hover {{ background: {c["surface_alt"]}; }}
QPushButton:focus, QToolButton:focus {{ border: 2px solid {c["focus"]}; padding: 5px {sp["md"] - 1}px; }}
QPushButton:checked {{ background: {c["surface_alt"]}; border-color: {c["accent"]}; }}
QPushButton:disabled, QToolButton:disabled {{ color: {c["disabled"]}; background: {c["surface_alt"]}; }}
QPushButton[primary="true"] {{ background: {c["accent"]}; color: {c["accent_text"]}; border: 1px solid {c["accent"]}; font-weight: 600; padding: 9px {sp["lg"]}px; }}
QPushButton[primary="true"]:hover {{ background: {c["accent_hover"]}; }}
QPushButton[primary="true"]:disabled {{ background: {c["surface_alt"]}; color: {c["disabled"]}; border-color: {c["border"]}; }}
QCheckBox {{ spacing: {sp["sm"]}px; background: transparent; }}
QCheckBox::indicator {{ width: 16px; height: 16px; border: 1px solid {c["muted"]}; border-radius: 4px; background: {c["surface"]}; }}
QCheckBox::indicator:checked {{ background: {c["accent"]}; border-color: {c["accent"]}; }}
QCheckBox::indicator:focus {{ border: 2px solid {c["focus"]}; }}
QPlainTextEdit {{
    background: {c["surface_alt"]}; border: 1px solid {c["border"]}; border-radius: {r}px; padding: {sp["sm"]}px;
    font-family: {mono}; font-size: {SCALE["caption"]}px;
}}
QStatusBar {{ background: {c["bg"]}; color: {c["muted"]}; }}
QStatusBar QLabel {{ color: {c["muted"]}; }}
QToolTip {{ background: {c["surface"]}; color: {c["text"]}; border: 1px solid {c["border"]}; padding: {sp["xs"]}px; }}
QDialog, QMessageBox, QInputDialog {{ background: {c["surface"]}; }}
QDialog QLabel, QMessageBox QLabel {{ color: {c["text"]}; }}
QRadioButton {{ spacing: {sp["sm"]}px; background: transparent; padding: 2px 0; }}
QRadioButton::indicator {{ width: 10px; height: 10px; border: 2px solid {c["muted"]}; border-radius: 7px; background: {c["surface"]}; }}
QRadioButton::indicator:checked {{ border: 2px solid {c["accent"]}; background: {c["accent"]}; }}
QRadioButton:disabled {{ color: {c["disabled"]}; }}
QScrollArea {{ border: none; background: transparent; }}
QScrollArea > QWidget > QWidget {{ background: transparent; }}
QFrame[role="card"] {{ background: {c["surface_alt"]}; border: 1px solid {c["border"]}; border-radius: {r}px; }}
QFrame[role="card"][state="pass"] {{ background: {c["pass_bg"]}; border: 1px solid {c["pass_fg"]}; }}
QFrame[role="card"][state="fail"] {{ background: {c["fail_bg"]}; border: 1px solid {c["fail_fg"]}; }}
QFrame[role="card"][state="warn"] {{ background: {c["warn_bg"]}; border: 1px solid {c["warn_fg"]}; }}
QFrame[role="card"][state="unk"] {{ background: {c["unk_bg"]}; border: 1px solid {c["border"]}; }}
QLabel[role="cardTitle"] {{ font-weight: 600; font-size: {SCALE["caption"]}px; color: {c["muted"]}; }}
QLabel[role="cardStatus"] {{ font-weight: 700; font-size: {SCALE["title"] + 2}px; }}
QLabel[role="cardStatus"][state="pass"] {{ color: {c["pass_fg"]}; }}
QLabel[role="cardStatus"][state="fail"] {{ color: {c["fail_fg"]}; }}
QLabel[role="cardStatus"][state="warn"] {{ color: {c["warn_fg"]}; }}
QLabel[role="cardStatus"][state="unk"] {{ color: {c["unk_fg"]}; }}
QLabel[role="sectionHeader"] {{ font-weight: 700; font-size: {SCALE["body"]}px; letter-spacing: 0.5px; color: {c["accent"]}; }}
QFrame[role="rule"] {{ background: {c["border"]}; max-height: 1px; min-height: 1px; border: none; }}
QLabel[role="chip"] {{ background: {c["surface_alt"]}; border: 1px solid {c["border"]}; border-radius: 10px; padding: 1px 10px; font-size: {SCALE["caption"]}px; }}
QLabel[role="warnNote"] {{ color: {c["warn_fg"]}; background: {c["warn_bg"]}; border-radius: {r - 2}px; padding: 4px {sp["sm"]}px; }}
QPushButton[role="link"] {{ border: 2px solid transparent; background: transparent; color: {c["accent"]}; text-align: left; padding: 2px; text-decoration: underline; font-weight: 600; }}
QPushButton[role="link"]:hover {{ color: {c["accent_hover"]}; }}
QPushButton[role="link"]:focus {{ border: 2px solid {c["focus"]}; padding: 2px; }}
QDialog#aboutDialog {{ background: {c["surface"]}; }}
QLabel#aboutName {{ font-size: {SCALE["verdict"]}px; font-weight: 700; }}
QPushButton[flat="true"] {{ border: none; background: transparent; color: {c["accent"]}; text-align: left; padding: 4px 0; }}
QMenu {{ background: {c["surface"]}; border: 1px solid {c["border"]}; padding: {sp["xs"]}px; }}
QMenu::item {{ padding: 6px {sp["lg"]}px; border-radius: 4px; }}
QMenu::item:selected {{ background: {c["accent"]}; color: {c["accent_text"]}; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {c["border"]}; border-radius: 5px; min-height: 24px; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
"""
