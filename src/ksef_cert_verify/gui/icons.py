"""Ikony SVG (własny zestaw w `gui/assets/icons`) renderowane w kolorach aktywnego motywu, z obsługą HiDPI."""

from __future__ import annotations

import sys
from functools import lru_cache
from pathlib import Path

from PySide6.QtCore import QByteArray, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer


def _assets_dir() -> Path:
    """Zasoby GUI: w aplikacji PyInstaller (onedir/onefile) leżą w katalogu rozpakowania (`sys._MEIPASS`)."""
    base = getattr(sys, "_MEIPASS", None)
    if base:
        packed = Path(base) / "ksef_cert_verify" / "gui" / "assets"
        if packed.is_dir():
            return packed
    return Path(__file__).resolve().parent / "assets"


ASSETS = _assets_dir()

# status kontroli → (ikona, rola koloru)
STATUS_ICON = {
    "PASS": ("check-circle", "pass"),
    "FAIL": ("x-circle", "fail"),
    "WARNING": ("alert-triangle", "warn"),
    "UNKNOWN": ("help-circle", "unk"),
    "NOT_CHECKED": ("info", "unk"),
}


def asset(name: str) -> Path:
    return ASSETS / name


@lru_cache(maxsize=512)
def _svg_text(name: str) -> str:
    return (ASSETS / "icons" / f"{name}.svg").read_text(encoding="utf-8")


@lru_cache(maxsize=1024)
def pixmap(name: str, color: str, size: int = 18, dpr: float = 1.0) -> QPixmap:
    svg = _svg_text(name).replace("currentColor", color)
    renderer = QSvgRenderer(QByteArray(svg.encode("utf-8")))
    px = int(round(size * dpr))
    pm = QPixmap(px, px)
    pm.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pm)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    renderer.render(painter)
    painter.end()
    pm.setDevicePixelRatio(dpr)
    return pm


def icon(name: str, color: str, size: int = 18) -> QIcon:
    """QIcon z wariantami 1x/2x/3x (ostre na ekranach HiDPI)."""
    ic = QIcon()
    for dpr in (1.0, 2.0, 3.0):
        ic.addPixmap(pixmap(name, color, size, dpr))
    return ic


def app_icon() -> QIcon:
    """Ikona aplikacji (okno i pasek zadań)."""
    ic = QIcon()
    svg = ASSETS / "logo.svg"
    if svg.exists():
        ic.addFile(str(svg))
    png = ASSETS / "logo.png"
    if png.exists():
        ic.addFile(str(png))
    return ic
