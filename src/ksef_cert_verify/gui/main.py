"""Punkt wejścia GUI."""

from __future__ import annotations

import os
import sys


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    trace = os.environ.get("KSEF_CERT_VERIFY_TRACE")
    if trace:  # diagnostyka na życzenie: zrzut stosu do pliku po 40 s (gdzie „wisi” start); tylko ramki stosu, bez danych
        import faulthandler

        trace_file = open(trace, "w", encoding="utf-8")  # noqa: SIM115 - musi żyć do końca procesu
        faulthandler.enable(trace_file)
        faulthandler.dump_traceback_later(40, file=trace_file)
    if "--selftest" in argv:
        from .selftest import run_selftest

        report = argv[argv.index("--selftest-report") + 1] if "--selftest-report" in argv else None
        return run_selftest(report)
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QFont, QGuiApplication
    from PySide6.QtWidgets import QApplication

    from .main_window import MainWindow
    from .theme import FONT_FAMILIES

    # Qt 6 skaluje High DPI domyślnie; PassThrough daje dokładne skalowanie ułamkowe (Windows 125/150%).
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication.instance() or QApplication(sys.argv[:1])
    if not isinstance(app, QApplication):
        raise RuntimeError("Nie można utworzyć QApplication")
    app.setApplicationName("KSeF CertVerify")
    app.setOrganizationName("KSeF-cert-verify")  # identyfikator wewnętrzny (ustawienia) – nie zmieniać
    QGuiApplication.setDesktopFileName("ksef-cert-verify")  # dopasowanie do pliku .desktop (Wayland)
    if sys.platform == "win32":
        try:  # własna grupa na pasku zadań Windows (poprawna ikona zamiast ikony interpretera)
            import ctypes

            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("KSeFcertverify.GUI")  # type: ignore[attr-defined]
        except Exception:  # nosec B110 - ustawienie kosmetyczne (AppUserModelID/zapis motywu), brak wpływu na bezpieczeństwo
            pass
    from . import icons

    app.setWindowIcon(icons.app_icon())
    font = QFont()
    font.setFamilies(FONT_FAMILIES)
    app.setFont(font)
    window = MainWindow()
    window.show()
    if trace:  # diagnostyka: stan okna widziany od środka (platforma Qt, widoczność, ekran, geometria)
        from PySide6.QtCore import QTimer

        def window_state() -> None:
            screen = window.screen()
            trace_file.write(
                f"\n[stan okna] platforma={app.platformName()} widoczne={window.isVisible()} "
                f"minimalizowane={window.isMinimized()} geometria={window.geometry().getRect()} "
                f"ekran={screen.name() if screen else None} ekrany={len(app.screens())}\n"
            )
            trace_file.flush()

        QTimer.singleShot(2000, window_state)
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
