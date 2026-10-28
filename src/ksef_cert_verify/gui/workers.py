"""Praca w tle: dowolne zadanie (weryfikacja, uwierzytelnienie, KOD II) poza głównym wątkiem GUI."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QRunnable, Signal


class WorkerSignals(QObject):
    done = Signal(object)  # wynik zadania albo wyjątek (Exception)
    finished = Signal()


class JobTask(QRunnable):
    """Uruchamia `job()` w puli wątków. Wynik/wyjątek wraca sygnałem do wątku GUI.

    Hasło i tokeny żyją wyłącznie w domknięciu `job` i są zwalniane po zakończeniu (`clear_secrets`).
    """

    def __init__(self, job: Callable[[], Any], clear_secrets: Callable[[], None] | None = None) -> None:
        super().__init__()
        self.setAutoDelete(False)  # okno trzyma referencję do czasu zakończenia
        self._job = job
        self._clear = clear_secrets
        self.signals = WorkerSignals()

    def run(self) -> None:
        try:
            try:
                result: Any = self._job()
            except Exception as exc:  # nieprzewidziany błąd nie może zabić wątku po cichu
                result = exc
            self.signals.done.emit(result)
        finally:
            if self._clear is not None:
                self._clear()
            self._job = lambda: None
            self.signals.finished.emit()
