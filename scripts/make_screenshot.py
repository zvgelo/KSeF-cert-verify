"""Generuje docs/img/gui-light.png i gui-dark.png z danych SYNTETYCZNYCH (offscreen).
Użycie: python scripts/make_screenshot.py docs/img"""

import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from pathlib import Path

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QApplication

from ksef_cert_verify.core.report import VerifyOptions
from ksef_cert_verify.core.trust_store import TrustStore
from ksef_cert_verify.gui import icons
from ksef_cert_verify.gui.main_window import MainWindow
from tests.conftest import KEY_PASSWORD, NOW, make_ca, make_leaf, pem, write_key

app = QApplication([])
app.setWindowIcon(icons.app_icon())
ca = make_ca()
tmp = Path(tempfile.mkdtemp())
cert, key = make_leaf(ca)
(tmp / "KSeF_Ksiegowosc.crt").write_bytes(pem(cert))
write_key(tmp / "KSeF_Ksiegowosc.key", key)


def f(anchor):
    def g():
        t = TrustStore()
        if anchor:
            t.add(ca.cert, "s")
        return VerifyOptions(trust=t, now=NOW)

    return g


out = Path(sys.argv[1])
for mode, anchor, name in (("light", False, "gui-light"), ("dark", True, "gui-dark")):
    ini = QSettings(str(tmp / f"{mode}.ini"), QSettings.Format.IniFormat)
    ini.setValue("theme", mode)
    w = MainWindow(options_factory=f(anchor), settings=ini)
    w.show()
    w.set_cert(tmp / "KSeF_Ksiegowosc.crt")
    w.set_key(tmp / "KSeF_Ksiegowosc.key")
    w.edit_password.setText(KEY_PASSWORD)
    w.start_verification()
    w.wait_until_idle()
    for _ in range(60):
        app.processEvents()
    w.grab().save(str(out / f"{name}.png"))
    w.close()
print("ok")
