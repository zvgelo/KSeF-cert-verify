"""Zapisuje SYNTETYCZNĄ parę testową (CA + certyfikat + zaszyfrowany klucz) do katalogu.

To NIE jest certyfikat KSeF. Używane przez testy instalatorów. Użycie: python scripts/make_fixture_pair.py DIR
Pliki: KSeF_Ksiegowosc.crt, KSeF_Ksiegowosc.key, ca.pem, password.txt (hasło testowe, jawne – dane syntetyczne).
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ksef_cert_verify.gui.selftest import SELFTEST_PASSWORD, _make_pair  # noqa: E402


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as d:
        cert, key, ca = _make_pair(Path(d))
        (out / "KSeF_Ksiegowosc.crt").write_bytes(cert.read_bytes())
        (out / "KSeF_Ksiegowosc.key").write_bytes(key.read_bytes())
        (out / "ca.pem").write_bytes(ca.read_bytes())
    (out / "password.txt").write_text(SELFTEST_PASSWORD + "\n", encoding="utf-8")
    print(f"zapisano parę syntetyczną w {out}")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
