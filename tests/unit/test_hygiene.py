"""Higiena repozytorium i regresje bezpieczeństwa znalezione w audycie przed wydaniem."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BIDI = re.compile(
    "["
    + "".join(
        chr(c) for c in list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A)) + [0x200E, 0x200F, 0x061C]
    )
    + "]"
)


def tracked_text_files():
    try:
        out = subprocess.run(
            ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.split("\n")
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("brak git")
    return [
        ROOT / f
        for f in out
        if f.endswith(
            (".py", ".md", ".toml", ".yml", ".yaml", ".iss", ".ps1", ".sh", ".spec", ".in", ".desktop")
        )
    ]


def test_no_bidi_control_characters_in_tracked_sources():
    """Trojan Source: literalne znaki sterujące bidi w kodzie są niedozwolone (używaj chr()/escape)."""
    bad = [
        f.name for f in tracked_text_files() if BIDI.search(f.read_text(encoding="utf-8", errors="ignore"))
    ]
    assert bad == []


def test_no_private_key_material_tracked():
    """Śledzone pliki nie zawierają kluczy prywatnych (poza oczywistymi atrapami 'AAAA' w testach)."""
    real = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----\s*[A-Za-z0-9+/=\s]{80,}-----END")
    for f in tracked_text_files():
        assert not real.search(f.read_text(encoding="utf-8", errors="ignore")), f.name


def test_gitignore_blocks_secret_files():
    text = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for pattern in (".env", "*.key", "*.p12", "*.pfx", ".mcp.json", ".claude/"):
        assert pattern in text


def test_unexpected_exception_does_not_print_traceback_locals(tmp_path):
    """Nieoczekiwany wyjątek nie wypisuje zmiennych lokalnych (hasło/token) ani śladu stosu."""
    code = (
        "import sys\n"
        "from ksef_cert_verify import cli\n"
        "def boom(*a, **k):\n"
        "    secret_password = 'SEKRET-HASLO-123'\n"
        "    raise RuntimeError('awaria')\n"
        "cli.verify_with_online = boom\n"
        "sys.argv = ['x', 'verify', '--cert', 'a.crt', '--key', 'a.key']\n"
        "cli.main()\n"
    )
    env = {k: v for k, v in os.environ.items() if k != "KSEF_CERT_VERIFY_DEBUG"}
    r = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        encoding="utf-8",  # CLI zawsze pisze UTF-8; bez tego Windows dekoduje wg strony kodowej (cp1250)
        env=env,
        timeout=60,
        cwd=tmp_path,
        stdin=subprocess.DEVNULL,
    )
    assert r.returncode == 2 and "SEKRET-HASLO-123" not in r.stdout + r.stderr and "Traceback" not in r.stderr
    assert "Błąd wewnętrzny (RuntimeError)" in r.stderr


@pytest.mark.skipif(sys.platform == "win32", reason="uprawnienia POSIX")
def test_world_writable_default_trust_dir_is_ignored(tmp_path, ca, monkeypatch):
    from ksef_cert_verify.core.trust_store import TrustStore
    from tests.conftest import pem

    d = tmp_path / "trust"
    d.mkdir()
    (d / "ca.pem").write_bytes(pem(ca.cert))
    monkeypatch.setenv("KSEF_CERT_VERIFY_TRUST_DIR", str(d))
    os.chmod(d, 0o755)
    assert len(TrustStore.from_paths([])) == 1  # bezpieczne uprawnienia → ładowane
    os.chmod(d, 0o777)
    store = TrustStore.from_paths([])
    assert len(store) == 0 and any("zapisywalny" in w for w in store.warnings)


def test_stdin_terminal_detection_rejects_nul_like_devices(monkeypatch):
    """Windows: isatty() jest True dla NUL, ale bez bufora konsoli nie wolno pytać o hasło (getpass czytałby z konsoli)."""
    import io

    from ksef_cert_verify import cli

    class FakeTty(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(cli.sys, "stdin", FakeTty())
    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli, "_windows_console_attached", lambda: False)  # NUL
    assert cli._stdin_is_terminal() is False
    monkeypatch.setattr(cli, "_windows_console_attached", lambda: True)  # prawdziwa konsola
    assert cli._stdin_is_terminal() is True
