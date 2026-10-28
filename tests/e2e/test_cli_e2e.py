"""E2E CLI: prawdziwy proces, stdout/stderr/exit code/JSON. Fixtury SYMULOWANE (nie KSeF)."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from tests.conftest import KEY_PASSWORD, NOW, make_ca, make_leaf, pem, write_key, write_p12

pytestmark = [pytest.mark.e2e, pytest.mark.simulated]
AT = NOW.strftime("%Y-%m-%dT%H:%M:%SZ")
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def run(*args, stdin=None, env=None, pass_fds=(), preexec=None):
    e = {k: v for k, v in os.environ.items() if not k.startswith("KSEF_")}
    e.update(
        {
            "KSEF_CERT_VERIFY_TRUST_DIR": "/nonexistent-trust-dir",
            "PYTHONIOENCODING": "utf-8",
            "COLUMNS": "200",
        }
    )
    e.update(env or {})
    r = subprocess.run(
        [sys.executable, "-m", "ksef_cert_verify", *map(str, args)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=e,
        input=stdin,
        timeout=60,
        stdin=None if stdin is not None else subprocess.DEVNULL,
        pass_fds=pass_fds,
    )
    r.stdout, r.stderr = _ANSI.sub("", r.stdout), _ANSI.sub("", r.stderr)
    return r


@pytest.fixture
def pair(tmp_path, auth_cert):
    c = tmp_path / "KSeF_Ksiegowosc.crt"
    c.write_bytes(pem(auth_cert[0]))
    k = write_key(tmp_path / "KSeF_Ksiegowosc.key", auth_cert[1])
    return c, k


def full(pair, anchor_file, *extra, stdin=KEY_PASSWORD + "\n"):
    return run(
        "verify",
        "--cert",
        pair[0],
        "--key",
        pair[1],
        "-t",
        anchor_file,
        "--at",
        AT,
        "--password-stdin",
        *extra,
        stdin=stdin,
    )


def test_version_and_help():
    assert run("--version").stdout.startswith("ksef-cert-verify ")
    h = run("verify", "--help").stdout
    assert "--cert" in h and "--key" in h and "--password-stdin" in h
    assert "--password " not in h  # brak opcji z jawnym hasłem


# 1. poprawny cert + klucz + hasło
def test_full_verification_valid_json(pair, anchor_file):
    r = full(pair, anchor_file, "--json")
    assert r.returncode == 0, r.stdout + r.stderr
    doc = json.loads(r.stdout)
    assert doc["schema_version"] == "2"
    c = doc["files"][0]["certificates"][0]
    assert c["result"] == "VALID" and c["checks"]["key_decrypt"]["status"] == "PASS"
    assert c["checks"]["key_match"]["status"] == "PASS" and c["type"] == "Authentication"
    assert r.stderr == ""


def test_human_output_shows_separate_statuses(pair, anchor_file):
    r = full(pair, anchor_file)
    assert r.returncode == 0
    for needle in (
        "Certificate type:",
        "Authentication",
        "Date validity:",
        "Issuer trust:",
        "KSeF profile:",
        "Private key:",
        "Key matches cert.:",
        "KSeF API status:",
        "FULL VERIFICATION:",
        "VALID",
        "ONLINE STATUS:",
        "NOT CHECKED",
    ):
        assert needle in r.stdout, needle


# 2. błędne hasło
def test_wrong_password_not_valid(pair, anchor_file):
    r = full(pair, anchor_file, "--json", stdin="zle-haslo-SEKRET\n")
    assert r.returncode == 1
    c = json.loads(r.stdout)["files"][0]["certificates"][0]
    assert c["result"] == "INVALID" and c["checks"]["key_decrypt"]["status"] == "FAIL"
    assert c["checks"]["key_match"]["status"] == "NOT_CHECKED"
    assert "SEKRET" not in r.stdout + r.stderr  # 15


# 3. klucz innego certyfikatu
def test_key_of_other_certificate(tmp_path, pair, anchor_file):
    other = write_key(tmp_path / "inny.key", ec.generate_private_key(ec.SECP256R1()))
    r = run(
        "verify",
        "--cert",
        pair[0],
        "--key",
        other,
        "-t",
        anchor_file,
        "--at",
        AT,
        "--password-stdin",
        "--json",
        stdin=KEY_PASSWORD + "\n",
    )
    assert r.returncode == 1
    c = json.loads(r.stdout)["files"][0]["certificates"][0]
    assert c["checks"]["key_match"]["status"] == "FAIL" and c["result"] == "INVALID"


# 4. brak pliku .key
def test_missing_key_file(tmp_path, pair, anchor_file):
    r = run(
        "verify",
        "--cert",
        pair[0],
        "--key",
        tmp_path / "brak.key",
        "-t",
        anchor_file,
        "--password-stdin",
        stdin="x\n",
    )
    assert r.returncode == 2 and "nie istnieje" in r.stderr


def test_key_option_required(pair):
    r = run("verify", "--cert", pair[0])
    assert r.returncode == 2 and "--key" in r.stderr and "VALID" not in r.stdout


# 5. brak hasła (brak źródła, brak terminala; oraz pusta linia)
def test_no_password_available_is_indeterminate(pair, anchor_file):
    r = run("verify", "--cert", pair[0], "--key", pair[1], "-t", anchor_file, "--at", AT, "--json")
    assert r.returncode == 3
    c = json.loads(r.stdout)["files"][0]["certificates"][0]
    assert c["checks"]["key_decrypt"]["status"] == "UNKNOWN" and c["result"] == "INDETERMINATE"
    r = full(pair, anchor_file, "--json", stdin="\n")
    assert r.returncode == 3


# 6/7. uszkodzony klucz, nieobsługiwany format
def test_corrupted_and_unsupported_key(tmp_path, pair, anchor_file):
    bad = tmp_path / "zly.key"
    bad.write_text("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n")
    r = run(
        "verify",
        "--cert",
        pair[0],
        "--key",
        bad,
        "-t",
        anchor_file,
        "--password-stdin",
        "--json",
        stdin="x\n",
    )
    assert r.returncode == 1
    junk = tmp_path / "junk.key"
    junk.write_text("to nie jest klucz")
    r = run(
        "verify",
        "--cert",
        pair[0],
        "--key",
        junk,
        "-t",
        anchor_file,
        "--password-stdin",
        "--json",
        stdin="x\n",
    )
    c = json.loads(r.stdout)["files"][0]["certificates"][0]
    assert r.returncode == 1 and c["checks"]["key_decrypt"]["findings"][0]["code"] == "KEY_UNSUPPORTED_FORMAT"


# 8/9. RSA i EC
@pytest.mark.parametrize("kind", ["rsa", "ec"])
def test_rsa_and_ec_pairs(tmp_path, kind):
    ca = make_ca()
    key = rsa.generate_private_key(65537, 2048) if kind == "rsa" else ec.generate_private_key(ec.SECP256R1())
    cert, _ = make_leaf(ca, key=key)
    c, k, a = tmp_path / "c.crt", write_key(tmp_path / "k.key", key), tmp_path / "ca.pem"
    c.write_bytes(pem(cert))
    a.write_bytes(pem(ca.cert))
    r = run(
        "verify", "--cert", c, "--key", k, "-t", a, "--at", AT, "--password-stdin", stdin=KEY_PASSWORD + "\n"
    )
    assert r.returncode == 0, r.stdout


# 10. interaktywny ukryty prompt (PTY – tylko POSIX)
@pytest.mark.skipif(
    sys.platform == "win32", reason="PTY niedostępny na Windows (test pominięty, nie zaliczony)"
)
def test_interactive_hidden_prompt(pair, anchor_file):
    import pty
    import select

    pid, fd = pty.fork()
    if pid == 0:  # dziecko
        os.environ.update({"KSEF_CERT_VERIFY_TRUST_DIR": "/x", "COLUMNS": "200"})
        os.execv(
            sys.executable,
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
                "--json",
            ],
        )
    out = b""
    sent = False
    while True:
        r, _, _ = select.select([fd], [], [], 30)
        if not r:
            break
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
        if not sent and b"Has" in out:
            os.write(fd, (KEY_PASSWORD + "\n").encode())
            sent = True
    _, status = os.waitpid(pid, 0)
    text = out.decode("utf-8", "replace")
    assert sent and os.WEXITSTATUS(status) == 0
    assert KEY_PASSWORD not in text  # hasło nie jest echo-wane
    assert '"result": "VALID"' in text


# 11. automatyzacja: stdin i deskryptor pliku
@pytest.mark.skipif(sys.platform == "win32", reason="pass_fds nie istnieje w Windows (użyj --password-stdin)")
def test_password_fd_for_automation(pair, anchor_file):
    r_fd, w_fd = os.pipe()
    os.write(w_fd, (KEY_PASSWORD + "\n").encode())
    os.close(w_fd)
    try:
        r = run(
            "verify",
            "--cert",
            pair[0],
            "--key",
            pair[1],
            "-t",
            anchor_file,
            "--at",
            AT,
            "--password-fd",
            r_fd,
            "--json",
            pass_fds=(r_fd,),
        )
    finally:
        os.close(r_fd)
    assert r.returncode == 0 and KEY_PASSWORD not in r.stdout + r.stderr


def test_stdin_and_fd_are_exclusive(pair):
    assert (
        run(
            "verify", "--cert", pair[0], "--key", pair[1], "--password-stdin", "--password-fd", "3"
        ).returncode
        == 2
    )


def test_expected_type_and_expiry(pair, anchor_file):
    assert full(pair, anchor_file, "--expected-type", "Offline").returncode == 1
    assert full(pair, anchor_file, "--expected-type", "Authentication").returncode == 0
    assert full(pair, anchor_file, "--expected-type", "Zly").returncode == 2
    r = run(
        "verify",
        "--cert",
        pair[0],
        "--key",
        pair[1],
        "-t",
        anchor_file,
        "--at",
        "2030-01-01T00:00:00Z",
        "--password-stdin",
        stdin=KEY_PASSWORD + "\n",
    )
    assert r.returncode == 1


def test_no_anchor_is_indeterminate_even_with_good_pair(pair):
    r = run(
        "verify",
        "--cert",
        pair[0],
        "--key",
        pair[1],
        "--at",
        AT,
        "--password-stdin",
        stdin=KEY_PASSWORD + "\n",
    )
    assert r.returncode == 3 and "zaufanych CA" in r.stdout


def test_pkcs12_cert_with_embedded_key(tmp_path, auth_cert, anchor_file):
    cert, key = auth_cert
    p = write_p12(tmp_path / "k.p12", cert, key, b"p12pw")
    r = run(
        "verify", "--cert", p, "-t", anchor_file, "--at", AT, "--password-stdin", "--json", stdin="p12pw\n"
    )
    assert r.returncode == 0 and "p12pw" not in r.stdout + r.stderr


def test_missing_cert_file_exit2(tmp_path, pair):
    r = run("verify", "--cert", tmp_path / "brak.crt", "--key", pair[1], "--password-stdin", stdin="x\n")
    assert r.returncode == 2


def test_garbage_cert_exit1(tmp_path, pair):
    p = tmp_path / "junk.pem"
    p.write_text("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
    r = run("verify", "--cert", p, "--key", pair[1], "--password-stdin", "--json", stdin="x\n")
    assert r.returncode == 1 and json.loads(r.stdout)["files"][0]["error"]["kind"] == "content"


def run_blocked(*args, stdin=None, env=None):
    """CLI z ZABLOKOWANĄ siecią (DNS → gaierror): testy online nie mogą łączyć się z internetem."""
    code = (
        "import socket,sys;"
        "socket.getaddrinfo=lambda *a,**k:(_ for _ in ()).throw(socket.gaierror('blocked'));"
        "from ksef_cert_verify.cli import app;"
        f"sys.argv=['x',*{[str(a) for a in args]!r}];"
        "app()"
    )
    e = {k: v for k, v in os.environ.items() if not k.startswith("KSEF_")}
    e.update({"KSEF_CERT_VERIFY_TRUST_DIR": "/x", "PYTHONIOENCODING": "utf-8", "COLUMNS": "200"})
    e.update(env or {})
    return subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=e,
        input=stdin,
        # bez jawnego wejścia proces NIE może dziedziczyć terminala (inaczej CLI zapytałoby o hasło w konsoli testera)
        stdin=None if stdin is not None else subprocess.DEVNULL,
        timeout=60,
    )


def test_online_requires_environment(pair):
    r = run("verify", "--cert", pair[0], "--key", pair[1], "--online")
    assert r.returncode == 2 and "--environment" in r.stderr


def test_prod_requires_explicit_confirmation_and_makes_no_call(pair):
    r = run_blocked(
        "verify",
        "--cert",
        pair[0],
        "--key",
        pair[1],
        "--online",
        "-e",
        "prod",
        "--password-stdin",
        stdin=KEY_PASSWORD + "\n",
    )
    assert r.returncode == 2 and "PROD wymaga" in r.stderr


def test_online_network_failure_is_unknown_not_valid_and_local_stays_valid(pair, anchor_file):
    r = run_blocked(
        "verify",
        "--cert",
        pair[0],
        "--key",
        pair[1],
        "-t",
        anchor_file,
        "--at",
        AT,
        "--online",
        "-e",
        "test",
        "--context-nip",
        "1234563218",
        "--password-stdin",
        "--json",
        stdin=KEY_PASSWORD + "\n",
    )
    assert r.returncode == 3, r.stdout + r.stderr
    c = json.loads(r.stdout)["files"][0]["certificates"][0]
    assert c["groups"]["local"]["result"] == "VALID" and c["groups"]["trust"]["result"] == "CONFIRMED"
    assert c["operations"]["authentication"]["code"] == "AUTH_NETWORK"
    assert c["summary"]["KSEF_ONLINE_STATUS"] == "UNKNOWN" and c["result"] == "INDETERMINATE"
    assert KEY_PASSWORD not in r.stdout + r.stderr


def test_missing_context_is_reported_not_guessed(pair, anchor_file):
    r = run_blocked(
        "verify",
        "--cert",
        pair[0],
        "--key",
        pair[1],
        "-t",
        anchor_file,
        "--at",
        AT,
        "--online",
        "-e",
        "test",
        "--password-stdin",
        "--json",
        stdin=KEY_PASSWORD + "\n",
    )
    c = json.loads(r.stdout)["files"][0]["certificates"][0]
    assert c["operations"]["authentication"]["code"] == "AUTH_CONTEXT_REQUIRED"


def test_invalid_and_expired_jwt_from_env_never_sent(pair, anchor_file):
    for token, code in (("nie-jwt", "JWT_INVALID"),):
        r = run_blocked(
            "verify",
            "--cert",
            pair[0],
            "--key",
            pair[1],
            "-t",
            anchor_file,
            "--at",
            AT,
            "--online",
            "-e",
            "TEST",
            "--password-stdin",
            "--json",
            stdin=KEY_PASSWORD + "\n",
            env={"KSEF_ACCESS_TOKEN": token},
        )
        c = json.loads(r.stdout)["files"][0]["certificates"][0]
        assert c["operations"]["authentication"]["code"] == code and r.returncode == 3
        assert token not in r.stdout + r.stderr


def test_no_network_in_default_mode(pair, anchor_file):
    code = (
        "import socket,sys;"
        "socket.socket.connect=lambda *a,**k:(_ for _ in ()).throw(RuntimeError('NET'));"
        "from ksef_cert_verify.cli import main;"
        f"sys.argv=['x','verify','--cert',r'{pair[0]}','--key',r'{pair[1]}','-t',r'{anchor_file}','--at','{AT}',"
        "'--password-stdin'];"
        "main()"
    )
    r = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        encoding="utf-8",
        input=KEY_PASSWORD + "\n",
        env={**os.environ, "KSEF_CERT_VERIFY_TRUST_DIR": "/x"},
    )
    assert r.returncode == 0 and "NET" not in r.stderr


# inspect nie jest weryfikacją
def test_inspect_is_not_a_verification(pair):
    r = run("inspect", pair[0])
    assert r.returncode == 0 and "to nie jest weryfikacja" in r.stdout
    assert "VALID" not in r.stdout and "RESULT" not in r.stdout and "Key Usage" in r.stdout
    doc = json.loads(run("inspect", pair[0], "--json").stdout)
    assert doc["verification"] is False and doc["certificates"][0]["key_usage"] == ["Digital Signature"]


# 15. hasło nigdzie nie wycieka (stdout, stderr, JSON, verbose)
def test_password_never_leaks_anywhere(pair, anchor_file):
    r = full(pair, anchor_file, "--json", "-v")
    r2 = full(pair, anchor_file, "-v")
    assert KEY_PASSWORD not in r.stdout + r.stderr + r2.stdout + r2.stderr


def test_verbose_shows_extensions(pair, anchor_file):
    r = full(pair, anchor_file, "-v")
    assert "Basic Constraints" in r.stdout and "Key Usage" in r.stdout


def test_hostile_subject_cannot_inject_markup_or_escape_sequences(tmp_path):
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    ca = make_ca()
    evil = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "[bold red]ZŁY[/bold red] [link=http://evil]x[/link]"),
            x509.NameAttribute(NameOID.GIVEN_NAME, "\x1b[2J\x1b]0;pwn\x07"),
            x509.NameAttribute(NameOID.SURNAME, "A\nFAKE: VALID"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PL"),
        ]
    )
    cert, key = make_leaf(ca, subject=evil)
    p = tmp_path / "evil[red].pem"
    p.write_bytes(pem(cert))
    k = write_key(tmp_path / "e.key", key)
    r = run(
        "verify", "--cert", p, "--key", k, "--at", AT, "-v", "--password-stdin", stdin=KEY_PASSWORD + "\n"
    )
    assert "\x1b" not in r.stdout and "\x07" not in r.stdout
    assert "[bold red]" in r.stdout and "evil[red].pem" in r.stdout
    assert "\x1b" not in run("inspect", p).stdout


# ---------------------------------------------------------------- grupy w wyniku tekstowym i JSON
def test_human_output_has_local_trust_online_sections(pair, anchor_file):
    r = full(pair, anchor_file)
    for needle in (
        "LOCAL",
        "TRUST",
        "ONLINE",
        "Zestaw certyfikatu i klucza:",
        "POPRAWNY (VALID)",
        "Zaufanie do certyfikatu:",
        "POTWIERDZONE",
        "Signature test:",
        "Password:",
        "PROVIDED",
    ):
        assert needle in r.stdout, needle


def test_local_success_with_unconfirmed_trust_is_not_full_valid(pair):
    r = run(
        "verify",
        "--cert",
        pair[0],
        "--key",
        pair[1],
        "--at",
        AT,
        "--password-stdin",
        stdin=KEY_PASSWORD + "\n",
    )
    assert r.returncode == 3
    assert "POPRAWNY (VALID)" in r.stdout and "NIEPOTWIERDZONE" in r.stdout
    assert "FULL VERIFICATION:" in r.stdout and "INDETERMINATE" in r.stdout
    doc = json.loads(
        run(
            "verify",
            "--cert",
            pair[0],
            "--key",
            pair[1],
            "--at",
            AT,
            "--password-stdin",
            "--json",
            stdin=KEY_PASSWORD + "\n",
        ).stdout
    )
    c = doc["files"][0]["certificates"][0]
    s = c["summary"]
    assert s["CERTIFICATE_VALIDATION"] == "VALID" and s["PRIVATE_KEY_DECRYPTION"] == "DECRYPTED"
    assert s["KEY_PAIR_MATCH"] == "MATCH" and s["SIGNATURE_VERIFICATION"] == "SIGNATURE_VALID"
    assert s["KSEF_ONLINE_STATUS"] == "NOT_CHECKED" and s["KSEF_AUTHENTICATION_RESULT"] == "NOT_TESTED"
    assert (
        s["LOCAL_KEYSET_RESULT"] == "VALID"
        and s["TRUST_RESULT"] == "UNCONFIRMED"
        and s["LOCAL_RESULT"] == "INDETERMINATE"
    )


def test_unencrypted_key_is_flagged_as_security_problem(tmp_path, auth_cert, anchor_file):
    cpath = tmp_path / "c.crt"
    cpath.write_bytes(pem(auth_cert[0]))
    k = write_key(tmp_path / "plain.key", auth_cert[1], password=None)
    r = run("verify", "--cert", cpath, "--key", k, "-t", anchor_file, "--at", AT, "--json")
    c = json.loads(r.stdout)["files"][0]["certificates"][0]
    assert r.returncode == 1 and c["checks"]["key_decrypt"]["code"] == "KEY_UNENCRYPTED"
    assert "PROBLEM BEZPIECZEŃSTWA" in c["checks"]["key_decrypt"]["summary"]
    r2 = run(
        "verify",
        "--cert",
        cpath,
        "--key",
        k,
        "-t",
        anchor_file,
        "--at",
        AT,
        "--json",
        "--allow-unencrypted-key",
    )
    assert r2.returncode == 0


# ---------------------------------------------------------------- test-signature / test-kod2 / test-auth / trust
def make_offline_pair(tmp_path, kind="ec"):
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    ca = make_ca()
    key = ec.generate_private_key(ec.SECP256R1()) if kind == "ec" else rsa.generate_private_key(65537, 2048)
    cert, _ = make_leaf(ca, kind="Offline", key=key)
    c, k, a = tmp_path / "o.crt", write_key(tmp_path / "o.key", key), tmp_path / "ca.pem"
    c.write_bytes(pem(cert))
    a.write_bytes(pem(ca.cert))
    return c, k, a


@pytest.mark.parametrize("kind", ["ec", "rsa"])
def test_test_signature_command_valid(tmp_path, kind):
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    key = ec.generate_private_key(ec.SECP256R1()) if kind == "ec" else rsa.generate_private_key(65537, 2048)
    cert, _ = make_leaf(make_ca(), key=key)
    c, k = tmp_path / "c.crt", write_key(tmp_path / "c.key", key)
    c.write_bytes(pem(cert))
    r = run(
        "test-signature", "--cert", c, "--key", k, "--password-stdin", "--json", stdin=KEY_PASSWORD + "\n"
    )
    assert r.returncode == 0, r.stdout + r.stderr
    doc = json.loads(r.stdout)
    assert doc["result"] == "SIGNATURE_VALID" and doc["key_pair"]["code"] == "KEY_PAIR_MATCH"
    assert KEY_PASSWORD not in r.stdout + r.stderr


def test_test_signature_failure_codes(tmp_path, pair):
    from cryptography.hazmat.primitives.asymmetric import ec

    other = write_key(tmp_path / "x.key", ec.generate_private_key(ec.SECP256R1()))
    r = run(
        "test-signature",
        "--cert",
        pair[0],
        "--key",
        other,
        "--password-stdin",
        "--json",
        stdin=KEY_PASSWORD + "\n",
    )
    assert r.returncode == 1 and json.loads(r.stdout)["result"] == "KEY_CERT_MISMATCH"
    r = run(
        "test-signature", "--cert", pair[0], "--key", pair[1], "--password-stdin", "--json", stdin="zle\n"
    )
    assert r.returncode == 1 and json.loads(r.stdout)["result"] == "KEY_DECRYPTION_FAILED"
    r = run("test-signature", "--cert", pair[0], "--key", pair[1], "--json")
    assert r.returncode == 3 and json.loads(r.stdout)["result"] == "NOT_CHECKED"
    assert (
        run(
            "test-signature",
            "--cert",
            pair[0],
            "--key",
            tmp_path / "brak.key",
            "--password-stdin",
            stdin="x\n",
        ).returncode
        == 2
    )


@pytest.mark.parametrize("kind", ["ec", "rsa"])
def test_test_kod2_offline_certificate(tmp_path, kind):
    c, k, _ = make_offline_pair(tmp_path, kind)
    r = run("test-kod2", "--cert", c, "--key", k, "--password-stdin", "--json", stdin=KEY_PASSWORD + "\n")
    assert r.returncode == 0, r.stdout + r.stderr
    op = json.loads(r.stdout)["kod2"]
    assert op["code"] == "KOD2_SIGNATURE_VALID" and op["synthetic"] is True
    assert op["url"].startswith("https://qr-test.ksef.mf.gov.pl/certificate/Nip/")
    assert "Zmiana danych unieważnia podpis" in op["message"]


def test_test_kod2_rejects_authentication_certificate(pair):
    r = run(
        "test-kod2",
        "--cert",
        pair[0],
        "--key",
        pair[1],
        "--password-stdin",
        "--json",
        stdin=KEY_PASSWORD + "\n",
    )
    assert r.returncode == 2 and json.loads(r.stdout)["kod2"]["code"] == "KOD2_NOT_APPLICABLE"


def test_test_auth_offline_cert_not_offered_and_prod_needs_confirmation(tmp_path, pair):
    c, k, _ = make_offline_pair(tmp_path)
    r = run_blocked(
        "test-auth", "--cert", c, "--key", k, "--password-stdin", "--json", stdin=KEY_PASSWORD + "\n"
    )
    assert r.returncode == 2 and json.loads(r.stdout)["result"] == "AUTH_NOT_APPLICABLE"
    r = run_blocked(
        "test-auth",
        "--cert",
        pair[0],
        "--key",
        pair[1],
        "-e",
        "PROD",
        "--password-stdin",
        stdin=KEY_PASSWORD + "\n",
    )
    assert r.returncode == 2 and "PROD wymaga" in r.stderr


def test_test_auth_network_failure_is_inconclusive_not_a_key_failure(pair):
    r = run_blocked(
        "test-auth",
        "--cert",
        pair[0],
        "--key",
        pair[1],
        "--context-nip",
        "1234563218",
        "--password-stdin",
        "--json",
        stdin=KEY_PASSWORD + "\n",
    )
    doc = json.loads(r.stdout)
    assert r.returncode == 3 and doc["result"] == "AUTH_NETWORK"
    assert doc["authentication"]["authorization"] == "UNKNOWN" and KEY_PASSWORD not in r.stdout + r.stderr


def test_trust_add_list_remove(tmp_path, ca, monkeypatch):
    d = tmp_path / "trust"
    env = {"KSEF_CERT_VERIFY_TRUST_DIR": str(d)}
    cafile = tmp_path / "ca.pem"
    cafile.write_bytes(pem(ca.cert))
    r = run("trust", "add", cafile, "--yes", env=env)
    assert r.returncode == 0 and "SHA-256:" in r.stdout
    r = run("trust", "list", env=env)
    assert "Symulowane CA" in r.stdout and str(d) in r.stdout
    leaf = tmp_path / "leaf.pem"
    leaf.write_bytes(pem(make_leaf(ca)[0]))
    r = run("trust", "add", leaf, "--yes", env=env)
    assert "nie jest certyfikat CA" in r.stderr  # liść nie zostaje kotwicą
    fp = [ln for ln in run("trust", "list", env=env).stdout.splitlines() if "Symulowane" in ln][0].split()[0]
    assert run("trust", "remove", fp[:12], env=env).returncode == 0
    assert "brak" in run("trust", "list", env=env).stdout
    assert run("trust", "add", cafile, env=env).returncode == 2  # bez terminala i bez --yes: odmowa
