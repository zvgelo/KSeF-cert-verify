"""Interfejs wiersza poleceń: `ksef-cert-verify`."""

from __future__ import annotations

import getpass
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from . import __version__
from .branding import PRODUCT_NAME, PRODUCT_TAGLINE
from .core.certificate_loader import LoaderError, PasswordRequired, WrongPassword, load_file
from .core.certificate_parser import parse_certificate
from .core.models import GROUPS, CertReport, CertType, CheckStatus, FileReport, Verdict
from .core.report import (
    PasswordProvider,
    VerifyOptions,
    build_json,
    dumps,
    exit_code,
    verify_file,
)
from .core.trust_store import TrustStore
from .operations import (
    CachedPassword,
    Kod2Setup,
    OnlineSetup,
    establish_online,
    run_kod2_test,
    verify_with_online,
)

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help=f"{PRODUCT_TAGLINE} 2.0 (Authentication / Offline). Domyślnie działa offline.",
    context_settings={"help_option_names": ["-h", "--help"]},
    # Nieoczekiwany wyjątek nie może wypisać zmiennych lokalnych (mogłyby zawierać hasło/token).
    pretty_exceptions_enable=False,
    pretty_exceptions_show_locals=False,
)

_STATUS_STYLE = {
    "PASS": "green",
    "FAIL": "red",
    "WARNING": "yellow",
    "UNKNOWN": "magenta",
    "NOT_CHECKED": "dim",
    "VALID": "bold green",
    "INVALID": "bold red",
    "INDETERMINATE": "bold magenta",
}
_CHECK_LABELS = {
    "parsing": "Certificate",
    "validity": "Date validity",
    "inputs": "Input completeness",
    "key_decrypt": "Private key",
    "key_match": "Key matches cert.",
    "signature_test": "Signature test",
    "crypto": "Cryptography",
    "trust": "Issuer trust",
    "classification": "Certificate type",
    "profile": "KSeF profile",
    "online": "KSeF API status",
}


def _stdin_is_terminal() -> bool:
    """Czy wejście to prawdziwy terminal (można pytać o hasło/potwierdzenie).

    Na Windows `isatty()` zwraca True także dla urządzenia NUL (`< NUL`, `stdin=DEVNULL`), a `getpass` czyta wtedy z konsoli
    zamiast ze `stdin`; dlatego dodatkowo sprawdzamy, czy uchwyt jest prawdziwym buforem konsoli."""
    try:
        if sys.stdin is None or not sys.stdin.isatty():
            return False
    except (OSError, ValueError):
        return False
    return _windows_console_attached() if sys.platform == "win32" else True


def _windows_console_attached() -> bool:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]  # tylko Windows
    kernel32.GetStdHandle.restype = wintypes.HANDLE
    mode = wintypes.DWORD()
    return bool(kernel32.GetConsoleMode(kernel32.GetStdHandle(-10), ctypes.byref(mode)))


def _version(value: bool) -> None:
    if value:
        typer.echo(f"ksef-cert-verify {__version__}")
        raise typer.Exit(0)


def _console(stderr: bool = False) -> Console:
    return Console(stderr=stderr, highlight=False, soft_wrap=True)


def _fmt(status: str) -> str:
    s = _STATUS_STYLE.get(status, "")
    shown = _s(status.replace("_", " "))
    return f"[{s}]{shown}[/{s}]" if s else shown


def _local(iso_utc: str) -> str:
    dt = datetime.strptime(iso_utc, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


_CTRL_RANGES = [
    (0x00, 0x08),
    (0x0B, 0x1F),
    (0x7F, 0x9F),
    (0x2028, 0x2029),
    (0x202A, 0x202E),
    (0x2066, 0x2069),
]
# Zakresy budowane z liczb (a nie z literalnych znaków bidi w źródle – zabezpieczenie przed „Trojan Source”).
_CTRL = re.compile("[" + "".join(f"{chr(a)}-{chr(b)}" for a, b in _CTRL_RANGES) + "]")


def _s(value: object) -> str:
    """Bezpieczny tekst do wypisania przez Rich: bez znaków sterujących (ANSI, newline, bidi) i bez znaczników.

    Dane z certyfikatu są niezaufane – nie mogą wstrzykiwać markupu ani sekwencji terminala.
    """
    return escape(_CTRL.sub("?", str(value)))


def _na(v: object) -> str:
    return _s(v) if v else "Brak danych"


def make_password_provider(use_stdin: bool = False, fd: int | None = None) -> PasswordProvider:
    """Źródło hasła: `--password-stdin` / `--password-fd` (automatyzacja) albo ukryty prompt na terminalu.

    Hasło nigdy nie pochodzi z argumentów polecenia i nie jest wypisywane. Bez terminala i bez jawnego
    źródła hasła zwracamy None (kontrola klucza kończy się wynikiem UNKNOWN, a nie zawieszeniem).
    """
    used = {"done": False}

    def provider(path: Path, retry: bool) -> str | None:
        if use_stdin or fd is not None:
            if used["done"] or retry:  # jedno hasło, brak pętli ponowień w automatyzacji
                return None
            used["done"] = True
            try:
                if fd is not None:
                    with os.fdopen(os.dup(fd), "r", encoding="utf-8") as fh:
                        line = fh.readline()
                else:
                    line = sys.stdin.readline()
            except (OSError, ValueError):
                return None
            return line.rstrip("\r\n") or None
        if not _stdin_is_terminal():
            return None
        try:
            note = " (błędne – spróbuj ponownie)" if retry else ""
            pw = getpass.getpass(f"Hasło dla {path.name}{note}: ")
        except (EOFError, KeyboardInterrupt):
            return None
        return pw or None

    return provider


def _build_options(
    trust_anchor: list[Path] | None,
    no_default_trust: bool,
    expected_type: str | None,
    allow_unencrypted: bool,
    at: str | None,
    err: Console,
) -> VerifyOptions:
    trust = TrustStore.from_paths(list(trust_anchor or []), include_default=not no_default_trust)
    for w in trust.warnings:
        err.print(f"[yellow]Uwaga:[/yellow] {_s(w)}")
    exp = None
    if expected_type is not None:
        try:
            exp = next(
                t
                for t in (CertType.AUTHENTICATION, CertType.OFFLINE)
                if t.value.lower() == expected_type.lower()
            )
        except StopIteration:
            raise typer.BadParameter(
                "Dozwolone wartości: Authentication, Offline", param_hint="--expected-type"
            ) from None
    now = None
    if at:
        try:
            now = datetime.fromisoformat(at.replace("Z", "+00:00"))
        except ValueError:
            raise typer.BadParameter(
                "Oczekiwano ISO-8601, np. 2026-10-28T12:00:00Z", param_hint="--at"
            ) from None
        if now.tzinfo is None:
            now = now.replace(tzinfo=UTC)
    return VerifyOptions(trust=trust, expected_type=exp, now=now, require_encrypted_key=not allow_unencrypted)


def _online_setup(
    online: bool,
    environment: str | None,
    confirm_prod: bool,
    context_nip: str | None,
    token_env: str,
    err: Console,
) -> OnlineSetup | None:
    """Konfiguracja online: domyślnie automatyczne uwierzytelnienie XAdES; istniejący JWT z `--token-env`."""
    if not online:
        if environment:
            err.print("[yellow]Uwaga:[/yellow] --environment ignorowane bez --online (tryb offline).")
        return None
    if not environment:
        raise typer.BadParameter(
            "--online wymaga jawnego --environment TEST|DEMO|PROD", param_hint="--environment"
        )
    env = environment.upper()
    if env not in ("TEST", "DEMO", "PROD"):
        raise typer.BadParameter("Dozwolone: TEST, DEMO, PROD", param_hint="--environment")
    allow_prod = False
    if env == "PROD":
        if confirm_prod:
            allow_prod = True
        elif _stdin_is_terminal():
            answer = input("Środowisko PRODUKCYJNE. Wpisz PROD, aby potwierdzić (inaczej przerwij): ")
            allow_prod = answer.strip() == "PROD"
        if not allow_prod:
            err.print(
                "[red]PROD wymaga świadomego potwierdzenia[/red] (--confirm-prod lub wpisanie PROD w terminalu)."
            )
            raise typer.Exit(2)
    jwt = os.environ.get(token_env)
    return OnlineSetup(
        environment=env,
        mode="jwt" if jwt else "auto",
        jwt=jwt or None,
        allow_prod=allow_prod,
        context_value=context_nip,
    )


def _render_cert(console: Console, fr: FileReport, c: CertReport, verbose: bool) -> None:
    i = c.info
    t = Table.grid(padding=(0, 2))
    t.add_column(style="bold", no_wrap=True)
    t.add_column(overflow="fold")
    sub = i.subject_info
    t.add_row("File:", _s(fr.path))
    t.add_row("Certificate type:", c.cert_type.value)
    t.add_row("Subject:", _s(i.subject))
    t.add_row("Issuer:", _s(i.issuer))
    t.add_row("Serial number:", _s(i.serial_hex))
    t.add_row("Valid from:", _local(i.not_before))
    t.add_row("Valid until:", _local(i.not_after))
    t.add_row("Days remaining:", str(c.days_remaining))
    t.add_row("Algorithm:", _s(i.key_algorithm))
    t.add_row("Fingerprint:", _s(i.fingerprint_sha256))
    name = " ".join([*sub.given_names, sub.surname or ""]).strip() or sub.organization or sub.common_name
    t.add_row("Podmiot:", _na(name))
    t.add_row("NIP / PESEL:", f"{_na(sub.nip)} / {_na(sub.pesel)}")
    console.print(t)
    console.print()

    def rows(keys: list[str]) -> None:
        for key in keys:
            chk = c.checks[key]
            console.print(
                f"{_CHECK_LABELS[key] + ':':<22}{_fmt(chk.status.value)}  [dim]{_s(chk.summary)}[/dim]"
            )
            if verbose or chk.status in (CheckStatus.FAIL, CheckStatus.WARNING, CheckStatus.UNKNOWN):
                for f in chk.findings:
                    console.print(f"    • {_fmt(f.status.value)} {_s(f.message)}")

    inp = fr.inputs or {}
    pw_txt = {
        "PROVIDED": "PROVIDED",
        "NOT_PROVIDED": "NOT PROVIDED",
        "NOT_REQUIRED": "NOT REQUIRED (key not encrypted)",
    }.get(inp.get("password") or "", "NOT PROVIDED")
    console.print(f"[bold]Private key:[/bold]       {_s(inp.get('private_key') or '(none)')}")
    console.print(f"[bold]Password:[/bold]          {pw_txt}")
    console.print()
    console.print("[bold]LOCAL[/bold] – zestaw certyfikat + klucz + hasło")
    rows(GROUPS["local"])
    console.print()
    console.print("[bold]TRUST[/bold] – zaufanie do wystawcy i profil KSeF")
    rows(GROUPS["trust"])
    console.print()
    console.print("[bold]ONLINE[/bold] – status w KSeF (nie wpływa na wyniki lokalne)")
    rows(GROUPS["online"])
    auth = c.operations.get("authentication")
    if auth:
        console.print(f"{'Authentication:':<22}{_s(auth['code'])}  [dim]{_s(auth['message'])}[/dim]")
        console.print(f"{'Authorization:':<22}{_s(auth['authorization'])}")
        for st in auth["steps"]:
            console.print(f"    • {_s(st['name'])}: {_s(st['status'])} – {_s(st['message'])}")
    kod = c.operations.get("kod2")
    if kod:
        console.print(f"{'KOD II test:':<22}{_fmt(kod['status'])}  [dim]{_s(kod['message'])}[/dim]")
    if verbose:
        console.print()
        console.print(f"[bold]Key Usage:[/bold] {_s(', '.join(i.key_usage) or 'Brak danych')}")
        console.print(f"[bold]Extended Key Usage:[/bold] {_s(', '.join(i.extended_key_usage) or 'Brak')}")
        console.print(f"[bold]Basic Constraints:[/bold] {_s(i.basic_constraints or 'Brak')}")
        console.print(f"[bold]SKI:[/bold] {_s(i.ski or 'Brak')}   [bold]AKI:[/bold] {_s(i.aki or 'Brak')}")
        console.print(f"[bold]Podpis:[/bold] {_s(i.signature_algorithm)}")
        console.print(
            "[bold]Rozszerzenia:[/bold] "
            + ", ".join(_s(f"{e.name}{' (critical)' if e.critical else ''}") for e in i.extensions)
        )
    console.print()
    local = c.local_result()
    trust = c.trust_result()
    local_txt = {
        "VALID": "POPRAWNY (VALID)",
        "INVALID": "NIEPOPRAWNY (INVALID)",
        "INDETERMINATE": "NIEUSTALONY (INDETERMINATE)",
    }[local.value]
    trust_txt = {"CONFIRMED": "POTWIERDZONE", "UNCONFIRMED": "NIEPOTWIERDZONE", "FAILED": "ODRZUCONE"}[trust]
    console.print(f"[bold]Zestaw certyfikatu i klucza:[/bold] {_fmt(local.value)}  {local_txt}")
    console.print(
        f"[bold]Zaufanie do certyfikatu:[/bold]     {_fmt({'CONFIRMED': 'PASS', 'FAILED': 'FAIL', 'UNCONFIRMED': 'UNKNOWN'}[trust])}  {trust_txt}"
    )
    console.print(f"[bold]FULL VERIFICATION:[/bold] {_fmt(c.verdict.value)}")
    console.print(f"[bold]ONLINE STATUS:[/bold]   {_fmt(c.online_status)}")
    if c.online_status == "NOT_CHECKED":
        console.print(
            "[dim]Wynik lokalny nie oznacza aktywnego statusu certyfikatu w KSeF ani zgodności potwierdzonej przez MF.[/dim]"
        )
    if local is Verdict.VALID and trust == "UNCONFIRMED":
        console.print(
            "[dim]Zestaw cert+klucz jest poprawny, ale zaufanie do wystawcy nie zostało potwierdzone – "
            "pełna walidacja nie jest VALID (podaj zaufane CA: --trust-anchor).[/dim]"
        )


def _render(console: Console, reports: list[FileReport], verbose: bool, trust_n: int) -> None:
    console.print(f"[bold]{PRODUCT_NAME}[/bold] – KSeF Certificate Verification")
    console.rule()
    for fr in reports:
        if fr.error:
            console.print(f"[bold]File:[/bold] {_s(fr.path)}")
            console.print(f"[red]{_s(fr.error.code)}[/red]: {_s(fr.error.message)}")
            console.print(f"[bold]RESULT:[/bold] {_fmt('INVALID') if fr.verdict else '[red]ERROR[/red]'}")
            console.rule()
            continue
        for n in fr.notes:
            console.print(f"[yellow]Uwaga:[/yellow] {_s(n)}")
        for c in fr.certificates:
            _render_cert(console, fr, c, verbose)
            console.rule()
    if trust_n == 0:
        console.print(
            "[magenta]Nie skonfigurowano zaufanych CA[/magenta] (--trust-anchor / katalog zaufania). MF nie publikuje "
            "CA certyfikatów KSeF, więc zaufanie do wystawcy nie mogło zostać sprawdzone – wynik co najwyżej INDETERMINATE."
        )


@app.callback()
def _main(
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Pokaż wersję.")
    ] = False,
) -> None:
    pass


@app.command()
def verify(
    cert: Annotated[
        Path,
        typer.Option(
            "--cert", "-c", help="Certyfikat X.509 (.crt .cer .pem .der; także .p12/.pfx z kluczem)."
        ),
    ],
    key: Annotated[
        Path | None,
        typer.Option(
            "--key",
            "-k",
            help="Zaszyfrowany klucz prywatny (.key/.pem). Wymagany, chyba że --cert to PKCS#12.",
        ),
    ] = None,
    password_stdin: Annotated[
        bool,
        typer.Option("--password-stdin", help="Przeczytaj hasło z pierwszej linii stdin (automatyzacja)."),
    ] = False,
    password_fd: Annotated[
        int | None,
        typer.Option("--password-fd", help="Przeczytaj hasło z deskryptora pliku (automatyzacja)."),
    ] = None,
    json_out: Annotated[
        bool, typer.Option("--json", help="Wynik jako stabilny JSON (schema_version).")
    ] = False,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Pokaż wszystkie ustalenia i rozszerzenia.")
    ] = False,
    expected_type: Annotated[
        str | None, typer.Option("--expected-type", help="Authentication albo Offline.")
    ] = None,
    trust_anchor: Annotated[
        list[Path] | None,
        typer.Option("--trust-anchor", "-t", help="Plik lub katalog z zaufanymi CA (można powtarzać)."),
    ] = None,
    no_default_trust: Annotated[
        bool, typer.Option("--no-default-trust", help="Nie ładuj domyślnego katalogu zaufania.")
    ] = False,
    online: Annotated[
        bool, typer.Option("--online", help="Sprawdź status w API KSeF (tylko odczyt; wymaga tokenu).")
    ] = False,
    environment: Annotated[
        str | None, typer.Option("--environment", "-e", help="TEST | DEMO | PROD (wymagane z --online).")
    ] = None,
    token_env: Annotated[
        str, typer.Option("--token-env", help="Zmienna środowiskowa z tokenem dostępu.")
    ] = "KSEF_ACCESS_TOKEN",
    confirm_prod: Annotated[
        bool, typer.Option("--confirm-prod", help="Świadome potwierdzenie użycia środowiska PRODUKCYJNEGO.")
    ] = False,
    context_nip: Annotated[
        str | None,
        typer.Option("--context-nip", help="NIP kontekstu uwierzytelnienia (domyślnie NIP z certyfikatu)."),
    ] = None,
    allow_unencrypted_key: Annotated[
        bool,
        typer.Option("--allow-unencrypted-key", help="Dopuść klucz niezaszyfrowany (tylko ostrzeżenie)."),
    ] = False,
    at: Annotated[
        str | None, typer.Option("--at", help="Oceń ważność na podany moment (ISO-8601, UTC).")
    ] = None,
) -> None:
    """Pełna weryfikacja: certyfikat + klucz prywatny + hasło. VALID wymaga wszystkich trzech.

    Hasło pobierane jest z ukrytego promptu (albo --password-stdin / --password-fd) – nigdy z argumentu.
    Kody wyjścia: 0 poprawny, 1 niepoprawny, 2 błąd, 3 niejednoznaczny.
    """
    err = _console(stderr=True)
    if password_stdin and password_fd is not None:
        raise typer.BadParameter(
            "Użyj albo --password-stdin, albo --password-fd.", param_hint="--password-stdin"
        )
    if key is None and cert.suffix.lower() not in (".p12", ".pfx"):
        err.print("[red]Brak klucza prywatnego.[/red] Pełna weryfikacja wymaga --key (oraz hasła do klucza).")
        raise typer.Exit(2)
    opts = _build_options(trust_anchor, no_default_trust, expected_type, allow_unencrypted_key, at, err)
    setup = _online_setup(online, environment, confirm_prod, context_nip, token_env, err)
    provider = make_password_provider(password_stdin, password_fd)
    report, _session = verify_with_online(cert, key, opts, provider, setup)
    reports = [report]
    code = exit_code(reports)
    if json_out:
        sys.stdout.write(dumps(build_json(reports, opts, __version__)) + "\n")
    else:
        _render(_console(), reports, verbose, len(opts.trust))
    for fr in reports:
        if fr.error and fr.error.kind == "runtime":
            err.print(f"[red]Błąd:[/red] {_s(fr.path)}: {_s(fr.error.message)}")
    raise typer.Exit(code)


@app.command()
def inspect(
    path: Annotated[Path, typer.Argument(help="Plik z certyfikatem.")],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Wyświetla publiczne informacje z samego certyfikatu. To NIE jest weryfikacja (brak werdyktu)."""
    err = _console(stderr=True)
    password: str | None = None
    provider = make_password_provider()
    while True:
        try:
            loaded = load_file(path, password)
            break
        except (PasswordRequired, WrongPassword) as exc:
            password = provider(path, isinstance(exc, WrongPassword))
            if password is None:
                err.print(f"[red]Błąd:[/red] {_s(exc.message)}")
                raise typer.Exit(2) from None
        except LoaderError as exc:
            err.print(f"[red]Błąd:[/red] {_s(exc.message)}")
            raise typer.Exit(2 if exc.kind == "runtime" else 1) from None
    infos = [parse_certificate(c)[0] for c in loaded.certificates]
    if json_out:
        import json

        sys.stdout.write(
            json.dumps(
                {
                    "schema_version": "2",
                    "verification": False,
                    "format": loaded.file_format,
                    "certificates": [i.to_dict() for i in infos],
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n"
        )
        raise typer.Exit(0)
    console = _console()
    console.print(
        "[yellow]Podgląd informacji z certyfikatu – to nie jest weryfikacja[/yellow] "
        "(brak sprawdzenia klucza prywatnego, zaufania ani statusu). Użyj: verify --cert … --key …"
    )
    for n, i in enumerate(infos):
        console.print(f"[bold]Certyfikat #{n + 1}[/bold] ({_s(loaded.file_format)})")
        t = Table.grid(padding=(0, 2))
        t.add_column(style="bold", no_wrap=True)
        t.add_column(overflow="fold")
        for k, v in [
            ("Subject", i.subject),
            ("Issuer", i.issuer),
            ("Serial", i.serial_hex),
            ("Valid from", _local(i.not_before)),
            ("Valid until", _local(i.not_after)),
            ("SHA-256", i.fingerprint_sha256),
            ("Podpis", i.signature_algorithm),
            ("Klucz", i.key_algorithm),
            ("Key Usage", ", ".join(i.key_usage) or "Brak"),
            ("EKU", ", ".join(i.extended_key_usage) or "Brak"),
            ("Basic Constraints", i.basic_constraints or "Brak"),
            ("SKI", i.ski or "Brak"),
            ("AKI", i.aki or "Brak"),
            ("NIP", _na(i.subject_info.nip)),
            ("PESEL", _na(i.subject_info.pesel)),
        ]:
            t.add_row(k + ":", _s(v))
        console.print(t)
        console.print()
    raise typer.Exit(0)


def _pair_options(
    cert: Path,
    key: Path,
    password_stdin: bool,
    password_fd: int | None,
    allow_unencrypted_key: bool,
    at: str | None,
    err: Console,
) -> tuple[VerifyOptions, PasswordProvider]:
    if password_stdin and password_fd is not None:
        raise typer.BadParameter(
            "Użyj albo --password-stdin, albo --password-fd.", param_hint="--password-stdin"
        )
    opts = _build_options(None, True, None, allow_unencrypted_key, at, err)
    return opts, make_password_provider(password_stdin, password_fd)


def _emit(console: Console, as_json: bool, doc: dict, lines: list[str]) -> None:
    if as_json:
        sys.stdout.write(dumps(doc) + "\n")
    else:
        for line in lines:
            console.print(line)


@app.command("test-signature")
def test_signature(
    cert: Annotated[Path, typer.Option("--cert", "-c", help="Certyfikat X.509.")],
    key: Annotated[Path, typer.Option("--key", "-k", help="Zaszyfrowany klucz prywatny.")],
    password_stdin: Annotated[bool, typer.Option("--password-stdin")] = False,
    password_fd: Annotated[int | None, typer.Option("--password-fd")] = None,
    allow_unencrypted_key: Annotated[bool, typer.Option("--allow-unencrypted-key")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Aktywny test podpisu: podpisuje losowe dane kluczem prywatnym i weryfikuje kluczem z certyfikatu.

    To NIE jest podpis XAdES ani podpis KODU II. Kody: SIGNATURE_VALID, SIGNATURE_INVALID, KEY_DECRYPTION_FAILED,
    KEY_CERT_MISMATCH, UNSUPPORTED_ALGORITHM. Exit: 0 poprawny, 1 niepoprawny, 2 błąd, 3 nieustalony.
    """
    err = _console(stderr=True)
    opts, provider = _pair_options(cert, key, password_stdin, password_fd, allow_unencrypted_key, None, err)
    report = verify_file(cert, opts, provider, key_path=key)
    if report.error or not report.certificates:
        err.print(f"[red]Błąd:[/red] {_s(report.error.message if report.error else 'brak certyfikatu')}")
        if json_out:
            sys.stdout.write(dumps(report.to_dict()) + "\n")
        raise typer.Exit(2 if report.error and report.error.kind == "runtime" else 1)
    c = report.certificates[0]
    sig, dec, mat = c.checks["signature_test"], c.checks["key_decrypt"], c.checks["key_match"]
    code = sig.code or "NOT_CHECKED"
    doc = {
        "schema_version": "2",
        "command": "test-signature",
        "result": code,
        "private_key": {"status": dec.status.value, "code": dec.code, "summary": dec.summary},
        "key_pair": {"status": mat.status.value, "code": mat.code},
        "signature_test": {"status": sig.status.value, "code": code, "summary": sig.summary},
    }
    lines = [
        "[bold]KSeF Signature Test[/bold] (losowe dane testowe – nie XAdES, nie KOD II)",
        f"{'Private key:':<18}{_fmt(dec.status.value)}  [dim]{_s(dec.summary)}[/dim]",
        f"{'Key pair:':<18}{_fmt(mat.status.value)}  [dim]{_s(mat.summary)}[/dim]",
        f"{'Signature test:':<18}{_fmt(sig.status.value)}  [bold]{_s(code)}[/bold] [dim]{_s(sig.summary)}[/dim]",
    ]
    _emit(_console(), json_out, doc, lines)
    raise typer.Exit(0 if sig.status is CheckStatus.PASS else 1 if sig.status is CheckStatus.FAIL else 3)


@app.command("test-auth")
def test_auth(
    cert: Annotated[Path, typer.Option("--cert", "-c")],
    key: Annotated[Path, typer.Option("--key", "-k")],
    environment: Annotated[
        str, typer.Option("--environment", "-e", help="TEST (domyślnie) | DEMO | PROD.")
    ] = "TEST",
    confirm_prod: Annotated[
        bool, typer.Option("--confirm-prod", help="Świadome potwierdzenie PROD.")
    ] = False,
    context_nip: Annotated[str | None, typer.Option("--context-nip")] = None,
    subject_identifier: Annotated[
        str,
        typer.Option("--subject-identifier", help="certificateSubject (domyślnie) | certificateFingerprint."),
    ] = "certificateSubject",
    verify_chain: Annotated[
        bool | None,
        typer.Option("--verify-chain/--no-verify-chain", help="Wymuś weryfikację łańcucha po stronie KSeF."),
    ] = None,
    password_stdin: Annotated[bool, typer.Option("--password-stdin")] = False,
    password_fd: Annotated[int | None, typer.Option("--password-fd")] = None,
    allow_unencrypted_key: Annotated[bool, typer.Option("--allow-unencrypted-key")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Test uwierzytelnienia w KSeF (XAdES) – tylko certyfikat Authentication.

    Rozdziela: kryptografię (lokalnie), uwierzytelnienie (KSeF zaakceptował certyfikat) i autoryzację (uprawnienia).
    Brak uprawnień (415) NIE jest dowodem nieprawidłowej pary kluczy. Exit: 0 sukces, 1 odrzucenie, 2 błąd/PROD
    niepotwierdzony, 3 nieustalony (brak uprawnień, sieć, timeout, kontekst).
    """
    err = _console(stderr=True)
    opts, provider = _pair_options(cert, key, password_stdin, password_fd, allow_unencrypted_key, None, err)
    setup = _online_setup(True, environment, confirm_prod, context_nip, "KSEF_ACCESS_TOKEN_UNUSED", err)
    if setup is None:
        raise typer.Exit(2)
    setup.mode = "auto"
    if subject_identifier not in ("certificateSubject", "certificateFingerprint"):
        raise typer.BadParameter(
            "certificateSubject albo certificateFingerprint", param_hint="--subject-identifier"
        )
    setup.subject_type = subject_identifier
    setup.verify_certificate_chain = verify_chain
    cached = CachedPassword(provider)
    try:
        session = establish_online(cert, key, cached, setup, opts.require_encrypted_key)
    finally:
        cached.clear()
    if session.client is not None:
        session.client.close()
    a = session.auth
    doc = {"schema_version": "2", "command": "test-auth", "result": a.code, "authentication": a.to_dict()}
    lines = [
        f"[bold]KSeF Authentication Test[/bold] – {_s(a.environment or setup.environment)}",
        f"Kontekst: {_s(a.context or '-')}",
    ]
    for st in a.steps:
        lines.append(f"  • {_s(st.name)}: {_fmt('PASS' if st.status == 'OK' else 'FAIL')} {_s(st.message)}")
    lines += [
        f"{'Authentication:':<18}{_s(a.authentication)}",
        f"{'Authorization:':<18}{_s(a.authorization)}",
        f"{'Result:':<18}[bold]{_s(a.code)}[/bold] {_s(a.message)}",
        "[dim]accessToken (JWT) nie jest zapisywany ani wypisywany.[/dim]",
    ]
    _emit(_console(), json_out, doc, lines)
    if a.code == "AUTH_SUCCESS":
        raise typer.Exit(0)
    if a.code in (
        "AUTH_NOT_APPLICABLE",
        "AUTH_PROD_NOT_CONFIRMED",
        "AUTH_BAD_ENVIRONMENT",
        "AUTH_KEY_REQUIRED",
        "AUTH_CERT_UNREADABLE",
    ):
        raise typer.Exit(2)
    if a.authentication == "REJECTED" or a.code in (
        "AUTH_REQUEST_INVALID",
        "AUTH_REQUEST_REJECTED",
        "AUTH_SIGNING_FAILED",
    ):
        raise typer.Exit(1)
    raise typer.Exit(3)


@app.command("test-kod2")
def test_kod2(
    cert: Annotated[Path, typer.Option("--cert", "-c")],
    key: Annotated[Path, typer.Option("--key", "-k")],
    environment: Annotated[
        str, typer.Option("--environment", "-e", help="TEST (domyślnie) | DEMO | PROD (tylko host linku).")
    ] = "TEST",
    context_nip: Annotated[str | None, typer.Option("--context-nip")] = None,
    seller_nip: Annotated[str | None, typer.Option("--seller-nip")] = None,
    password_stdin: Annotated[bool, typer.Option("--password-stdin")] = False,
    password_fd: Annotated[int | None, typer.Option("--password-fd")] = None,
    allow_unencrypted_key: Annotated[bool, typer.Option("--allow-unencrypted-key")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Test podpisu KODU II (certyfikat Offline) na danych SYNTETYCZNYCH, wg `kody-qr.md`.

    Nic nie jest wysyłane do KSeF; link jest tylko budowany i lokalnie weryfikowany. Exit: 0 poprawny, 1 niepoprawny,
    2 błąd/niezastosowalny (np. certyfikat Authentication), 3 nieustalony (np. brak hasła).
    """
    err = _console(stderr=True)
    opts, provider = _pair_options(cert, key, password_stdin, password_fd, allow_unencrypted_key, None, err)
    env = environment.upper()
    if env not in ("TEST", "DEMO", "PROD"):
        raise typer.BadParameter("TEST, DEMO albo PROD", param_hint="--environment")
    report = run_kod2_test(cert, key, opts, provider, Kod2Setup(env, "Nip", context_nip, seller_nip))
    if report.error or not report.certificates:
        err.print(f"[red]Błąd:[/red] {_s(report.error.message if report.error else 'brak certyfikatu')}")
        raise typer.Exit(2 if report.error and report.error.kind == "runtime" else 1)
    c = report.certificates[0]
    op = c.operations.get(
        "kod2", {"code": "KOD2_NOT_PERFORMED", "status": "UNKNOWN", "message": "Test nie został wykonany."}
    )
    doc = {
        "schema_version": "2",
        "command": "test-kod2",
        "certificate_type": c.cert_type.value,
        "result": op["code"],
        "kod2": op,
        "key_pair": c.checks["key_match"].status.value,
        "signature_test": c.checks["signature_test"].code,
    }
    lines = [
        "[bold]KSeF KOD II Signature Test[/bold] (dane syntetyczne – nie faktura, nic nie jest wysyłane)",
        f"{'Certificate type:':<20}{c.cert_type.value}",
        f"{'Key pair:':<20}{_fmt(c.checks['key_match'].status.value)}",
        f"{'KOD II:':<20}{_fmt(op['status'] if op['status'] in ('PASS', 'FAIL') else 'UNKNOWN')}  [bold]{_s(op['code'])}[/bold] {_s(op['message'])}",
    ]
    if op.get("url"):
        lines.append(f"{'Test link:':<20}[dim]{_s(op['url'])}[/dim]")
        lines.append("[dim]Link syntetyczny – NIE używać i NIE wysyłać do KSeF.[/dim]")
    _emit(_console(), json_out, doc, lines)
    if op["status"] == "PASS":
        raise typer.Exit(0)
    if op["code"] == "KOD2_NOT_APPLICABLE":
        raise typer.Exit(2)
    raise typer.Exit(1 if op["status"] == "FAIL" else 3)


trust_app = typer.Typer(
    help="Zarządzanie zaufanymi CA (MF nie publikuje CA certyfikatów KSeF – dodajesz je sam).",
    pretty_exceptions_enable=False,
    pretty_exceptions_show_locals=False,
)
app.add_typer(trust_app, name="trust")


@trust_app.command("list")
def trust_list() -> None:
    """Pokazuje zaufane CA z domyślnego katalogu zaufania wraz z odciskami SHA-256."""
    from .core.certificate_parser import fingerprint, not_after
    from .core.trust_store import default_trust_dir

    d = default_trust_dir()
    store = TrustStore.from_paths([], include_default=True)
    console = _console()
    console.print(f"Katalog zaufania: {_s(d)}")
    for a, src in zip(store.anchors, store.sources, strict=False):
        console.print(
            f"  {_s(fingerprint(a))}  {_s(a.subject.rfc4514_string())}  ważny do {not_after(a):%Y-%m-%d}  [dim]{_s(src)}[/dim]"
        )
    if not store.anchors:
        console.print("  (brak – dodaj CA: ksef-cert-verify trust add PLIK)")


@trust_app.command("add")
def trust_add(
    path: Annotated[Path, typer.Argument(help="Plik z certyfikatem CA (.pem .crt .cer .der).")],
    yes: Annotated[
        bool, typer.Option("--yes", help="Potwierdź bez pytania (po sprawdzeniu odcisku innym kanałem).")
    ] = False,
) -> None:
    """Dodaje CA do katalogu zaufania po ręcznym potwierdzeniu odcisku SHA-256."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    from .core.certificate_parser import fingerprint
    from .core.trust_store import default_trust_dir

    err = _console(stderr=True)
    try:
        loaded = load_file(path)
    except LoaderError as exc:
        err.print(f"[red]Błąd:[/red] {_s(exc.message)}")
        raise typer.Exit(2) from None
    console = _console()
    d = default_trust_dir()
    for c in loaded.certificates:
        try:
            is_ca = c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        except x509.ExtensionNotFound:
            is_ca = False
        console.print(
            f"Subject: {_s(c.subject.rfc4514_string())}\nSHA-256: [bold]{_s(fingerprint(c))}[/bold]  CA={is_ca}"
        )
        if not is_ca:
            err.print("[red]To nie jest certyfikat CA (BasicConstraints CA=TRUE) – pominięto.[/red]")
            continue
        if not yes:
            if not _stdin_is_terminal():
                err.print("[red]Brak terminala – użyj --yes po zweryfikowaniu odcisku innym kanałem.[/red]")
                raise typer.Exit(2)
            if input(
                "Zaufać temu CA? Odcisk musi zgadzać się z danymi z zaufanego źródła [t/N]: "
            ).strip().lower() not in ("t", "y"):
                continue
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{fingerprint(c)[:16].lower()}.pem").write_bytes(c.public_bytes(Encoding.PEM))
        console.print(f"[green]Dodano[/green] do {_s(d)}")


@trust_app.command("remove")
def trust_remove(
    fingerprint_prefix: Annotated[str, typer.Argument(help="Początek odcisku SHA-256 (min. 8 znaków).")],
) -> None:
    """Usuwa CA z katalogu zaufania."""
    from .core.certificate_parser import fingerprint
    from .core.trust_store import default_trust_dir

    if len(fingerprint_prefix) < 8:
        raise typer.BadParameter("Podaj co najmniej 8 znaków odcisku.")
    d = default_trust_dir()
    removed = 0
    if d.is_dir():
        for f in sorted(d.iterdir()):
            try:
                certs = load_file(f).certificates
            except LoaderError:
                continue
            if any(fingerprint(c).startswith(fingerprint_prefix.upper()) for c in certs):
                f.unlink()
                removed += 1
    _console().print(f"Usunięto: {removed}")
    raise typer.Exit(0 if removed else 1)


@app.command()
def gui(
    selftest: Annotated[
        bool, typer.Option("--selftest", help="Autotest GUI na danych syntetycznych (kod wyjścia 0 = OK).")
    ] = False,
) -> None:
    """Uruchamia interfejs graficzny."""
    try:
        from .gui.main import main as gui_main
    except ImportError:
        if getattr(sys, "frozen", False):
            msg = "[red]Ta wersja CLI nie zawiera GUI.[/red] Użyj pliku *-portable.exe albo instalatora KSeF CertVerify."
        else:
            msg = "[red]Brak PySide6.[/red] Zainstaluj: pip install 'ksef-cert-verify[gui]'"
        _console(stderr=True).print(msg)
        raise typer.Exit(2) from None
    raise typer.Exit(gui_main(["--selftest"] if selftest else []))


def main() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass
    try:
        app()
    except (
        Exception
    ) as exc:  # nigdy nie pokazuj śladu stosu ze zmiennymi (sekrety); szczegóły tylko świadomie
        if os.environ.get("KSEF_CERT_VERIFY_DEBUG") == "1":
            raise
        sys.stderr.write(
            f"Błąd wewnętrzny ({type(exc).__name__}). Ustaw KSEF_CERT_VERIFY_DEBUG=1, aby zobaczyć ślad stosu.\n"
        )
        sys.exit(2)
