"""Zaufane punkty (trust anchors) i kryptograficzna walidacja łańcucha.

Zasady:
* kotwicą jest wyłącznie certyfikat jawnie skonfigurowany przez użytkownika,
  dopasowywany po **identycznym DER** – nigdy po tekście Subject/Issuer;
* certyfikaty z analizowanego pliku są tylko kandydatami na pośrednie CA;
* każde ogniwo: podpis (`verify_directly_issued_by`), CA=TRUE, keyCertSign,
  pathLen, daty ważności.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.serialization import Encoding

from .certificate_loader import LoaderError, load_file
from .certificate_parser import (
    KNOWN_EXTENSION_OIDS,
    fingerprint,
    key_usage_flags,
    not_after,
    not_before,
)
from .models import CheckStatus, Finding

MAX_CHAIN_DEPTH = 8
TRUST_DIR_ENV = "KSEF_CERT_VERIFY_TRUST_DIR"
_TRUST_EXTS = {".pem", ".crt", ".cer", ".der"}
_DER = Encoding.DER


def default_trust_dir() -> Path:
    env = os.environ.get(TRUST_DIR_ENV)
    if env:
        return Path(env)
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "ksef-cert-verify" / "trust"


def _unsafe_trust_dir(d: Path) -> str | None:
    """Na POSIX katalog zaufania musi należeć do bieżącego użytkownika i nie być zapisywalny przez grupę/innych."""
    if sys.platform == "win32":
        return None  # na Windows kontrola ACL wykracza poza zakres (uprawnienia profilu użytkownika)
    try:
        st = d.stat()
    except OSError as exc:
        return f"nie można odczytać atrybutów ({exc.strerror})"
    if st.st_uid != os.getuid():
        return "katalog nie należy do bieżącego użytkownika"
    if st.st_mode & 0o022:
        return "katalog jest zapisywalny przez grupę lub innych użytkowników (chmod go-w)"
    return None


@dataclass
class TrustStore:
    anchors: list[x509.Certificate] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._ders = {a.public_bytes(_DER) for a in self.anchors}

    def add(self, cert: x509.Certificate, source: str) -> None:
        der = cert.public_bytes(_DER)
        if der not in self._ders:
            self._ders.add(der)
            self.anchors.append(cert)
            self.sources.append(source)

    def is_anchor(self, cert: x509.Certificate) -> bool:
        return cert.public_bytes(_DER) in self._ders

    def __len__(self) -> int:
        return len(self.anchors)

    def load_path(self, path: Path) -> None:
        """Dodaje plik albo (niekursywnie) katalog z certyfikatami jako kotwice."""
        files = (
            sorted(p for p in path.iterdir() if p.is_file() and p.suffix.lower() in _TRUST_EXTS)
            if path.is_dir()
            else [path]
        )
        for f in files:
            try:
                loaded = load_file(f)
            except LoaderError as exc:
                self.warnings.append(f"Pominięto {f.name}: {exc.message}")
                continue
            for c in loaded.certificates:
                self.add(c, str(f))

    @classmethod
    def from_paths(cls, paths: list[Path], include_default: bool = True) -> TrustStore:
        store = cls()
        if include_default:
            d = default_trust_dir()
            if d.is_dir():
                problem = _unsafe_trust_dir(d)
                if problem:
                    # Katalog zaufania z możliwością zapisu przez innych = możliwość podstawienia kotwicy zaufania.
                    store.warnings.append(f"Pominięto domyślny katalog zaufania {d}: {problem}")
                else:
                    store.load_path(d)
        for p in paths:
            if not p.exists():
                store.warnings.append(f"Ścieżka zaufania nie istnieje: {p}")
                continue
            store.load_path(p)
        return store


@dataclass
class ChainResult:
    crypto: CheckStatus
    trust: CheckStatus
    findings: list[Finding]
    path: list[str]  # odciski SHA-256 od liścia do ostatniego znalezionego ogniwa
    issuer_kind: str = "OTHER"  # SELF_SIGNED | KSEF | OTHER (wg pola Issuer – to deklaracja, nie dowód)


ISSUER_SELF_SIGNED, ISSUER_KSEF, ISSUER_OTHER = "SELF_SIGNED", "KSEF", "OTHER"


def issuer_kind(cert: x509.Certificate) -> str:
    """Rodzaj wystawcy wg pola Issuer. KSEF oznacza wyłącznie *deklarację* MF/KSeF w nazwie – bez certyfikatu
    wystawcy nie jest to dowód pochodzenia (podpis wystawcy weryfikuje `validate_chain`)."""
    if cert.subject == cert.issuer:
        return ISSUER_SELF_SIGNED
    parts = [a.value for a in cert.issuer if isinstance(a.value, str)]
    text = " ".join(parts).casefold()
    if "ksef" in text or "ministerstwo finans" in text:
        return ISSUER_KSEF
    return ISSUER_OTHER


def _issuer_label(cert: x509.Certificate) -> str:
    cn = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return str(cn[0].value) if cn else cert.issuer.rfc4514_string()


def _is_self_issued(cert: x509.Certificate) -> bool:
    return cert.subject == cert.issuer


def _verifies(cert: x509.Certificate, issuer: x509.Certificate) -> str:
    """'ok' | 'bad_sig' | 'unsupported'. Wymaga zgodności nazw (sprawdza to biblioteka)."""
    try:
        cert.verify_directly_issued_by(issuer)
        return "ok"
    except (InvalidSignature, ValueError):
        return "bad_sig"
    except (UnsupportedAlgorithm, TypeError):
        return "unsupported"


def _ca_problems(ca: x509.Certificate, ca_below: int, now: datetime) -> list[str]:
    problems: list[str] = []
    try:
        bc = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return ["brak BasicConstraints (CA nie jest oznaczone jako CA)"]
    if not bc.ca:
        problems.append("BasicConstraints: CA=FALSE")
    elif bc.path_length is not None and ca_below > bc.path_length:
        problems.append(f"przekroczone pathLen={bc.path_length}")
    ku = key_usage_flags(ca)
    if ku is not None and "Certificate Sign" not in ku:
        problems.append("Key Usage bez keyCertSign")
    if not (not_before(ca) <= now <= not_after(ca)):
        problems.append("certyfikat CA poza okresem ważności")
    for ext in ca.extensions:
        if ext.critical and ext.oid not in KNOWN_EXTENSION_OIDS:
            problems.append(f"nieznane krytyczne rozszerzenie {ext.oid.dotted_string}")
    return problems


def validate_chain(
    leaf: x509.Certificate,
    candidates: list[x509.Certificate],
    store: TrustStore,
    now: datetime,
) -> ChainResult:
    findings: list[Finding] = []
    path = [fingerprint(leaf)]
    current = leaf
    seen = {fingerprint(leaf)}
    sig_failed_for_name_match = False
    unsupported = False
    ca_below = 0  # liczba pośrednich CA pod aktualnym wystawcą
    trusted = False
    top_untrusted_root = False
    problems: list[str] = []
    kind = issuer_kind(leaf)

    if store.is_anchor(leaf):
        return ChainResult(
            CheckStatus.PASS,
            CheckStatus.PASS,
            [
                Finding(
                    "TRUST_PINNED",
                    CheckStatus.PASS,
                    "Certyfikat jest bezpośrednio skonfigurowanym punktem zaufania.",
                )
            ],
            path,
            kind,
        )

    for _ in range(MAX_CHAIN_DEPTH):
        issuer = None
        for pool in (store.anchors, candidates):
            for c in pool:
                if c.subject != current.issuer:
                    continue
                res = _verifies(current, c)
                if res == "ok":
                    issuer = c
                    break
                if res == "unsupported":
                    unsupported = True
                else:
                    sig_failed_for_name_match = True
            if issuer is not None:
                break
        if issuer is None:
            # samopodpisany, ale nie będący kotwicą?
            if _is_self_issued(current):
                self_res = _verifies(current, current)
                if self_res == "ok":
                    top_untrusted_root = True
                elif self_res == "bad_sig":
                    sig_failed_for_name_match = True  # podpis własny nie zgadza się z kluczem
            break
        fp = fingerprint(issuer)
        if fp in seen:  # pętla
            break
        seen.add(fp)
        path.append(fp)
        if issuer is not current:
            p = _ca_problems(issuer, ca_below, now)
            problems.extend(f"{issuer.subject.rfc4514_string()}: {x}" for x in p)
        if store.is_anchor(issuer):
            trusted = True
            break
        if _is_self_issued(issuer):
            top_untrusted_root = True
            break
        ca_below += 1
        current = issuer

    # --- wynik kryptograficzny ---
    if unsupported and len(path) == 1:
        crypto = CheckStatus.FAIL
        findings.append(
            Finding("SIG_UNSUPPORTED", CheckStatus.FAIL, "Algorytm podpisu wystawcy nie jest obsługiwany.")
        )
    elif len(path) == 1 and not top_untrusted_root:
        if sig_failed_for_name_match:
            crypto = CheckStatus.FAIL
            findings.append(
                Finding(
                    "SIG_INVALID",
                    CheckStatus.FAIL,
                    "Podpis certyfikatu nie zgadza się z kluczem żadnego znanego wystawcy o tej nazwie "
                    "(możliwa podmiana CA lub uszkodzenie).",
                )
            )
        else:
            crypto = CheckStatus.UNKNOWN
            declared = {
                ISSUER_KSEF: "zadeklarowany jako KSeF/MF",
                ISSUER_OTHER: "inny urząd certyfikacji",
            }.get(kind, "")
            findings.append(
                Finding(
                    "ISSUER_MISSING",
                    CheckStatus.UNKNOWN,
                    f"Podpis wystawcy nie został sprawdzony: certyfikat wystawcy „{_issuer_label(leaf)}” "
                    f"({declared}) nie został dostarczony ani skonfigurowany jako punkt zaufania. "
                    "To ograniczenie weryfikacji offline, a nie błąd badanego certyfikatu.",
                )
            )
    else:
        crypto = CheckStatus.PASS
        if top_untrusted_root and len(path) == 1:
            findings.append(
                Finding(
                    "SELF_SIGNED",
                    CheckStatus.PASS,
                    "Certyfikat jest samopodpisany; podpis własny jest poprawny.",
                )
            )

    # --- zaufanie ---
    if problems:
        trust = CheckStatus.FAIL
        findings.extend(
            Finding("CA_CONSTRAINTS", CheckStatus.FAIL, f"Ograniczenia CA naruszone: {x}") for x in problems
        )
    elif trusted:
        trust = CheckStatus.PASS
        findings.append(
            Finding("TRUST_OK", CheckStatus.PASS, "Łańcuch kończy się w skonfigurowanym punkcie zaufania.")
        )
    elif len(store) == 0:
        trust = CheckStatus.NOT_CHECKED
        findings.append(
            Finding(
                "TRUST_NO_ANCHORS",
                CheckStatus.NOT_CHECKED,
                "Nie skonfigurowano punktów zaufania (MF nie publikuje CA certyfikatów KSeF) – "
                "zaufanie do wystawcy nie zostało sprawdzone.",
            )
        )
        if top_untrusted_root and len(path) == 1:
            findings.append(
                Finding(
                    "TRUST_SELF_SIGNED",
                    CheckStatus.NOT_CHECKED,
                    "Certyfikat samopodpisany: podpis własny jest poprawny, lecz brak zaufanego łańcucha PKI. "
                    "Akceptacja przez KSeF TEST (jeśli występuje) to osobny wynik w sekcji ONLINE.",
                )
            )
    elif top_untrusted_root and len(path) == 1:
        # Samopodpisany liść spoza punktów zaufania: nie ma podstawy zaufania PKI, ale to nie jest dowód błędu.
        trust = CheckStatus.UNKNOWN
        findings.append(
            Finding(
                "TRUST_SELF_SIGNED",
                CheckStatus.UNKNOWN,
                "Certyfikat samopodpisany: podpis własny jest poprawny, lecz brak zaufanego łańcucha PKI. "
                "Akceptacja przez KSeF TEST (jeśli występuje) to osobny wynik w sekcji ONLINE.",
            )
        )
    elif top_untrusted_root:
        trust = CheckStatus.FAIL
        findings.append(
            Finding(
                "TRUST_UNTRUSTED_ROOT",
                CheckStatus.FAIL,
                "Łańcuch kończy się w certyfikacie głównym, którego nie ma wśród zaufanych punktów.",
            )
        )
    elif crypto is CheckStatus.FAIL:
        trust = CheckStatus.FAIL
    else:
        trust = CheckStatus.UNKNOWN
        findings.append(
            Finding(
                "TRUST_INCOMPLETE",
                CheckStatus.UNKNOWN,
                "Nie zbudowano pełnej ścieżki do zaufanego punktu (brakuje ogniwa łańcucha).",
            )
        )
    return ChainResult(crypto, trust, findings, path, kind)
