"""Model domenowy wyników weryfikacji (niezależny od CLI i GUI)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

SCHEMA_VERSION = "2"


class CheckStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    UNKNOWN = "UNKNOWN"
    NOT_CHECKED = "NOT_CHECKED"


class CertType(str, Enum):
    AUTHENTICATION = "Authentication"
    OFFLINE = "Offline"
    UNKNOWN = "UNKNOWN"


class Verdict(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    INDETERMINATE = "INDETERMINATE"


# Kolejność „pogarszania" przy agregacji ustaleń w jedną kontrolę.
_SEVERITY = {
    CheckStatus.PASS: 0,
    CheckStatus.WARNING: 1,
    CheckStatus.NOT_CHECKED: 2,
    CheckStatus.UNKNOWN: 3,
    CheckStatus.FAIL: 4,
}


@dataclass
class Finding:
    code: str
    status: CheckStatus
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "status": self.status.value, "message": self.message}


@dataclass
class Check:
    name: str
    status: CheckStatus
    summary: str
    findings: list[Finding] = field(default_factory=list)
    code: str | None = None  # kod wyniku, np. KEY_DECRYPTION_FAILED, SIGNATURE_VALID

    @classmethod
    def from_findings(cls, name: str, findings: list[Finding], ok_summary: str) -> Check:
        if not findings:
            return cls(name, CheckStatus.PASS, ok_summary, [])
        worst = max(findings, key=lambda f: _SEVERITY[f.status])
        if worst.status is CheckStatus.PASS:
            return cls(name, CheckStatus.PASS, ok_summary, findings)
        return cls(name, worst.status, worst.message, findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "code": self.code,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class SubjectInfo:
    common_name: str | None = None
    given_names: list[str] = field(default_factory=list)
    surname: str | None = None
    organization: str | None = None
    country: str | None = None
    serial_number: str | None = None
    organization_identifier: str | None = None
    unique_identifier: str | None = None
    nip: str | None = None
    pesel: str | None = None
    kind: str = "unknown"  # person | organization | unknown

    def to_dict(self) -> dict[str, Any]:
        return {
            "common_name": self.common_name,
            "given_names": self.given_names,
            "surname": self.surname,
            "organization": self.organization,
            "country": self.country,
            "serial_number": self.serial_number,
            "organization_identifier": self.organization_identifier,
            "unique_identifier": self.unique_identifier,
            "nip": self.nip,
            "pesel": self.pesel,
            "kind": self.kind,
        }


@dataclass
class ExtensionInfo:
    oid: str
    name: str
    critical: bool

    def to_dict(self) -> dict[str, Any]:
        return {"oid": self.oid, "name": self.name, "critical": self.critical}


@dataclass
class CertInfo:
    subject: str
    issuer: str
    serial_hex: str
    not_before: str  # ISO-8601 UTC
    not_after: str
    fingerprint_sha256: str
    signature_algorithm: str
    key_algorithm: str  # np. "ECDSA P-256", "RSA 2048"
    ski: str | None
    aki: str | None
    key_usage: list[str]
    extended_key_usage: list[str]
    basic_constraints: str | None
    is_ca: bool
    extensions: list[ExtensionInfo]
    subject_info: SubjectInfo

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "serial_hex": self.serial_hex,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "fingerprint_sha256": self.fingerprint_sha256,
            "signature_algorithm": self.signature_algorithm,
            "key_algorithm": self.key_algorithm,
            "subject_key_identifier": self.ski,
            "authority_key_identifier": self.aki,
            "key_usage": self.key_usage,
            "extended_key_usage": self.extended_key_usage,
            "basic_constraints": self.basic_constraints,
            "is_ca": self.is_ca,
            "extensions": [e.to_dict() for e in self.extensions],
            "subject_info": self.subject_info.to_dict(),
        }


GROUPS: dict[str, list[str]] = {
    # A. zestaw CERT + KEY + PASSWORD
    "local": ["parsing", "validity", "inputs", "key_decrypt", "key_match", "signature_test"],
    # B. zaufanie i profil KSeF
    "trust": ["crypto", "trust", "classification", "profile"],
    # C. online
    "online": ["online"],
}


def group_status(checks: dict[str, Check], names: list[str]) -> CheckStatus:
    """Najgorszy status grupy: FAIL > UNKNOWN > NOT_CHECKED > WARNING > PASS (UNKNOWN nigdy nie staje się PASS)."""
    st = [checks[n].status for n in names if n in checks]
    if CheckStatus.FAIL in st:
        return CheckStatus.FAIL
    if CheckStatus.UNKNOWN in st:
        return CheckStatus.UNKNOWN
    if CheckStatus.NOT_CHECKED in st:
        return CheckStatus.NOT_CHECKED
    return CheckStatus.WARNING if CheckStatus.WARNING in st else CheckStatus.PASS


@dataclass
class CertReport:
    index: int  # pozycja w pliku (od 0)
    role: str  # "leaf" | "ca"
    info: CertInfo
    cert_type: CertType
    days_remaining: int
    expiry_warning_days: int | None  # 30 / 14 / 7 albo None
    checks: dict[str, Check]
    verdict: Verdict
    online_status: str  # NOT_CHECKED albo status z API / UNKNOWN
    chain: list[str] = field(default_factory=list)  # odciski SHA-256 ścieżki
    operations: dict[str, Any] = field(default_factory=dict)  # wyniki operacji (uwierzytelnienie, KOD II)
    owner: dict[str, Any] = field(default_factory=dict)  # właściciel = X.509 Subject (patrz owner_info)
    api_subject: dict[str, Any] | None = (
        None  # podmiot z API – tylko gdy rekord rejestru jednoznacznie dopasowano
    )

    def local_result(self) -> Verdict:
        g = group_status(self.checks, GROUPS["local"])
        return {
            CheckStatus.FAIL: Verdict.INVALID,
            CheckStatus.UNKNOWN: Verdict.INDETERMINATE,
            CheckStatus.NOT_CHECKED: Verdict.INDETERMINATE,
        }.get(g, Verdict.VALID)

    def trust_result(self) -> str:
        g = group_status(self.checks, GROUPS["trust"])
        return {
            CheckStatus.FAIL: "FAILED",
            CheckStatus.UNKNOWN: "UNCONFIRMED",
            CheckStatus.NOT_CHECKED: "UNCONFIRMED",
        }.get(g, "CONFIRMED")

    def ksef_context(self) -> dict[str, Any] | None:
        """Kontekst wskazany do uwierzytelnienia (np. Nip:6666666666) – nie dowodzi tożsamości właściciela."""
        ctx = self.operations.get("authentication", {}).get("context")
        return {"value": ctx, "source": "uwierzytelnienie KSeF"} if ctx else None

    def online_authorization(self) -> str:
        """GRANTED/DENIED tylko, gdy potwierdziło to API (uwierzytelnienie XAdES lub odpowiedź rejestru)."""
        auth = self.operations.get("authentication", {})
        if auth.get("authorization") in ("GRANTED", "DENIED"):
            return str(auth["authorization"])
        return "NOT_TESTED"

    def summary(self) -> dict[str, Any]:
        c = self.checks
        dec = c["key_decrypt"]
        decrypt = {
            "KEY_DECRYPTED": "DECRYPTED",
            "KEY_UNENCRYPTED": "UNENCRYPTED",
            "KEY_DECRYPTION_FAILED": "DECRYPTION_FAILED",
        }.get(dec.code or "", None)
        if decrypt is None:
            decrypt = (
                "NOT_DECRYPTED"
                if dec.status in (CheckStatus.UNKNOWN, CheckStatus.NOT_CHECKED)
                else "DECRYPTION_FAILED"
            )
        match = {CheckStatus.PASS: "MATCH", CheckStatus.FAIL: "MISMATCH"}.get(
            c["key_match"].status, "NOT_CHECKED"
        )
        sig = c["signature_test"]
        cert_val = group_status(c, ["parsing", "validity"])
        auth = self.operations.get("authentication", {})
        return {
            "CERTIFICATE_VALIDATION": {CheckStatus.FAIL: "INVALID"}.get(cert_val, "VALID"),
            "PRIVATE_KEY_DECRYPTION": decrypt,
            "KEY_PAIR_MATCH": match,
            "SIGNATURE_VERIFICATION": sig.code or "NOT_CHECKED",
            "KSEF_PROFILE_VALIDATION": c["profile"].status.value,
            "KSEF_ONLINE_STATUS": self.online_status,
            "KSEF_AUTHENTICATION_RESULT": auth.get("code", "NOT_TESTED"),
            # niezależne wyniki online: uwierzytelnienie ≠ autoryzacja ≠ wpis w rejestrze certyfikatów
            "KSEF_AUTHENTICATION": auth.get("authentication", "NOT_TESTED"),
            "KSEF_AUTHORIZATION": self.online_authorization(),
            "KSEF_REGISTRY_STATUS": self.online_status,
            "LOCAL_KEYSET_RESULT": self.local_result().value,
            "TRUST_RESULT": self.trust_result(),
            "LOCAL_RESULT": self.verdict.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "role": self.role,
            "certificate": self.info.to_dict(),
            # trzy RÓŻNE pojęcia: właściciel (X.509 Subject), kontekst KSeF (NIP uwierzytelnienia), podmiot z API
            "owner": self.owner,
            "ksef_context": self.ksef_context(),
            "api_subject": self.api_subject,
            "type": self.cert_type.value,
            "days_remaining": self.days_remaining,
            "expiry_warning_days": self.expiry_warning_days,
            "checks": {k: v.to_dict() for k, v in self.checks.items()},
            "chain": self.chain,
            "result": self.verdict.value,
            "groups": {
                "local": {"result": self.local_result().value, "checks": GROUPS["local"]},
                "trust": {"result": self.trust_result(), "checks": GROUPS["trust"]},
                "online": {"result": self.online_status, "checks": GROUPS["online"]},
            },
            "summary": self.summary(),
            "operations": self.operations,
            "online_status": self.online_status,
        }


@dataclass
class FileError:
    code: str
    message: str
    kind: str  # "runtime" (błąd wykonania → exit 2) | "content" (zawartość pliku → INVALID)

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, "kind": self.kind}


@dataclass
class FileReport:
    path: str
    file_format: str | None
    certificates: list[CertReport] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    error: FileError | None = None
    inputs: dict[str, str | None] = field(default_factory=dict)  # certificate / private_key / password

    @property
    def verdict(self) -> Verdict | None:
        """Werdykt pliku; None = błąd wykonania (brak werdyktu)."""
        if self.error is not None:
            return Verdict.INVALID if self.error.kind == "content" else None
        verdicts = [c.verdict for c in self.certificates]
        if not verdicts:
            return Verdict.INVALID
        if Verdict.INVALID in verdicts:
            return Verdict.INVALID
        if Verdict.INDETERMINATE in verdicts:
            return Verdict.INDETERMINATE
        return Verdict.VALID

    def to_dict(self) -> dict[str, Any]:
        v = self.verdict
        return {
            "file": self.path,
            "format": self.file_format,
            "result": v.value if v else "ERROR",
            "error": self.error.to_dict() if self.error else None,
            "inputs": self.inputs,
            "notes": self.notes,
            "certificates": [c.to_dict() for c in self.certificates],
        }
