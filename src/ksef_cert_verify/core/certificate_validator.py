"""Silnik weryfikacji: wspólny dla CLI i GUI. Czas (`now`) jest parametrem."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from .certificate_classifier import classify
from .certificate_parser import (
    KNOWN_EXTENSION_OIDS,
    KSEF_DN_OIDS,
    OID_ORG_IDENTIFIER,
    api_serial,
    aware,
    key_description,
    not_after,
    not_before,
    owner_info,
    parse_certificate,
)
from .models import (
    CertInfo,
    CertReport,
    CertType,
    Check,
    CheckStatus,
    Finding,
    Verdict,
)
from .private_key import SignatureEvidence, match_check, signature_check, spki_of_certificate
from .trust_store import ISSUER_KSEF, TrustStore, validate_chain

EXPIRY_THRESHOLDS = (7, 14, 30)
MAX_VALIDITY_DAYS = 2 * 366  # „maks. 2 lata” – źródło: ksef.podatki.gov.pl (nie repo API)

MANDATORY_OFFLINE = (
    "parsing",
    "validity",
    "crypto",
    "trust",
    "classification",
    "profile",
    "inputs",
    "key_decrypt",
    "key_match",
    "signature_test",
)


class OnlineLookup(Protocol):
    def lookup(self, serial_hex16: str) -> OnlineOutcome: ...

    # Opcjonalnie (sprawdzane przez hasattr): def retrieve_der(self, serial_hex16: str) -> tuple[bytes | None, str]


@dataclass
class OnlineOutcome:
    """Wynik zapytania /certificates/query (niezależny od warstwy HTTP)."""

    status: str  # Active | Blocked | Revoked | Expired | NOT_FOUND | UNKNOWN
    message: str
    api_type: str | None = None
    api_valid_from: str | None = None
    api_valid_to: str | None = None
    api_common_name: str | None = None  # CN podmiotu wg rejestru (NIE nazwa własna certyfikatu)
    api_name: str | None = None  # nazwa własna nadana przy rejestracji certyfikatu
    api_subject_id_type: str | None = None  # Nip | Pesel | Fingerprint
    api_subject_id_value: str | None = None
    authorization: str | None = None  # GRANTED (HTTP 200 z rejestru) | DENIED (403) | None (nieustalone)


@dataclass
class VerifyContext:
    now: datetime
    trust: TrustStore
    expected_type: CertType | None = None
    online: OnlineLookup | None = None
    candidates: list[x509.Certificate] = field(default_factory=list)
    # Wynik odczytu klucza prywatnego (bez klucza: NOT_CHECKED → wynik nigdy nie jest VALID).
    key_decrypt: Check | None = None
    key_spki: bytes | None = None
    signature: SignatureEvidence | None = None  # dowód aktywnego testu podpisu (bez klucza)
    online_requested: bool = (
        False  # użytkownik zażądał statusu online (nawet jeśli sesji nie udało się uzyskać)
    )
    online_note: str | None = None
    online_fetch_certificate: bool = False  # zawsze porównuj DER z /certificates/retrieve (dodatkowe żądanie)
    inputs: Check | None = None  # kompletność danych wejściowych (certyfikat, klucz, hasło)


def _validity_check(cert: x509.Certificate, now: datetime) -> tuple[Check, int, int | None]:
    nb, na = not_before(cert), not_after(cert)
    days = (na - now) // timedelta(days=1)
    findings: list[Finding] = []
    warn: int | None = None
    if na <= nb:
        findings.append(
            Finding("DATES_INVERTED", CheckStatus.FAIL, "Not After nie jest późniejsze niż Not Before.")
        )
    if now < nb:
        findings.append(
            Finding(
                "NOT_YET_VALID", CheckStatus.FAIL, "Certyfikat jeszcze nie obowiązuje (przed Not Before)."
            )
        )
    elif now > na:
        findings.append(Finding("EXPIRED", CheckStatus.FAIL, "Certyfikat wygasł (po Not After)."))
    else:
        warn = next((t for t in EXPIRY_THRESHOLDS if days <= t), None)
        if warn is not None:
            findings.append(
                Finding(
                    "EXPIRES_SOON",
                    CheckStatus.WARNING,
                    f"Certyfikat wygasa za {days} dn. (próg ostrzeżenia: {warn} dn.).",
                )
            )
    if (na - nb).days > MAX_VALIDITY_DAYS:
        findings.append(
            Finding(
                "VALIDITY_TOO_LONG",
                CheckStatus.WARNING,
                "Okres ważności dłuższy niż 2 lata – certyfikaty KSeF są ważne maks. 2 lata (informacja urzędowa).",
            )
        )
    return Check.from_findings("validity", findings, "Certyfikat jest w okresie ważności."), days, warn


def _crypto_algorithm_findings(cert: x509.Certificate) -> list[Finding]:
    out: list[Finding] = []
    _, family, _ = key_description(cert)
    h = cert.signature_hash_algorithm
    if isinstance(h, hashes.MD5):
        out.append(Finding("SIG_WEAK", CheckStatus.FAIL, "Podpis certyfikatu używa MD5 – niedozwolone."))
    elif isinstance(h, hashes.SHA1):
        out.append(Finding("SIG_SHA1", CheckStatus.WARNING, "Podpis certyfikatu używa SHA-1 (przestarzały)."))
    if family == "inna":
        out.append(
            Finding(
                "KEY_UNSUPPORTED",
                CheckStatus.FAIL,
                f"Nieobsługiwany algorytm klucza publicznego ({key_description(cert)[0]}); KSeF dopuszcza RSA 2048 lub EC P-256.",
            )
        )
    return out


def _profile_check(cert: x509.Certificate, cert_type: CertType, subject_notes: list[str]) -> Check:
    """Zgodność z *udokumentowanymi* kryteriami MF. Nie jest to potwierdzenie przez MF."""
    findings: list[Finding] = []
    _, family, detail = key_description(cert)
    if family == "RSA" and detail != 2048:
        findings.append(
            Finding(
                "KEY_RSA_SIZE", CheckStatus.FAIL, f"Klucz RSA {detail} bitów; KSeF dopuszcza wyłącznie 2048."
            )
        )
    elif family == "EC" and detail != "secp256r1":
        findings.append(
            Finding(
                "KEY_EC_CURVE",
                CheckStatus.FAIL,
                f"Krzywa {detail}; KSeF dopuszcza wyłącznie NIST P-256 (secp256r1).",
            )
        )
    elif family == "inna":
        findings.append(
            Finding("KEY_FAMILY", CheckStatus.FAIL, "Rodzaj klucza spoza dozwolonych (RSA 2048, EC P-256).")
        )

    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if bc.ca:
            findings.append(
                Finding(
                    "LEAF_IS_CA",
                    CheckStatus.FAIL,
                    "Certyfikat końcowy KSeF nie może być CA (BasicConstraints CA=TRUE).",
                )
            )
    except x509.ExtensionNotFound:
        pass

    for ext in cert.extensions:
        if ext.critical and ext.oid not in KNOWN_EXTENSION_OIDS:
            findings.append(
                Finding(
                    "CRITICAL_UNKNOWN_EXT",
                    CheckStatus.FAIL,
                    f"Nieznane rozszerzenie krytyczne {ext.oid.dotted_string} – certyfikatu nie wolno akceptować.",
                )
            )

    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        names = ", ".join(getattr(o, "_name", o.dotted_string) for o in eku)
        findings.append(
            Finding(
                "EKU_PRESENT",
                CheckStatus.WARNING,
                f"Obecne Extended Key Usage ({names}); dokumentacja MF nie opisuje EKU.",
            )
        )
    except x509.ExtensionNotFound:
        pass

    serial_hex = f"{cert.serial_number:X}"
    if cert.serial_number < 0 or len(serial_hex) > 16:
        findings.append(
            Finding(
                "SERIAL_FORMAT",
                CheckStatus.WARNING,
                "Numer seryjny nie mieści się w formacie 16 znaków hex używanym przez API KSeF "
                "(wniosek z `open-api.json`; mapowanie na serial X.509 nie jest udokumentowane).",
            )
        )

    oids = {a.oid for a in cert.subject}
    unknown = oids - KSEF_DN_OIDS
    if unknown:
        findings.append(
            Finding(
                "DN_UNKNOWN_ATTR",
                CheckStatus.WARNING,
                "Subject zawiera atrybuty spoza listy KSeF: "
                + ", ".join(sorted(o.dotted_string for o in unknown)),
            )
        )
    for oid, label in ((x509.NameOID.COMMON_NAME, "commonName"), (x509.NameOID.COUNTRY_NAME, "countryName")):
        if oid not in oids:
            findings.append(
                Finding("DN_MISSING", CheckStatus.WARNING, f"W Subject brak wymaganego atrybutu {label}.")
            )
    has_person = bool(oids & {x509.NameOID.GIVEN_NAME, x509.NameOID.SURNAME})
    has_org = bool(oids & {x509.NameOID.ORGANIZATION_NAME, OID_ORG_IDENTIFIER})
    if has_person and has_org:
        findings.append(
            Finding(
                "DN_MIXED",
                CheckStatus.WARNING,
                "Subject łączy atrybuty osoby i organizacji; profile MF (osoba / pieczęć firmowa) są rozłączne.",
            )
        )
    for n in subject_notes:
        findings.append(Finding("ID_CHECKSUM", CheckStatus.WARNING, n))

    if cert_type is CertType.UNKNOWN:
        findings.append(
            Finding(
                "PROFILE_UNCONFIRMED",
                CheckStatus.UNKNOWN,
                "Typ certyfikatu nie został ustalony – zgodność z profilem KSeF nie została potwierdzona.",
            )
        )
    return Check.from_findings(
        "profile", findings, "Spełnione udokumentowane kryteria profilu KSeF (nie jest to potwierdzenie MF)."
    )


def _parse_api_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return aware(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except ValueError:
        return None


def _metadata_mismatches(cert: x509.Certificate, info: CertInfo, out: OnlineOutcome) -> list[str]:
    """Pola z API, które NIE zgadzają się z certyfikatem (puste = wiarygodne dopasowanie)."""
    bad: list[str] = []
    tol = timedelta(seconds=2)
    for label, api_val, local in (
        ("ważny od", out.api_valid_from, not_before(cert)),
        ("ważny do", out.api_valid_to, not_after(cert)),
    ):
        parsed = _parse_api_dt(api_val)
        if api_val and (parsed is None or abs(parsed - local) > tol):
            bad.append(f"{label}: API {api_val} ≠ certyfikat {local.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    # commonName z API celowo NIE jest tu porównywane: to nie identyfikator (patrz _cn_note).
    sid = info.subject_info
    if out.api_subject_id_type == "Nip" and sid.nip and out.api_subject_id_value != sid.nip:
        bad.append("identyfikator NIP różni się")
    if out.api_subject_id_type == "Pesel" and sid.pesel and out.api_subject_id_value != sid.pesel:
        bad.append("identyfikator PESEL różni się")
    return bad


def _cn_note(info: CertInfo, out: OnlineOutcome) -> str | None:
    """Różnica CN/nazwa własna – wyłącznie informacja (nie wpływa na dopasowanie ani status)."""
    cn = info.subject_info.common_name
    if out.api_common_name and cn and out.api_common_name != cn:
        extra = f"; nazwa własna certyfikatu w rejestrze: „{out.api_name}”" if out.api_name else ""
        return (
            f"commonName w rejestrze („{out.api_common_name}”) różni się od CN w certyfikacie („{cn}”){extra}. "
            "To nie identyfikator – dopasowanie opiera się na numerze seryjnym, typie i terminach."
        )
    return None


def _online_check(
    cert: x509.Certificate, ctx: VerifyContext, cert_type: CertType, info: CertInfo, issuer: str
) -> tuple[Check, str, dict | None]:
    if ctx.online is None:
        if ctx.online_requested:
            msg = (
                ctx.online_note
                or "Zażądano statusu online, ale nie uzyskano dostępu do API – status nieustalony."
            )
            return (
                Check(
                    "online",
                    CheckStatus.UNKNOWN,
                    msg,
                    [Finding("ONLINE_UNAVAILABLE", CheckStatus.UNKNOWN, msg)],
                    code="KSEF_UNKNOWN",
                ),
                "UNKNOWN",
                None,
            )
        return (
            Check("online", CheckStatus.NOT_CHECKED, "Status w KSeF nie był sprawdzany."),
            "NOT_CHECKED",
            None,
        )
    serial = api_serial(cert)
    if serial is None:
        return (
            Check(
                "online",
                CheckStatus.UNKNOWN,
                "Numer seryjny nie mieści się w formacie 16 znaków hex – nie można zapytać API.",
            ),
            "UNKNOWN",
            None,
        )
    out = ctx.online.lookup(serial)
    findings: list[Finding] = []
    reported = out.status
    if out.status in ("Active", "Blocked", "Revoked", "Expired"):
        mismatches = _metadata_mismatches(cert, info, out)
        same_cert: bool | None = None  # None = brak dowodu DER
        retrieve = getattr(ctx.online, "retrieve_der", None)
        if retrieve is not None and (mismatches or ctx.online_fetch_certificate):
            der, why = retrieve(serial)
            if der is None:
                findings.append(Finding("ONLINE_RETRIEVE_FAILED", CheckStatus.WARNING, why))
            else:
                same_cert = der == cert.public_bytes(serialization.Encoding.DER)
                if same_cert:
                    findings.append(
                        Finding(
                            "ONLINE_DER_MATCH",
                            CheckStatus.PASS,
                            "Pełny certyfikat (DER) z rejestru jest identyczny z badanym (zgodny SHA-256).",
                        )
                    )
        if same_cert is False or (same_cert is None and mismatches):
            # Rejestr ma inny certyfikat o tym numerze albo nie da się tego rozstrzygnąć: to nie jest dopasowanie.
            reported = "UNKNOWN"
            why = (
                "pełny certyfikat z rejestru różni się od badanego"
                if same_cert is False
                else "; ".join(mismatches)
            )
            findings.append(
                Finding(
                    "ONLINE_NOT_MATCHED",
                    CheckStatus.UNKNOWN,
                    f"Rejestr zawiera wpis o tym numerze seryjnym, ale nie da się go przypisać do badanego "
                    f"certyfikatu ({why}). Status nie został potwierdzony – to nie oznacza, że certyfikat jest "
                    "niepoprawny.",
                )
            )
        else:
            note = _cn_note(info, out)
            if note:
                findings.append(Finding("ONLINE_CN_DIFFERS", CheckStatus.WARNING, note))
            if out.status != "Active":
                findings.append(
                    Finding(
                        "ONLINE_" + out.status.upper(),
                        CheckStatus.FAIL,
                        f"Status w KSeF: {out.status}. {out.message}".strip(),
                    )
                )
    elif out.status == "NOT_FOUND" and issuer != ISSUER_KSEF:
        # Certyfikat spoza KSeF (np. samopodpisany akceptowany w TEST) nie musi istnieć w rejestrze.
        reported = "NOT_APPLICABLE"
        findings.append(
            Finding(
                "ONLINE_NOT_APPLICABLE",
                CheckStatus.NOT_CHECKED,
                "Certyfikat nie został wystawiony przez KSeF (Issuer: "
                f"{'samopodpisany' if issuer == 'SELF_SIGNED' else 'inny urząd certyfikacji'}), więc brak wpisu "
                "w rejestrze KSeF jest oczekiwany. Rejestr nie dotyczy tego certyfikatu.",
            )
        )
    else:
        findings.append(Finding("ONLINE_UNKNOWN", CheckStatus.UNKNOWN, out.message))
    if (
        reported == "Active"
        and out.api_type
        and cert_type is not CertType.UNKNOWN
        and out.api_type != cert_type.value
    ):
        findings.append(
            Finding(
                "ONLINE_TYPE_MISMATCH",
                CheckStatus.FAIL,
                f"Typ w KSeF ({out.api_type}) różni się od rozpoznanego z certyfikatu ({cert_type.value}).",
            )
        )
    summary = (
        "Status w KSeF: Active (numer seryjny, typ i terminy ważności zgodne z certyfikatem)."
        if reported == "Active"
        else findings[-1].message
        if reported == "NOT_APPLICABLE" or (reported == "UNKNOWN" and findings)
        else out.message
    )
    check = Check.from_findings("online", findings, summary)
    check.code = f"KSEF_{reported.upper()}"
    record = None
    if reported in (
        "Active",
        "Blocked",
        "Revoked",
        "Expired",
    ):  # tylko jednoznacznie dopasowany wpis rejestru
        record = {
            "source": "API KSeF /certificates/query",
            "status": reported,
            "common_name": out.api_common_name,
            "certificate_name": out.api_name,  # nazwa własna nadana w KSeF – NIE dowód tożsamości
            "certificate_type": out.api_type,
            "subject_identifier": {"type": out.api_subject_id_type, "value": out.api_subject_id_value},
        }
    return check, reported, record


def aggregate(checks: dict[str, Check], online_requested: bool) -> Verdict:
    mandatory = list(MANDATORY_OFFLINE) + (["online"] if online_requested else [])
    statuses = [checks[n].status for n in mandatory]
    if CheckStatus.FAIL in statuses:
        return Verdict.INVALID
    if any(s in (CheckStatus.UNKNOWN, CheckStatus.NOT_CHECKED) for s in statuses):
        return Verdict.INDETERMINATE
    return Verdict.VALID


def verify_certificate(
    cert: x509.Certificate,
    ctx: VerifyContext,
    index: int = 0,
    role: str = "leaf",
) -> CertReport:
    now = aware(ctx.now)
    info, subject_notes = parse_certificate(cert)
    cert_type, cls_check = classify(cert, ctx.expected_type)
    validity, days, warn = _validity_check(cert, now)

    chain = validate_chain(cert, ctx.candidates, ctx.trust, now)
    crypto_findings = _crypto_algorithm_findings(cert)
    crypto_findings += [f for f in chain.findings if f.code.startswith(("SIG_", "ISSUER_", "SELF_"))]
    if chain.crypto is CheckStatus.UNKNOWN and not any(
        f.status is CheckStatus.UNKNOWN for f in crypto_findings
    ):
        crypto_findings.append(
            Finding("CRYPTO_UNKNOWN", CheckStatus.UNKNOWN, "Podpis nie został zweryfikowany.")
        )
    crypto = Check.from_findings(
        "crypto", crypto_findings, "Algorytmy dopuszczalne, podpisy w łańcuchu poprawne."
    )
    trust = Check.from_findings(
        "trust",
        [f for f in chain.findings if not f.code.startswith(("SIG_", "ISSUER_", "SELF_"))],
        "Wystawca zaufany (łańcuch kończy się w skonfigurowanym punkcie zaufania).",
    )
    if chain.trust is CheckStatus.FAIL and trust.status is not CheckStatus.FAIL:
        trust = Check(
            "trust",
            CheckStatus.FAIL,
            "Zaufanie do wystawcy nie zostało potwierdzone (nieprawidłowy podpis wystawcy).",
            trust.findings,
        )
    elif chain.trust is CheckStatus.UNKNOWN and trust.status is CheckStatus.PASS:
        trust = Check(
            "trust", CheckStatus.UNKNOWN, "Nie zbudowano ścieżki do punktu zaufania.", trust.findings
        )

    profile = _profile_check(cert, cert_type, subject_notes)
    online, online_status, api_subject = _online_check(cert, ctx, cert_type, info, chain.issuer_kind)
    key_decrypt = ctx.key_decrypt or Check(
        "key_decrypt", CheckStatus.NOT_CHECKED, "Nie podano klucza prywatnego – pełna weryfikacja niemożliwa."
    )
    key_match = match_check(spki_of_certificate(cert), ctx.key_spki)
    signature_test = signature_check(cert, ctx.key_spki, ctx.signature, ctx.key_decrypt)
    inputs = ctx.inputs or Check(
        "inputs", CheckStatus.NOT_CHECKED, "Brak kompletu danych: certyfikat, klucz i hasło."
    )

    checks = {
        "parsing": Check("parsing", CheckStatus.PASS, "Struktura X.509 odczytana poprawnie."),
        "validity": validity,
        "crypto": crypto,
        "trust": trust,
        "classification": cls_check,
        "profile": profile,
        "online": online,
        "inputs": inputs,
        "key_decrypt": key_decrypt,
        "key_match": key_match,
        "signature_test": signature_test,
    }
    verdict = aggregate(checks, ctx.online is not None or ctx.online_requested)
    return CertReport(
        index=index,
        role=role,
        info=info,
        cert_type=cert_type,
        days_remaining=days,
        expiry_warning_days=warn,
        checks=checks,
        verdict=verdict,
        online_status=online_status,
        chain=chain.path,
        owner=owner_info(info, cert_type, subject_notes),
        api_subject=api_subject,
    )
