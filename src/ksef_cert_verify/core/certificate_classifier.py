"""Klasyfikacja Authentication / Offline na podstawie Key Usage (`certyfikaty-KSeF.md`).

Sam Key Usage nie dowodzi, że to certyfikat KSeF – dlatego klasyfikacja jest
oddzielona od oceny profilu i zaufania do wystawcy.
"""

from __future__ import annotations

from cryptography import x509

from .certificate_parser import key_usage_flags
from .models import CertType, Check, CheckStatus, Finding

DS = "Digital Signature"
CC = "Non-Repudiation"


def classify(cert: x509.Certificate, expected: CertType | None = None) -> tuple[CertType, Check]:
    flags = key_usage_flags(cert)
    findings: list[Finding] = []
    cert_type = CertType.UNKNOWN

    if flags is None:
        findings.append(
            Finding(
                "KU_MISSING",
                CheckStatus.UNKNOWN,
                "Brak rozszerzenia Key Usage – nie można ustalić typu certyfikatu.",
            )
        )
    elif DS in flags and CC in flags:
        findings.append(
            Finding(
                "KU_BOTH",
                CheckStatus.FAIL,
                "Key Usage zawiera jednocześnie Digital Signature i Non-Repudiation – dokumentacja MF "
                "dopuszcza tylko jeden typ certyfikatu.",
            )
        )
    elif flags == {DS}:
        cert_type = CertType.AUTHENTICATION
    elif flags == {CC}:
        cert_type = CertType.OFFLINE
    elif DS in flags or CC in flags:
        extra = ", ".join(sorted(flags - {DS, CC}))
        findings.append(
            Finding(
                "KU_EXTRA",
                CheckStatus.UNKNOWN,
                f"Nieoczekiwana kombinacja Key Usage (dodatkowo: {extra}) – typu nie można wiarygodnie ustalić.",
            )
        )
    else:
        shown = ", ".join(sorted(flags)) or "(puste)"
        findings.append(
            Finding(
                "KU_WRONG",
                CheckStatus.FAIL,
                f"Key Usage ({shown}) nie zawiera ani Digital Signature, ani Non-Repudiation – "
                "to nie jest certyfikat Authentication ani Offline.",
            )
        )

    if expected is not None and cert_type is not CertType.UNKNOWN and cert_type is not expected:
        findings.append(
            Finding(
                "TYPE_MISMATCH",
                CheckStatus.FAIL,
                f"Oczekiwano typu {expected.value}, rozpoznano {cert_type.value}.",
            )
        )
    summary = f"Typ: {cert_type.value}" if cert_type is not CertType.UNKNOWN else "Typ nieustalony"
    return cert_type, Check.from_findings("classification", findings, summary)
