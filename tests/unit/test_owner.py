"""Właściciel certyfikatu: dane wyłącznie z X.509 Subject; trzy rozdzielone pojęcia (właściciel / kontekst / API)."""

from __future__ import annotations

import json

import pytest

from ksef_cert_verify.core.certificate_parser import owner_info, parse_certificate
from ksef_cert_verify.core.models import CertType
from ksef_cert_verify.core.report import VerifyOptions, build_json, verify_file
from tests.conftest import NOW, _name, make_ca, make_leaf, pem

pytestmark = pytest.mark.simulated


def owner_of(subject, kind="Authentication"):
    ca = make_ca()
    cert, _ = make_leaf(ca, kind=kind, subject=subject)
    info, notes = parse_certificate(cert)
    return owner_info(info, CertType(kind), notes)


def test_natural_person_with_pesel():
    o = owner_of(_name(cn="Jan Testowy", given="Jan", sn="Testowy", serial="PNOPL44051401359"))
    assert (o["kind"], o["name"], o["pesel"], o["nip"]) == ("person", "Jan Testowy", "44051401359", None)
    assert o["certificate_type"] == "Authentication" and o["source"] == "X.509 Subject"


def test_organization_with_vat_identifier():
    o = owner_of(_name(cn="Pieczęć firmy", o="Firma Sp. z o.o.", orgid="VATPL-5260250995"), kind="Offline")
    assert (o["kind"], o["name"], o["nip"], o["pesel"]) == (
        "organization",
        "Firma Sp. z o.o.",
        "5260250995",
        None,
    )
    assert o["certificate_type"] == "Offline" and o["organization"] == "Firma Sp. z o.o."


def test_person_with_tin_in_serial_number():
    o = owner_of(_name(cn="Anna Nowak", given="Anna", sn="Nowak", serial="TINPL-5260250995"))
    assert o["nip"] == "5260250995" and o["pesel"] is None


def test_incomplete_subject_has_no_invented_data():
    o = owner_of(_name())  # tylko kraj
    assert o["name"] is None and o["nip"] is None and o["pesel"] is None and o["organization"] is None
    assert o["kind"] == "unknown"


def test_common_name_is_only_a_fallback_label():
    o = owner_of(_name(cn="KSeF QA Tester (uwierzytelnienie)"))
    assert o["name"] == "KSeF QA Tester (uwierzytelnienie)" and o["nip"] is None


def test_invalid_checksum_identifier_is_not_guessed():
    o = owner_of(_name(cn="X", given="X", sn="Y", serial="PNOPL44051401350"))
    assert o["pesel"] is None and any("PESEL" in n for n in o["notes"])


def test_json_report_separates_owner_context_and_api_subject(tmp_path):
    ca = make_ca()
    cert, _ = make_leaf(ca, subject=_name(cn="Jan", given="Jan", sn="Testowy", serial="PNOPL44051401359"))
    p = tmp_path / "a.pem"
    p.write_bytes(pem(cert))
    opts = VerifyOptions(now=NOW)
    doc = json.loads(json.dumps(build_json([verify_file(p, opts)], opts, "x")))
    c = doc["files"][0]["certificates"][0] if "files" in doc else doc["certificates"][0]
    assert c["owner"]["pesel"] == "44051401359" and c["owner"]["source"] == "X.509 Subject"
    assert c["ksef_context"] is None and c["api_subject"] is None  # bez online: brak kontekstu i danych z API
