"""Realne testy E2E na lokalnych certyfikatach (grupa `live_api`; domyślnie pomijane).

Wymagają zmiennych środowiskowych (nigdy argumentów ani plików w repozytorium):
  KSEF_REAL_DIR       katalog z plikami `test cert.crt/.key` i `test offline.crt/.key`
  KSEF_REAL_PASSWORD  hasło do kluczy
Uwierzytelnienie XAdES odbywa się wyłącznie na środowisku TEST (kontekst NIP z certyfikatu); PROD nie jest używany.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ksef_cert_verify.core.models import CertType, CheckStatus
from ksef_cert_verify.core.report import VerifyOptions, verify_file
from ksef_cert_verify.operations import Kod2Setup, OnlineSetup, run_kod2_test, verify_with_online

pytestmark = pytest.mark.live_api

_DIR = os.environ.get("KSEF_REAL_DIR")
_PW = os.environ.get("KSEF_REAL_PASSWORD")
if not (_DIR and _PW):
    pytest.skip("brak KSEF_REAL_DIR / KSEF_REAL_PASSWORD – realne testy pominięte", allow_module_level=True)

AUTH = (Path(_DIR) / "test cert.crt", Path(_DIR) / "test cert.key")
OFFLINE = (Path(_DIR) / "test offline.crt", Path(_DIR) / "test offline.key")


def provider(*_a):
    return _PW


@pytest.mark.parametrize("pair,kind", [(AUTH, CertType.AUTHENTICATION), (OFFLINE, CertType.OFFLINE)])
def test_local_checks_pass_for_real_pair(pair, kind):
    c = verify_file(pair[0], VerifyOptions(), provider, key_path=pair[1]).certificates[0]
    assert c.cert_type is kind
    for name in ("parsing", "validity", "key_decrypt", "key_match", "signature_test", "profile"):
        assert c.checks[name].status is CheckStatus.PASS, (name, c.checks[name].summary)
    assert c.local_result().value == "VALID"
    assert c.trust_result() in ("UNCONFIRMED", "CONFIRMED")  # bez CA – nigdy FAILED z powodu braku wystawcy


def test_wrong_password_is_reported_as_decryption_failure():
    c = verify_file(AUTH[0], VerifyOptions(), lambda *_a: "zle-haslo", key_path=AUTH[1]).certificates[0]
    assert c.local_result().value != "VALID"


def test_authentication_on_test_environment():
    report, _ = verify_with_online(
        AUTH[0], AUTH[1], VerifyOptions(), provider, OnlineSetup(environment="TEST")
    )
    c = report.certificates[0]
    auth = c.operations["authentication"]
    print("AUTH:", auth["authentication"], auth["authorization"], "| registry:", c.online_status)
    print("ONLINE:", c.checks["online"].summary)
    assert auth["authentication"] == "ACCEPTED"
    assert c.local_result().value == "VALID"  # wynik online nie zmienia wyniku lokalnego


def test_offline_certificate_kod2_signature_is_local_only():
    rep = run_kod2_test(OFFLINE[0], OFFLINE[1], VerifyOptions(), provider, Kod2Setup())
    kod = rep.certificates[0].operations["kod2"]
    assert kod["status"] == "PASS", kod
