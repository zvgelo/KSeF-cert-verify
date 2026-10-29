"""Klient API na MockTransport – bez sieci. (Testy nie łączą się z PROD ani z TEST.)"""

from __future__ import annotations

import json

import httpx
import pytest

from ksef_cert_verify.core.models import CheckStatus, Verdict
from ksef_cert_verify.core.report import VerifyOptions, verify_file
from ksef_cert_verify.core.trust_store import TrustStore
from ksef_cert_verify.ksef_api.ksef_client import ENVIRONMENTS, KsefApiClient
from tests.conftest import KEY_PASSWORD, NOW, pem, write_key

pytestmark = pytest.mark.simulated
TOKEN = "eyJ.SEKRETNY.TOKEN"
SERIAL = "018209160C631F1E"


def client(handler, env="TEST"):
    return KsefApiClient(env, TOKEN, transport=httpx.MockTransport(handler))


def item(status, typ="Authentication", serial=SERIAL):
    return {
        "certificateSerialNumber": serial,
        "name": "x",
        "type": typ,
        "commonName": "Jan",
        "status": status,
        "subjectIdentifier": {"type": "Nip", "value": "1234445678"},
        "validFrom": "2025-08-24T14:15:22+00:00",
        "validTo": "2027-08-24T14:15:22+00:00",
        "requestDate": "2025-08-24T14:15:22+00:00",
    }


def item_for(cert, status, typ="Authentication", **over):
    """Rekord API z metadanymi zgodnymi z certyfikatem (serial, daty, CN)."""
    from ksef_cert_verify.core.certificate_parser import iso, not_after, not_before, parse_certificate

    info, _ = parse_certificate(cert)
    d = item(status, typ, serial=info.serial_hex)
    d["validFrom"], d["validTo"] = iso(not_before(cert)), iso(not_after(cert))
    d["commonName"] = info.subject_info.common_name
    d["subjectIdentifier"] = {"type": "Pesel", "value": info.subject_info.pesel or "00000000000"}
    d.update(over)
    return d


def ok(items):
    return httpx.Response(200, json={"certificates": items, "hasMore": False})


@pytest.mark.parametrize("status", ["Active", "Blocked", "Revoked", "Expired"])
def test_statuses(status):
    seen = {}

    def h(req: httpx.Request):
        seen["url"] = str(req.url)
        seen["method"] = req.method
        seen["auth"] = req.headers["authorization"]
        seen["body"] = json.loads(req.content)
        return ok([item(status)])

    out = client(h).lookup(SERIAL)
    assert out.status == status
    assert seen["method"] == "POST" and seen["url"].startswith(ENVIRONMENTS["TEST"] + "/certificates/query")
    assert seen["body"] == {"certificateSerialNumber": SERIAL}
    assert seen["auth"] == f"Bearer {TOKEN}"


def test_environments_urls():
    assert ENVIRONMENTS == {
        "TEST": "https://api-test.ksef.mf.gov.pl/v2",
        "DEMO": "https://api-demo.ksef.mf.gov.pl/v2",
        "PROD": "https://api.ksef.mf.gov.pl/v2",
    }


def test_unknown_environment_rejected():
    with pytest.raises(ValueError):
        KsefApiClient("LOCAL", TOKEN)


def test_empty_result_is_not_found_not_revoked():
    out = client(lambda r: ok([])).lookup(SERIAL)
    assert out.status == "NOT_FOUND" and "właściciela" in out.message


@pytest.mark.parametrize(
    "code,fragment", [(401, "401"), (403, "403"), (400, "400"), (500, "500"), (418, "418")]
)
def test_http_errors(code, fragment):
    out = client(lambda r: httpx.Response(code, json={})).lookup(SERIAL)
    assert out.status == "UNKNOWN" and fragment in out.message


def test_rate_limit_retry_after():
    out = client(lambda r: httpx.Response(429, headers={"Retry-After": "30"}, json={})).lookup(SERIAL)
    assert out.status == "UNKNOWN" and "30" in out.message


def test_timeout_and_network_errors():
    def timeout(r):
        raise httpx.ReadTimeout("t", request=r)

    def conn(r):
        raise httpx.ConnectError("c", request=r)

    assert "czas" in client(timeout).lookup(SERIAL).message
    assert "połączenia" in client(conn).lookup(SERIAL).message


def test_malformed_body():
    assert client(lambda r: httpx.Response(200, text="<html>")).lookup(SERIAL).status == "UNKNOWN"
    assert client(lambda r: httpx.Response(200, json={"x": 1})).lookup(SERIAL).status == "UNKNOWN"
    assert client(lambda r: ok([item("Weird")])).lookup(SERIAL).status == "UNKNOWN"


def test_token_never_leaks():
    c = client(lambda r: httpx.Response(401, json={"detail": TOKEN}))
    out = c.lookup(SERIAL)
    assert TOKEN not in out.message and TOKEN not in repr(c)


def test_other_serial_in_response_is_ignored():
    assert (
        client(lambda r: ok([item("Active", serial="FFFFFFFFFFFFFFFF")])).lookup(SERIAL).status == "NOT_FOUND"
    )


def _opts(ca, c):
    t = TrustStore()
    t.add(ca.cert, "t")
    return VerifyOptions(trust=t, now=NOW, online=c, online_environment="TEST")


@pytest.mark.parametrize(
    "status,verdict",
    [
        ("Active", Verdict.VALID),
        ("Revoked", Verdict.INVALID),
        ("Blocked", Verdict.INVALID),
        ("Expired", Verdict.INVALID),
    ],
)
def test_online_status_in_engine(tmp_path, ca, auth_cert, status, verdict):
    p = tmp_path / "a.pem"
    p.write_bytes(pem(auth_cert[0]))
    kp = write_key(tmp_path / "a.key", auth_cert[1])
    r = verify_file(
        p,
        _opts(ca, client(lambda req: ok([item_for(auth_cert[0], status)]))),
        lambda *_a: KEY_PASSWORD,
        key_path=kp,
    )
    assert r.certificates[0].verdict is verdict and r.certificates[0].online_status == status


def test_online_failure_is_indeterminate_never_valid(tmp_path, ca, auth_cert):
    p = tmp_path / "a.pem"
    p.write_bytes(pem(auth_cert[0]))
    kp = write_key(tmp_path / "a.key", auth_cert[1])
    r = verify_file(
        p, _opts(ca, client(lambda req: httpx.Response(401, json={}))), lambda *_a: KEY_PASSWORD, key_path=kp
    )
    c = r.certificates[0]
    assert c.checks["online"].status is CheckStatus.UNKNOWN and c.verdict is Verdict.INDETERMINATE


def test_online_type_mismatch_fails(tmp_path, ca, auth_cert):
    p = tmp_path / "a.pem"
    p.write_bytes(pem(auth_cert[0]))
    kp = write_key(tmp_path / "a.key", auth_cert[1])
    r = verify_file(
        p,
        _opts(ca, client(lambda req: ok([item_for(auth_cert[0], "Active", typ="Offline")]))),
        lambda *_a: KEY_PASSWORD,
        key_path=kp,
    )
    assert r.certificates[0].verdict is Verdict.INVALID


def test_no_network_by_default(tmp_path, ca, auth_cert, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("połączenie sieciowe bez żądania --online")

    monkeypatch.setattr(httpx.Client, "send", boom)
    p = tmp_path / "a.pem"
    p.write_bytes(pem(auth_cert[0]))
    t = TrustStore()
    t.add(ca.cert, "t")
    r = verify_file(p, VerifyOptions(trust=t, now=NOW))
    assert r.certificates[0].online_status == "NOT_CHECKED"


@pytest.mark.parametrize(
    "over,fragment",
    [
        ({"validTo": "2031-01-01T00:00:00+00:00"}, "ważny do"),
        ({"validFrom": "2020-01-01T00:00:00+00:00"}, "ważny od"),
        ({"subjectIdentifier": {"type": "Pesel", "value": "11111111111"}}, "PESEL"),
    ],
)
def test_http_200_with_mismatched_metadata_is_not_active(tmp_path, ca, auth_cert, over, fragment):
    """HTTP 200 + zgodny numer seryjny NIE wystarcza: niezgodne metadane → UNKNOWN, nigdy Active/VALID."""
    p = tmp_path / "a.pem"
    p.write_bytes(pem(auth_cert[0]))
    kp = write_key(tmp_path / "a.key", auth_cert[1])
    r = verify_file(
        p,
        _opts(ca, client(lambda req: ok([item_for(auth_cert[0], "Active", **over)]))),
        lambda *_a: KEY_PASSWORD,
        key_path=kp,
    )
    c = r.certificates[0]
    assert c.online_status == "UNKNOWN" and c.verdict is Verdict.INDETERMINATE
    assert fragment in c.checks["online"].summary


def test_matching_metadata_reports_active_with_reasons(tmp_path, ca, auth_cert):
    p = tmp_path / "a.pem"
    p.write_bytes(pem(auth_cert[0]))
    kp = write_key(tmp_path / "a.key", auth_cert[1])
    r = verify_file(
        p,
        _opts(ca, client(lambda req: ok([item_for(auth_cert[0], "Active")]))),
        lambda *_a: KEY_PASSWORD,
        key_path=kp,
    )
    c = r.certificates[0]
    assert (
        c.online_status == "Active"
        and c.checks["online"].code == "KSEF_ACTIVE"
        and c.verdict is Verdict.VALID
    )


def _run(tmp_path, ca, auth_cert, handler):
    p = tmp_path / "a.pem"
    p.write_bytes(pem(auth_cert[0]))
    kp = write_key(tmp_path / "a.key", auth_cert[1])
    r = verify_file(p, _opts(ca, client(handler)), lambda *_a: KEY_PASSWORD, key_path=kp)
    return r.certificates[0]


def test_different_common_name_does_not_block_match(tmp_path, ca, auth_cert):
    """commonName/nazwa własna z rejestru to nie identyfikator: serial+typ+terminy wystarczają, CN → tylko uwaga."""
    c = _run(
        tmp_path,
        ca,
        auth_cert,
        lambda r: ok([item_for(auth_cert[0], "Active", commonName="Ktoś Inny", name="Moja")]),
    )
    assert c.online_status == "Active" and c.verdict is Verdict.VALID
    codes = {f.code: f for f in c.checks["online"].findings}
    assert codes["ONLINE_CN_DIFFERS"].status is CheckStatus.WARNING
    assert "Moja" in codes["ONLINE_CN_DIFFERS"].message


def test_serial_is_normalized_to_16_hex_and_pages_are_followed(tmp_path, ca, auth_cert):
    from ksef_cert_verify.core.certificate_parser import api_serial

    serial = api_serial(auth_cert[0])
    assert serial and len(serial) == 16 and serial == serial.upper()
    seen = []

    def h(req):
        seen.append((req.url.params["pageOffset"], json.loads(req.content)))
        if len(seen) == 1:
            return httpx.Response(
                200, json={"certificates": [item("Active", serial="FFFFFFFFFFFFFFFF")], "hasMore": True}
            )
        return ok([item_for(auth_cert[0], "Active")])

    c = _run(tmp_path, ca, auth_cert, h)
    assert [x[0] for x in seen] == ["0", "1"] and all(
        x[1] == {"certificateSerialNumber": serial} for x in seen
    )
    assert c.online_status == "Active"


def test_pagination_is_bounded():
    n = []

    def h(req):
        n.append(1)
        return httpx.Response(200, json={"certificates": [], "hasMore": True})

    out = client(h).lookup(SERIAL)
    assert len(n) == 5 and out.status == "UNKNOWN"


def test_der_mismatch_means_other_certificate_not_error(tmp_path, ca, auth_cert, no_such=None):
    import base64

    def h(req):
        if req.url.path.endswith("/retrieve"):
            return httpx.Response(
                200,
                json={
                    "certificates": [
                        {
                            "certificate": base64.b64encode(b"inny").decode(),
                            "certificateName": "x",
                            "certificateSerialNumber": item_for(auth_cert[0], "Active")[
                                "certificateSerialNumber"
                            ],
                            "certificateType": "Authentication",
                        }
                    ]
                },
            )
        return ok([item_for(auth_cert[0], "Active", validTo="2031-01-01T00:00:00+00:00")])

    c = _run(tmp_path, ca, auth_cert, h)
    assert c.online_status == "UNKNOWN" and c.verdict is Verdict.INDETERMINATE
    assert "nie da się go przypisać" in c.checks["online"].summary


def test_der_match_confirms_status_despite_metadata_gap(tmp_path, ca, auth_cert):
    import base64

    from cryptography.hazmat.primitives.serialization import Encoding

    der = auth_cert[0].public_bytes(Encoding.DER)

    def h(req):
        if req.url.path.endswith("/retrieve"):
            return httpx.Response(
                200,
                json={
                    "certificates": [
                        {
                            "certificate": base64.b64encode(der).decode(),
                            "certificateName": "x",
                            "certificateSerialNumber": item_for(auth_cert[0], "Active")[
                                "certificateSerialNumber"
                            ],
                            "certificateType": "Authentication",
                        }
                    ]
                },
            )
        return ok([item_for(auth_cert[0], "Revoked", validTo="2031-01-01T00:00:00+00:00")])

    c = _run(tmp_path, ca, auth_cert, h)
    assert c.online_status == "Revoked" and c.verdict is Verdict.INVALID


def test_not_in_registry_for_non_ksef_issuer_is_not_applicable(tmp_path, ca, auth_cert):
    c = _run(tmp_path, ca, auth_cert, lambda r: ok([]))
    assert c.online_status == "NOT_APPLICABLE" and c.checks["online"].status is CheckStatus.NOT_CHECKED
    assert "oczekiwany" in c.checks["online"].summary


def test_not_in_registry_for_ksef_issuer_is_not_found_not_error(tmp_path):
    from tests.conftest import make_ca, make_leaf

    kca = make_ca("TEST CCK KSeF")
    cert, key = make_leaf(kca)
    p = tmp_path / "a.pem"
    p.write_bytes(pem(cert))
    kp = write_key(tmp_path / "a.key", key)
    r = verify_file(p, _opts(kca, client(lambda r: ok([]))), lambda *_a: KEY_PASSWORD, key_path=kp)
    c = r.certificates[0]
    assert c.online_status == "NOT_FOUND" and c.checks["online"].status is not CheckStatus.FAIL


def test_registry_access_denied_is_unknown_and_authorization_denied():
    out = client(lambda r: httpx.Response(403, json={})).lookup(SERIAL)
    assert out.status == "UNKNOWN" and out.authorization == "DENIED"
