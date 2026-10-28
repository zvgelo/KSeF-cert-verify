"""Uwierzytelnienie XAdES z MOCKOWANYM API (bez sieci), JWT, sesja online, izolacja sekretów. Dane SYNTETYCZNE."""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from lxml import etree

from ksef_cert_verify.core.models import Verdict
from ksef_cert_verify.core.report import VerifyOptions
from ksef_cert_verify.core.trust_store import TrustStore
from ksef_cert_verify.ksef_api import xades
from ksef_cert_verify.ksef_api.jwt_utils import inspect_jwt
from ksef_cert_verify.operations import OnlineSetup, establish_online, verify_with_online
from tests.conftest import KEY_PASSWORD, NOW, _name, make_ca, make_leaf, pem, write_key

pytestmark = pytest.mark.simulated

CHALLENGE = "20250604-CR-461EA5B000-537A6BA15D-D7"
REF = "20250625-AU-2DFC46C000-3AC6B8538D-D4"
AUTH_TOKEN = "AUTHENTICATION-TOKEN-SECRET"
NIP = "1234563218"


def make_jwt(exp_offset: float, extra: dict | None = None) -> str:
    def b(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    return f"{b({'alg': 'RS256', 'typ': 'JWT'})}.{b({'exp': int(time.time() + exp_offset), **(extra or {})})}.c2lnbmF0dXJl"


ACCESS_JWT = make_jwt(900)


class FakeKsef:
    """Mock API KSeF: /auth/* + /certificates/query. Rejestruje wywołania (bez wartości tokenów w asercjach logów)."""

    def __init__(
        self,
        statuses=(100, 200),
        challenge_status=200,
        submit_status=202,
        submit_body=None,
        query_items=None,
        query_status=200,
        raise_on=None,
    ):
        self.statuses = list(statuses)
        self.calls: list[tuple[str, str]] = []
        self.headers: list[dict] = []
        self.submitted: bytes | None = None
        self.challenge_status, self.submit_status, self.submit_body = (
            challenge_status,
            submit_status,
            submit_body,
        )
        self.query_items, self.query_status, self.raise_on = query_items or [], query_status, raise_on

    def __call__(self, req: httpx.Request) -> httpx.Response:
        path = req.url.path.removeprefix("/v2")
        self.calls.append((req.method, path))
        self.headers.append(dict(req.headers))
        if self.raise_on == path:
            raise httpx.ReadTimeout("t", request=req)
        if path == "/auth/challenge":
            if self.challenge_status != 200:
                return httpx.Response(self.challenge_status, json={})
            return httpx.Response(
                200,
                json={
                    "challenge": CHALLENGE,
                    "timestamp": "2026-10-28T12:00:00+00:00",
                    "timestampMs": 1,
                    "clientIp": "127.0.0.1",
                },
            )
        if path == "/auth/xades-signature":
            self.submitted = req.content
            if self.submit_status != 202:
                return httpx.Response(self.submit_status, json=self.submit_body or {})
            return httpx.Response(
                202,
                json={
                    "referenceNumber": REF,
                    "authenticationToken": {"token": AUTH_TOKEN, "validUntil": "2026-10-28T13:00:00+00:00"},
                },
            )
        if path == f"/auth/{REF}":
            code = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
            det = {415: ["Brak przypisanych uprawnień"], 460: ["Niezaufany łańcuch certyfikatów"]}.get(code)
            return httpx.Response(
                200,
                json={
                    "startDate": "2026-10-28T12:00:00+00:00",
                    "authenticationMethod": "XadesSignature",
                    "status": {"code": code, "description": "x", **({"details": det} if det else {})},
                },
            )
        if path == "/auth/token/redeem":
            return httpx.Response(
                200,
                json={
                    "accessToken": {"token": ACCESS_JWT, "validUntil": "2026-10-28T12:15:00+00:00"},
                    "refreshToken": {"token": "REFRESH-SECRET", "validUntil": "2026-11-04T12:00:00+00:00"},
                },
            )
        if path == "/certificates/query":
            return httpx.Response(
                self.query_status, json={"certificates": self.query_items, "hasMore": False}
            )
        return httpx.Response(404, json={})


@pytest.fixture
def auth_pair(tmp_path):
    """Certyfikat Authentication z NIP (PEM) + zaszyfrowany klucz; CA jako kotwica zaufania."""
    ca = make_ca()
    key = ec.generate_private_key(ec.SECP256R1())
    subject = _name(cn="Jan Testowy", given="Jan", sn="Testowy", serial=f"TINPL{NIP}")
    cert, _ = make_leaf(ca, kind="Authentication", subject=subject, key=key)
    c, k = tmp_path / "c.crt", write_key(tmp_path / "c.key", key)
    c.write_bytes(pem(cert))
    return ca, cert, key, c, k


def setup(fake, **kw):
    return OnlineSetup(
        environment=kw.pop("environment", "TEST"), transport=httpx.MockTransport(fake), poll_interval=0, **kw
    )


def provider(pw=KEY_PASSWORD):
    return lambda path, retry: None if retry else pw


def opts(ca):
    t = TrustStore()
    t.add(ca.cert, "t")
    return VerifyOptions(trust=t, now=NOW)


# ------------------------------------------------------------------ XAdES: struktura i kryptografia
def xml_roundtrip_valid(signed: bytes, cert):
    """Niezależna weryfikacja podpisu biblioteką signxml (nie naszym kodem)."""
    signxml = pytest.importorskip("signxml")
    from cryptography.hazmat.primitives.serialization import Encoding

    verifier = signxml.XMLVerifier()
    # libxml2 przy c14n 1.0 poddrzewa dopisuje fałszywe `xmlns=""` – signxml ma na to oficjalną opcję
    # (zob. signxml issue #193); po jej włączeniu kanonikalizacja jest zgodna z XML-DSig/.NET.
    verifier.excise_empty_xmlns_declarations = True
    return verifier.verify(
        signed, x509_cert=cert.public_bytes(Encoding.PEM).decode(), expect_references=2, id_attribute="Id"
    )


@pytest.mark.parametrize("kind", ["ec", "rsa"])
def test_xades_signature_verified_by_independent_library(kind):
    ca = make_ca()
    key = ec.generate_private_key(ec.SECP256R1()) if kind == "ec" else rsa.generate_private_key(65537, 2048)
    cert, _ = make_leaf(ca, key=key)
    req = xades.build_auth_token_request(CHALLENGE, "Nip", NIP)
    signed = xades.sign_xades(req, cert, key)
    result = xml_roundtrip_valid(signed, cert)
    assert result is not None
    # struktura zgodna z oficjalnym przykładem (C#): Signature w AuthTokenRequest, QualifyingProperties, SignedProperties
    root = etree.fromstring(signed)
    ns = {"ds": xades.NS_DS, "xades": xades.NS_XADES, "a": xades.NS_AUTH}
    assert root.tag == f"{{{xades.NS_AUTH}}}AuthTokenRequest"
    assert root.find("ds:Signature", ns) is not None
    assert root.find(".//xades:SignedProperties[@Id='SignedProperties']", ns) is not None
    assert root.find(".//ds:X509Certificate", ns) is not None
    assert root.findtext("a:Challenge", namespaces=ns) == CHALLENGE


def test_xades_tampered_document_fails_independent_verification():
    signxml = pytest.importorskip("signxml")
    ca = make_ca()
    key = ec.generate_private_key(ec.SECP256R1())
    cert, _ = make_leaf(ca, key=key)
    signed = xades.sign_xades(xades.build_auth_token_request(CHALLENGE, "Nip", NIP), cert, key)
    with pytest.raises(signxml.exceptions.InvalidDigest):
        xml_roundtrip_valid(signed.replace(NIP.encode(), b"1111111111"), cert)


def test_auth_request_validation():
    with pytest.raises(ValueError):
        xades.build_auth_token_request("zly-challenge", "Nip", NIP)
    with pytest.raises(ValueError):
        xades.build_auth_token_request(CHALLENGE, "Zly", NIP)
    with pytest.raises(ValueError):
        xades.build_auth_token_request(CHALLENGE, "Nip", NIP, "inny")
    assert b"certificateFingerprint" in xades.build_auth_token_request(
        CHALLENGE, "Nip", NIP, "certificateFingerprint"
    )


# ------------------------------------------------------------------ automatyczny przebieg
def test_auto_auth_full_flow_and_access_token_used_for_query(auth_pair):
    ca, cert, key, c, k = auth_pair
    from tests.integration.test_ksef_api import item_for

    fake = FakeKsef(query_items=[item_for(cert, "Active")])
    report, session = verify_with_online(c, k, opts(ca), provider(), setup(fake))
    steps = [p for _, p in fake.calls]
    assert steps[:2] == ["/auth/challenge", "/auth/xades-signature"] and "/auth/token/redeem" in steps
    assert (
        steps.index(f"/auth/{REF}") < steps.index("/auth/token/redeem") < steps.index("/certificates/query")
    )
    # nagłówki: status z authenticationToken, zapytanie o certyfikat z accessToken (JWT)
    status_hdr = fake.headers[[i for i, (_, p) in enumerate(fake.calls) if p == f"/auth/{REF}"][0]]
    query_hdr = fake.headers[[i for i, (_, p) in enumerate(fake.calls) if p == "/certificates/query"][0]]
    assert status_hdr["authorization"] == f"Bearer {AUTH_TOKEN}"
    assert query_hdr["authorization"] == f"Bearer {ACCESS_JWT}"
    assert fake.submitted is not None and xml_roundtrip_valid(fake.submitted, cert) is not None
    cr = report.certificates[0]
    assert cr.online_status == "Active" and cr.verdict is Verdict.VALID
    auth = cr.operations["authentication"]
    assert (
        auth["code"] == "AUTH_SUCCESS"
        and auth["authentication"] == "ACCEPTED"
        and auth["authorization"] == "GRANTED"
    )
    assert session.auth.access_token == ACCESS_JWT  # tylko w pamięci


def test_context_defaults_to_nip_from_certificate(auth_pair):
    ca, cert, key, c, k = auth_pair
    fake = FakeKsef()
    establish_online(c, k, provider(), setup(fake)).client.close()
    assert f"<Nip>{NIP}</Nip>".encode() in fake.submitted


def test_context_required_when_cert_has_no_nip(tmp_path):
    ca = make_ca()
    key = ec.generate_private_key(ec.SECP256R1())
    cert, _ = make_leaf(ca, key=key, subject=_name(cn="Bez NIP", given="A", sn="B", serial="XYZ"))
    c, k = tmp_path / "c.crt", write_key(tmp_path / "c.key", key)
    c.write_bytes(pem(cert))
    fake = FakeKsef()
    s = establish_online(c, k, provider(), setup(fake))
    assert s.auth.code == "AUTH_CONTEXT_REQUIRED" and fake.calls == []
    s2 = establish_online(c, k, provider(), setup(fake, context_value=NIP))
    assert s2.auth.code == "AUTH_SUCCESS"
    s2.client.close()


# ------------------------------------------------------------------ błędy i uprawnienia
def test_no_permissions_is_authorization_not_key_failure(auth_pair):
    ca, cert, key, c, k = auth_pair
    report, session = verify_with_online(c, k, opts(ca), provider(), setup(FakeKsef(statuses=[100, 415])))
    a = report.certificates[0].operations["authentication"]
    assert (
        a["code"] == "AUTH_NO_PERMISSIONS"
        and a["authorization"] == "DENIED"
        and "nie dowodzi" in a["message"]
    )
    cr = report.certificates[0]
    assert cr.local_result() is Verdict.VALID  # lokalny zestaw cert+key nie jest dotknięty
    assert cr.online_status == "UNKNOWN" and cr.verdict is Verdict.INDETERMINATE


def test_certificate_rejected_460(auth_pair):
    ca, cert, key, c, k = auth_pair
    s = establish_online(c, k, provider(), setup(FakeKsef(statuses=[460])))
    assert s.auth.code == "AUTH_CERT_REJECTED" and s.auth.authentication == "REJECTED" and s.client is None
    assert "Niezaufany łańcuch" in s.auth.message


def test_400_invalid_certificate_and_context(auth_pair):
    ca, cert, key, c, k = auth_pair
    body = lambda code: {"exception": {"exceptionDetailList": [{"exceptionCode": code}]}}  # noqa: E731
    assert (
        establish_online(
            c, k, provider(), setup(FakeKsef(submit_status=400, submit_body=body(21115)))
        ).auth.code
        == "AUTH_CERT_REJECTED"
    )
    assert (
        establish_online(
            c, k, provider(), setup(FakeKsef(submit_status=400, submit_body=body(21117)))
        ).auth.code
        == "AUTH_CONTEXT_INVALID"
    )
    assert (
        establish_online(
            c, k, provider(), setup(FakeKsef(submit_status=400, submit_body=body(21401)))
        ).auth.code
        == "AUTH_REQUEST_INVALID"
    )


def test_timeout_and_network_and_tls_errors(auth_pair, monkeypatch):
    ca, cert, key, c, k = auth_pair
    assert (
        establish_online(c, k, provider(), setup(FakeKsef(raise_on="/auth/challenge"))).auth.code
        == "AUTH_TIMEOUT"
    )
    assert (
        establish_online(c, k, provider(), setup(FakeKsef(raise_on="/auth/xades-signature"))).auth.code
        == "AUTH_TIMEOUT"
    )

    import ssl

    def tls(req):
        err = httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed", request=req)
        err.__cause__ = ssl.SSLCertVerificationError("bad")
        raise err

    s = establish_online(c, k, provider(), OnlineSetup("TEST", transport=httpx.MockTransport(tls)))
    assert s.auth.code == "AUTH_TLS" and "nie jest wyłączana" in s.auth.message

    def refused(req):
        raise httpx.ConnectError("refused", request=req)

    assert (
        establish_online(
            c, k, provider(), OnlineSetup("TEST", transport=httpx.MockTransport(refused))
        ).auth.code
        == "AUTH_NETWORK"
    )


def test_rate_limit_and_server_errors(auth_pair):
    ca, cert, key, c, k = auth_pair
    assert (
        establish_online(c, k, provider(), setup(FakeKsef(challenge_status=429))).auth.code
        == "AUTH_CHALLENGE_FAILED"
    )
    assert establish_online(c, k, provider(), setup(FakeKsef(submit_status=500))).auth.code == "AUTH_SERVER"
    assert (
        establish_online(c, k, provider(), setup(FakeKsef(submit_status=403))).auth.code == "AUTH_FORBIDDEN"
    )


def test_poll_timeout_is_unknown(auth_pair):
    ca, cert, key, c, k = auth_pair
    s = establish_online(
        c,
        k,
        provider(),
        OnlineSetup(
            "TEST",
            transport=httpx.MockTransport(FakeKsef(statuses=[100])),
            poll_timeout=0.05,
            poll_interval=0.01,
        ),
    )
    assert s.auth.code == "AUTH_IN_PROGRESS_TIMEOUT" and s.auth.authentication == "UNKNOWN"


def test_wrong_password_no_request_is_submitted(auth_pair):
    ca, cert, key, c, k = auth_pair
    fake = FakeKsef()
    s = establish_online(c, k, provider("zle-haslo"), setup(fake))
    assert s.auth.code == "AUTH_SIGNING_FAILED" and fake.submitted is None
    assert "zle-haslo" not in json.dumps(s.auth.to_dict())


def test_key_of_another_certificate_is_not_used_for_signing(auth_pair, tmp_path):
    ca, cert, key, c, k = auth_pair
    other = write_key(tmp_path / "inny.key", ec.generate_private_key(ec.SECP256R1()))
    fake = FakeKsef()
    s = establish_online(c, other, provider(), setup(fake))
    assert s.auth.code == "AUTH_SIGNING_FAILED" and "nie pasuje" in s.auth.message and fake.submitted is None


# ------------------------------------------------------------------ PROD i certyfikat Offline
def test_prod_requires_explicit_confirmation_and_makes_no_calls(auth_pair):
    ca, cert, key, c, k = auth_pair
    fake = FakeKsef()
    s = establish_online(c, k, provider(), setup(fake, environment="PROD"))
    assert s.auth.code == "AUTH_PROD_NOT_CONFIRMED" and fake.calls == []
    s2 = establish_online(c, k, provider(), setup(fake, environment="prod", allow_prod=True))
    assert fake.calls and s2.client is not None
    s2.client.close()


def test_offline_certificate_cannot_authenticate(tmp_path):
    ca = make_ca()
    key = ec.generate_private_key(ec.SECP256R1())
    cert, _ = make_leaf(
        ca, kind="Offline", key=key, subject=_name(cn="J", given="J", sn="K", serial=f"TINPL{NIP}")
    )
    c, k = tmp_path / "o.crt", write_key(tmp_path / "o.key", key)
    c.write_bytes(pem(cert))
    fake = FakeKsef()
    s = establish_online(c, k, provider(), setup(fake))
    assert s.auth.code == "AUTH_NOT_APPLICABLE" and fake.calls == [] and "Offline" in s.auth.message


# ------------------------------------------------------------------ JWT
def test_jwt_inspection_structure_and_expiry():
    assert inspect_jwt(ACCESS_JWT).usable
    assert inspect_jwt("Bearer " + ACCESS_JWT).usable
    for bad in ("", "abc", "a.b", "a.b.c.d", "###.###.###", "e30.nie-json.x"):
        assert not inspect_jwt(bad).structure_ok, bad
    exp = inspect_jwt(make_jwt(-60))
    assert exp.structure_ok and exp.expired and not exp.usable
    noexp = inspect_jwt(
        make_jwt(0).replace(
            make_jwt(0).split(".")[1], base64.urlsafe_b64encode(b'{"a":1}').rstrip(b"=").decode()
        )
    )
    assert noexp.structure_ok and noexp.expired is None and not noexp.usable


def test_existing_jwt_used_for_query_without_authentication(auth_pair):
    ca, cert, key, c, k = auth_pair
    from tests.integration.test_ksef_api import item_for

    fake = FakeKsef(query_items=[item_for(cert, "Revoked")])
    report, _ = verify_with_online(c, None, opts(ca), provider(), setup(fake, mode="jwt", jwt=ACCESS_JWT))
    assert [p for _, p in fake.calls] == ["/certificates/query"]  # bez /auth/*
    assert fake.headers[0]["authorization"] == f"Bearer {ACCESS_JWT}"
    assert report.certificates[0].online_status == "Revoked"


@pytest.mark.parametrize("token,code", [("to-nie-jwt", "JWT_INVALID"), (make_jwt(-5), "JWT_EXPIRED")])
def test_bad_or_expired_jwt_rejected_before_any_request(auth_pair, token, code):
    ca, cert, key, c, k = auth_pair
    fake = FakeKsef()
    s = establish_online(c, k, provider(), setup(fake, mode="jwt", jwt=token))
    assert s.auth.code == code and fake.calls == [] and s.client is None


def test_jwt_inspection_does_not_claim_authenticity():
    from ksef_cert_verify.ksef_api.jwt_utils import describe

    assert "NIE została potwierdzona" in describe(inspect_jwt(ACCESS_JWT))


# ------------------------------------------------------------------ rozdzielenie LOCAL / TRUST / ONLINE
def test_groups_are_independent_online_failure_does_not_change_local(auth_pair):
    ca, cert, key, c, k = auth_pair
    from tests.integration.test_ksef_api import item_for

    fake = FakeKsef(query_items=[item_for(cert, "Revoked")])
    r, _ = verify_with_online(c, k, opts(ca), provider(), setup(fake))
    cr = r.certificates[0]
    d = cr.to_dict()
    assert d["groups"]["local"]["result"] == "VALID" and d["groups"]["trust"]["result"] == "CONFIRMED"
    assert d["groups"]["online"]["result"] == "Revoked"
    assert d["summary"]["LOCAL_KEYSET_RESULT"] == "VALID" and d["summary"]["KSEF_ONLINE_STATUS"] == "Revoked"
    assert cr.verdict is Verdict.INVALID  # ogólny wynik uwzględnia online, ale grupa LOCAL pozostaje VALID


def test_local_success_with_unconfirmed_trust_is_never_full_valid(auth_pair):
    ca, cert, key, c, k = auth_pair
    from ksef_cert_verify.core.report import verify_file

    r = verify_file(c, VerifyOptions(now=NOW), provider(), key_path=k)  # brak zaufanych CA
    cr = r.certificates[0]
    assert cr.local_result() is Verdict.VALID  # zestaw cert+key+hasło poprawny
    assert cr.trust_result() == "UNCONFIRMED"
    assert cr.verdict is Verdict.INDETERMINATE  # pełna walidacja NIE jest VALID
    assert cr.summary()["LOCAL_RESULT"] == "INDETERMINATE"


def test_trust_failure_is_separate_from_local(auth_pair):
    ca, cert, key, c, k = auth_pair
    from ksef_cert_verify.core.report import verify_file

    other = TrustStore()
    other.add(make_ca("Inny CA").cert, "x")
    # liść wystawiony przez `ca`, plik zawiera CA `ca` jako kandydata, ale kotwicą jest inny CA
    c.write_bytes(pem(cert, ca.cert))
    r = verify_file(c, VerifyOptions(trust=other, now=NOW), provider(), key_path=k)
    cr = r.certificates[0]
    assert (
        cr.local_result() is Verdict.VALID and cr.trust_result() == "FAILED" and cr.verdict is Verdict.INVALID
    )


# ------------------------------------------------------------------ izolacja sekretów
def test_tokens_and_passwords_never_in_results_logs_or_repr(auth_pair, caplog):
    ca, cert, key, c, k = auth_pair
    from tests.integration.test_ksef_api import item_for

    caplog.set_level("DEBUG")
    fake = FakeKsef(query_items=[item_for(cert, "Active")])
    report, session = verify_with_online(c, k, opts(ca), provider(), setup(fake))
    from ksef_cert_verify.core.report import build_json, dumps

    blob = (
        dumps(build_json([report], opts(ca), "x"))
        + repr(session)
        + repr(session.auth)
        + caplog.text
        + repr(session.client)
    )
    for secret in (ACCESS_JWT, AUTH_TOKEN, "REFRESH-SECRET", KEY_PASSWORD):
        assert secret not in blob, secret[:6]
    assert Path(str(c)).exists()  # sanity
