"""Zgodność wywoływanych endpointów z OpenAPI MF i brak operacji modyfikujących poza uwierzytelnieniem."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from ksef_cert_verify.ksef_api.ksef_client import ENVIRONMENTS
from ksef_cert_verify.operations import OnlineSetup, verify_with_online
from tests.integration.test_auth_flow import ACCESS_JWT, FakeKsef, auth_pair, opts, provider  # noqa: F401
from tests.integration.test_ksef_api import item_for

pytestmark = pytest.mark.simulated
SPEC = json.loads(
    (Path(__file__).resolve().parents[1] / "fixtures" / "ksef_openapi_endpoints.json").read_text(
        encoding="utf-8"
    )
)
ENDPOINTS = SPEC["endpoints"]
# jedyne dozwolone wywołania; wszystkie inne (enrollments, revoke, sessions, permissions, testdata…) są niedopuszczalne
ALLOWED = {
    ("POST", "/auth/challenge"),
    ("POST", "/auth/xades-signature"),
    ("GET", "/auth/{referenceNumber}"),
    ("POST", "/auth/token/redeem"),
    ("POST", "/certificates/query"),
}


def normalize(method: str, path: str) -> tuple[str, str]:
    if path.startswith("/auth/") and path not in (
        "/auth/challenge",
        "/auth/xades-signature",
        "/auth/token/redeem",
    ):
        path = "/auth/{referenceNumber}"
    return method.upper(), path


def test_environment_urls_match_openapi_servers():
    assert sorted(ENVIRONMENTS.values()) == sorted(SPEC["servers"])


def test_every_allowed_call_exists_in_the_official_openapi():
    for method, path in ALLOWED:
        assert method.lower() in ENDPOINTS[path], (method, path)


def test_certificate_query_requires_bearer_and_other_auth_endpoints_do_not():
    assert ENDPOINTS["/certificates/query"]["post"]["secured"] is True
    assert ENDPOINTS["/auth/challenge"]["post"]["secured"] is False
    assert ENDPOINTS["/auth/xades-signature"]["post"]["secured"] is False
    assert ENDPOINTS["/auth/token/redeem"]["post"]["secured"] is True  # Bearer = authenticationToken


def test_full_flows_call_only_documented_endpoints(auth_pair):  # noqa: F811
    ca, cert, key, c, k = auth_pair
    seen: set[tuple[str, str]] = set()
    for setup_kw in ({}, {"mode": "jwt", "jwt": ACCESS_JWT}):
        fake = FakeKsef(query_items=[item_for(cert, "Active")])
        setup = OnlineSetup("TEST", transport=httpx.MockTransport(fake), poll_interval=0, **setup_kw)
        verify_with_online(c, k, opts(ca), provider(), setup)
        seen |= {normalize(m, p) for m, p in fake.calls}
    assert (
        seen <= ALLOWED
        and ("POST", "/certificates/query") in seen
        and ("POST", "/auth/xades-signature") in seen
    )


def test_jwt_mode_is_purely_read_only(auth_pair):  # noqa: F811
    """Z gotowym JWT wykonywane jest wyłącznie odczytowe zapytanie o status (żadnych /auth/*)."""
    ca, cert, key, c, k = auth_pair
    fake = FakeKsef(query_items=[item_for(cert, "Active")])
    verify_with_online(
        c,
        k,
        opts(ca),
        provider(),
        OnlineSetup("TEST", mode="jwt", jwt=ACCESS_JWT, transport=httpx.MockTransport(fake)),
    )
    assert [normalize(m, p) for m, p in fake.calls] == [("POST", "/certificates/query")]
