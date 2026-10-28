"""Podpis XAdES-BES (enveloped) dokumentu AuthTokenRequest – wg struktury oficjalnej biblioteki MF (ksef-client-csharp,
`SignatureService.cs`) i `auth/podpis-xades.md`.

Kryptografia wyłącznie przez `cryptography` (RSA PKCS#1 v1.5/SHA-256 albo ECDSA P-256/SHA-256 w formacie R||S);
kanonikalizacja XML przez lxml (libxml2). Klucz prywatny jest tylko argumentem funkcji – nie jest zapisywany.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import re
import secrets
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from lxml import etree

from ksef_cert_verify.core import signing

NS_AUTH = "http://ksef.mf.gov.pl/auth/token/2.0"
NS_DS = "http://www.w3.org/2000/09/xmldsig#"
NS_XADES = "http://uri.etsi.org/01903/v1.3.2#"
ALG_C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
ALG_EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
ALG_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
ALG_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
ALG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
ALG_ECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
TYPE_SIGNED_PROPERTIES = "http://uri.etsi.org/01903#SignedProperties"

SUBJECT_TYPES = ("certificateSubject", "certificateFingerprint")
CONTEXT_TYPES = {"Nip": "Nip", "InternalId": "InternalId", "NipVatUe": "NipVatUe"}
_CHALLENGE = re.compile(r"\d{8}-CR-[A-F0-9]{10}-[A-F0-9]{10}-[A-F0-9]{2}")


def build_auth_token_request(
    challenge: str, context_type: str, context_value: str, subject_type: str = "certificateSubject"
) -> bytes:
    """Dokument AuthTokenRequest (schemat 2.0: `auth/schemy/schemat_auth_v2-0.xsd`)."""
    if not _CHALLENGE.fullmatch(challenge):
        raise ValueError(
            "Nieprawidłowy format challenge (oczekiwano np. 20250604-CR-461EA5B000-537A6BA15D-D7)"
        )
    if context_type not in CONTEXT_TYPES:
        raise ValueError(f"Typ kontekstu musi być jednym z: {', '.join(CONTEXT_TYPES)}")
    if subject_type not in SUBJECT_TYPES:
        raise ValueError(f"SubjectIdentifierType musi być jednym z: {', '.join(SUBJECT_TYPES)}")
    root = etree.Element(f"{{{NS_AUTH}}}AuthTokenRequest", nsmap={None: NS_AUTH})
    etree.SubElement(root, f"{{{NS_AUTH}}}Challenge").text = challenge
    ctx = etree.SubElement(root, f"{{{NS_AUTH}}}ContextIdentifier")
    etree.SubElement(ctx, f"{{{NS_AUTH}}}{CONTEXT_TYPES[context_type]}").text = context_value
    etree.SubElement(root, f"{{{NS_AUTH}}}SubjectIdentifierType").text = subject_type
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _c14n(el: Any, exclusive: bool) -> bytes:
    """Kanonikalizacja poddrzewa „w kontekście": lxml nie dopisuje odziedziczonych deklaracji xmlns przy c14n
    pod-elementu, więc kanonikalizujemy samodzielną kopię z kompletem przestrzeni nazw w zasięgu
    (wymóg XML-DSig – inaczej skrót/podpis nie zgadza się z liczonym przez weryfikatora)."""
    detached = copy.deepcopy(el)
    return etree.tostring(detached, method="c14n", exclusive=exclusive, with_comments=False)


def _sub(parent: Any, ns: str, tag: str, text: str | None = None, **attrs: str) -> Any:
    el = etree.SubElement(parent, f"{{{ns}}}{tag}", attrs)
    if text is not None:
        el.text = text
    return el


def _raw_sign(key: Any, data: bytes) -> tuple[str, bytes]:
    if isinstance(key, rsa.RSAPrivateKey):
        if key.key_size != 2048:
            raise ValueError("Klucz RSA musi mieć 2048 bitów")
        return ALG_RSA_SHA256, key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    if isinstance(key, ec.EllipticCurvePrivateKey):
        if key.curve.name != "secp256r1":
            raise ValueError("Klucz EC musi używać krzywej NIST P-256")
        return ALG_ECDSA_SHA256, signing.der_to_p1363(key.sign(data, ec.ECDSA(hashes.SHA256())))
    raise ValueError("Nieobsługiwany algorytm klucza (dozwolone: RSA 2048, EC P-256)")


def sign_xades(xml: bytes, cert: x509.Certificate, key: Any, signing_time: datetime | None = None) -> bytes:
    """Zwraca dokument z dołączonym podpisem XAdES-BES (enveloped)."""
    root = etree.fromstring(xml)
    sig_id, props_id = "Signature", "SignedProperties"

    # Skrót dokumentu: root BEZ podpisu (transformata enveloped) → exclusive C14N → SHA-256.
    doc_digest = _b64(hashlib.sha256(_c14n(root, True)).digest())

    sig = etree.SubElement(root, f"{{{NS_DS}}}Signature", {"Id": sig_id}, nsmap={None: NS_DS})
    signed_info = _sub(sig, NS_DS, "SignedInfo")
    _sub(signed_info, NS_DS, "CanonicalizationMethod", Algorithm=ALG_C14N)
    sig_method = _sub(signed_info, NS_DS, "SignatureMethod")
    ref1 = _sub(signed_info, NS_DS, "Reference", URI="")
    t1 = _sub(ref1, NS_DS, "Transforms")
    _sub(t1, NS_DS, "Transform", Algorithm=ALG_ENVELOPED)
    _sub(t1, NS_DS, "Transform", Algorithm=ALG_EXC_C14N)
    _sub(ref1, NS_DS, "DigestMethod", Algorithm=ALG_SHA256)
    _sub(ref1, NS_DS, "DigestValue", doc_digest)
    ref2 = _sub(signed_info, NS_DS, "Reference", URI=f"#{props_id}", Type=TYPE_SIGNED_PROPERTIES)
    t2 = _sub(ref2, NS_DS, "Transforms")
    _sub(t2, NS_DS, "Transform", Algorithm=ALG_EXC_C14N)
    _sub(ref2, NS_DS, "DigestMethod", Algorithm=ALG_SHA256)
    digest2 = _sub(ref2, NS_DS, "DigestValue", "")
    sig_value = _sub(sig, NS_DS, "SignatureValue", "")
    key_info = _sub(sig, NS_DS, "KeyInfo")
    x509_data = _sub(key_info, NS_DS, "X509Data")
    _sub(x509_data, NS_DS, "X509Certificate", _b64(cert.public_bytes(Encoding.DER)))

    obj = _sub(sig, NS_DS, "Object")
    qp = etree.SubElement(
        obj, f"{{{NS_XADES}}}QualifyingProperties", {"Target": f"#{sig_id}"}, nsmap={"xades": NS_XADES}
    )
    sp = _sub(qp, NS_XADES, "SignedProperties", Id=props_id)
    ssp = _sub(sp, NS_XADES, "SignedSignatureProperties")
    when = (signing_time or datetime.now(UTC)).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    _sub(ssp, NS_XADES, "SigningTime", when)
    sc = _sub(ssp, NS_XADES, "SigningCertificate")
    c = _sub(sc, NS_XADES, "Cert")
    cd = _sub(c, NS_XADES, "CertDigest")
    _sub(cd, NS_DS, "DigestMethod", Algorithm=ALG_SHA256)
    _sub(cd, NS_DS, "DigestValue", _b64(hashlib.sha256(cert.public_bytes(Encoding.DER)).digest()))
    iss = _sub(c, NS_XADES, "IssuerSerial")
    _sub(iss, NS_DS, "X509IssuerName", cert.issuer.rfc4514_string())
    _sub(iss, NS_DS, "X509SerialNumber", str(cert.serial_number))

    digest2.text = _b64(hashlib.sha256(_c14n(sp, True)).digest())
    alg, raw = _raw_sign(key, _c14n(signed_info, False))
    sig_method.set("Algorithm", alg)
    # Algorytm zmienia treść SignedInfo – kanonikalizujemy i podpisujemy PO ustawieniu algorytmu.
    alg, raw = _raw_sign(key, _c14n(signed_info, False))
    sig_value.text = _b64(raw)
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def new_request_id() -> str:
    return secrets.token_hex(4)
