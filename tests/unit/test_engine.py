"""Testy silnika (fixtury SYMULOWANE – nie są certyfikatami KSeF)."""

from __future__ import annotations

import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from ksef_cert_verify.core.certificate_parser import parse_subject, valid_nip, valid_pesel
from ksef_cert_verify.core.certificate_validator import VerifyContext, verify_certificate
from ksef_cert_verify.core.models import CertType, Check, CheckStatus, Verdict
from ksef_cert_verify.core.private_key import _active_signature_test, spki_of_certificate
from ksef_cert_verify.core.trust_store import TrustStore
from tests.conftest import KEYS, NOW, _name, make_ca, make_leaf

pytestmark = pytest.mark.simulated

P, F, W, U, N = (
    CheckStatus.PASS,
    CheckStatus.FAIL,
    CheckStatus.WARNING,
    CheckStatus.UNKNOWN,
    CheckStatus.NOT_CHECKED,
)


def run(cert, *anchors, candidates=(), expected=None, now=NOW, with_key=True):
    """Reguły na poziomie certyfikatu. `with_key=True` modeluje poprawnie zweryfikowaną parę kluczy
    (właściwa kontrola klucza jest testowana w test_private_key.py)."""
    store = TrustStore()
    for a in anchors:
        store.add(a.cert, "test")
    ctx = VerifyContext(now=now, trust=store, expected_type=expected, candidates=list(candidates))
    key = KEYS.get(spki_of_certificate(cert))
    if with_key and key is not None:
        ctx.key_decrypt = Check("key_decrypt", CheckStatus.PASS, "model testowy")
        ctx.key_spki = spki_of_certificate(cert)
        ctx.signature = _active_signature_test(key)  # prawdziwy podpis testowy
        ctx.inputs = Check("inputs", CheckStatus.PASS, "model testowy")
    return verify_certificate(cert, ctx)


def test_valid_authentication(ca, auth_cert):
    r = run(auth_cert[0], ca)
    assert r.cert_type is CertType.AUTHENTICATION
    assert r.verdict is Verdict.VALID, {k: (v.status, v.summary) for k, v in r.checks.items()}
    assert r.checks["online"].status is N and r.online_status == "NOT_CHECKED"
    assert r.info.subject_info.pesel == "44051401359"


def test_valid_offline(ca, offline_cert):
    r = run(offline_cert[0], ca)
    assert r.cert_type is CertType.OFFLINE
    assert r.verdict is Verdict.VALID


def test_no_anchors_is_indeterminate_not_valid(auth_cert):
    r = run(auth_cert[0])
    assert r.checks["trust"].status is N
    assert r.verdict is Verdict.INDETERMINATE


def test_not_yet_valid(ca):
    cert, _ = make_leaf(ca, not_before=NOW + dt.timedelta(days=5))
    r = run(cert, ca)
    assert r.checks["validity"].status is F and r.verdict is Verdict.INVALID


def test_expired(ca):
    cert, _ = make_leaf(ca, not_before=NOW - dt.timedelta(days=400))
    r = run(cert, ca)
    assert r.checks["validity"].status is F and r.verdict is Verdict.INVALID


@pytest.mark.parametrize("days,expected", [(40, None), (25, 30), (10, 14), (3, 7)])
def test_expiry_warnings(ca, days, expected):
    cert, _ = make_leaf(
        ca,
        not_before=NOW - dt.timedelta(days=100),
        days_valid=100 + days,
    )
    r = run(cert, ca)
    assert r.expiry_warning_days == expected
    assert r.checks["validity"].status is (W if expected else P)
    assert r.verdict is Verdict.VALID  # ostrzeżenie nie unieważnia


def test_invalid_signature_detected(ca):
    # Podpis wystawcy podmieniony: certyfikat podpisany innym kluczem, ale z nazwą wystawcy = CA.
    impostor = make_ca()  # ta sama nazwa Subject, inny klucz
    cert, _ = make_leaf(impostor)
    r = run(cert, ca)  # tylko prawdziwy CA jest kotwicą
    assert r.checks["crypto"].status is F
    assert r.verdict is Verdict.INVALID


def test_subject_spoofing_ca_with_identical_subject_is_rejected(ca):
    """#29: CA o identycznym Subject, ale innym kluczu, dostarczone w pliku – nie jest kotwicą."""
    impostor = make_ca()
    assert impostor.cert.subject == ca.cert.subject
    cert, _ = make_leaf(impostor)
    r = run(cert, ca, candidates=[impostor.cert])
    assert r.checks["trust"].status is F
    assert r.verdict is Verdict.INVALID


def test_untrusted_foreign_issuer_with_valid_key_usage(ca):
    """#30: poprawny Key Usage, ale wystawca obcy – chain kończy się w niezaufanym roocie."""
    foreign = make_ca("Obce CA")
    cert, _ = make_leaf(foreign)
    r = run(cert, ca, candidates=[foreign.cert])
    assert r.checks["classification"].status is P
    assert r.checks["trust"].status is F
    assert r.verdict is Verdict.INVALID


def test_missing_chain_element_is_indeterminate(ca):
    inter = make_ca(
        "Pośrednie",
    )
    # leaf wystawiony przez pośrednie, które nie jest w pliku ani w kotwicach
    cert, _ = make_leaf(inter)
    r = run(cert, ca)
    assert r.checks["crypto"].status is U
    assert r.checks["trust"].status is U
    assert r.verdict is Verdict.INDETERMINATE


def test_chain_with_intermediate_is_trusted(ca):
    # pośrednie CA podpisane przez ca
    ikey = ec.generate_private_key(ec.SECP256R1())
    iname = _name(cn="Pośrednie CA")
    inter_cert = (
        x509.CertificateBuilder()
        .subject_name(iname)
        .issuer_name(ca.name)
        .public_key(ikey.public_key())
        .serial_number(7)
        .not_valid_before(NOW - dt.timedelta(days=100))
        .not_valid_after(NOW + dt.timedelta(days=900))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True
        )
        .sign(ca.key, hashes.SHA256())
    )
    from tests.conftest import CA

    inter = CA(inter_cert, ikey, iname)
    cert, _ = make_leaf(inter)
    r = run(cert, ca, candidates=[inter_cert])
    assert r.verdict is Verdict.VALID
    assert len(r.chain) == 3


def test_pathlen_violation(ca):
    c1 = make_ca("CA1", path_length=0)
    # c1 jest kotwicą, ale pod nim pośrednie (naruszenie pathLen=0)
    ikey = ec.generate_private_key(ec.SECP256R1())
    iname = _name(cn="Pośrednie")
    inter_cert = (
        x509.CertificateBuilder()
        .subject_name(iname)
        .issuer_name(c1.name)
        .public_key(ikey.public_key())
        .serial_number(8)
        .not_valid_before(NOW - dt.timedelta(days=10))
        .not_valid_after(NOW + dt.timedelta(days=100))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True
        )
        .sign(c1.key, hashes.SHA256())
    )
    from tests.conftest import CA

    cert, _ = make_leaf(CA(inter_cert, ikey, iname))
    r = run(cert, c1, candidates=[inter_cert])
    assert r.checks["trust"].status is F


def test_issuer_not_a_ca_fails(ca):
    bad = make_ca("Nie-CA", ca=False)
    cert, _ = make_leaf(bad)
    store = TrustStore()
    store.add(bad.cert, "t")
    r = verify_certificate(cert, VerifyContext(now=NOW, trust=store))
    assert r.checks["trust"].status is F


def test_wrong_key_usage_fails(ca):
    ku = x509.KeyUsage(False, False, True, False, False, False, False, False, False)  # keyEncipherment
    cert, _ = make_leaf(ca, key_usage=ku)
    r = run(cert, ca)
    assert r.cert_type is CertType.UNKNOWN
    assert r.checks["classification"].status is F
    assert r.verdict is Verdict.INVALID


def test_both_ds_and_cc_fails(ca):
    ku = x509.KeyUsage(True, True, False, False, False, False, False, False, False)
    cert, _ = make_leaf(ca, key_usage=ku)
    r = run(cert, ca)
    assert r.checks["classification"].status is F


def test_extra_key_usage_bits_unknown_type_indeterminate(ca):
    """#8/#28: technicznie poprawny, ale profil KSeF niepotwierdzony."""
    ku = x509.KeyUsage(True, False, True, False, False, False, False, False, False)
    cert, _ = make_leaf(ca, key_usage=ku)
    r = run(cert, ca)
    assert r.cert_type is CertType.UNKNOWN
    assert r.checks["profile"].status is U
    assert r.verdict is Verdict.INDETERMINATE


def test_missing_key_usage_unknown(ca):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn="x"))
        .issuer_name(ca.name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(NOW - dt.timedelta(days=1))
        .not_valid_after(NOW + dt.timedelta(days=100))
        .sign(ca.key, hashes.SHA256())
    )
    r = run(cert, ca)
    assert r.cert_type is CertType.UNKNOWN and r.verdict is Verdict.INDETERMINATE


def test_expected_type_mismatch(ca, auth_cert):
    r = run(auth_cert[0], ca, expected=CertType.OFFLINE)
    assert r.checks["classification"].status is F and r.verdict is Verdict.INVALID


def test_unsupported_key_algorithm_ed25519(ca):
    key = ed25519.Ed25519PrivateKey.generate()
    cert, _ = make_leaf(ca, key=key)
    r = run(cert, ca)
    assert r.checks["crypto"].status is F
    assert r.checks["profile"].status is F
    assert r.verdict is Verdict.INVALID


@pytest.mark.parametrize("size", [1024, 3072])
def test_rsa_wrong_size_fails_profile(ca, size):
    key = rsa.generate_private_key(65537, size)
    cert, _ = make_leaf(ca, key=key)
    assert run(cert, ca).checks["profile"].status is F


def test_rsa_2048_ok(ca):
    key = rsa.generate_private_key(65537, 2048)
    cert, _ = make_leaf(ca, key=key)
    assert run(cert, ca).verdict is Verdict.VALID


def test_wrong_ec_curve_fails(ca):
    key = ec.generate_private_key(ec.SECP384R1())
    cert, _ = make_leaf(ca, key=key)
    assert run(cert, ca).checks["profile"].status is F


def test_leaf_marked_ca_fails(ca):
    cert, _ = make_leaf(ca, is_ca=True)
    assert run(cert, ca).checks["profile"].status is F


def test_unknown_critical_extension_fails(ca):
    ext = x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4.5"), b"\x05\x00")
    cert, _ = make_leaf(ca, extra_exts=[(ext, True)])
    r = run(cert, ca)
    assert r.checks["profile"].status is F and r.verdict is Verdict.INVALID


def test_unknown_noncritical_extension_ok(ca):
    ext = x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4.5"), b"\x05\x00")
    cert, _ = make_leaf(ca, extra_exts=[(ext, False)])
    assert run(cert, ca).verdict is Verdict.VALID


def test_eku_present_is_warning_not_failure(ca):
    eku = x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH])
    cert, _ = make_leaf(ca, extra_exts=[(eku, False)])
    r = run(cert, ca)
    assert r.checks["profile"].status is W and r.verdict is Verdict.VALID


def test_sha1_signature_warns_if_openssl_allows():
    # UWAGA: nazwa dawniej sugerowała MD5. Ścieżka MD5→FAIL NIE jest pokryta testem (OpenSSL nie podpisuje MD5).
    ca = make_ca()
    try:
        cert, _ = make_leaf(ca, hash_alg=hashes.SHA1())
    except Exception:  # pragma: no cover
        pytest.skip("SHA-1 niedostępny w tej kompilacji OpenSSL")
    r = run(cert, ca)
    assert r.checks["crypto"].status is W


def test_self_signed_not_anchor_with_anchors_configured(ca):
    selfsigned = make_ca("Samopodpisany")
    r = run(selfsigned.cert, ca)
    assert r.checks["trust"].status is F


def test_anchor_matching_is_by_der_not_by_name(ca):
    """Kotwica o tej samej nazwie, ale innym DER, nie daje zaufania."""
    twin = make_ca()
    cert, _ = make_leaf(twin)
    r = run(cert, ca)  # twin nie jest w ogóle dostępny
    assert r.verdict is Verdict.INVALID


def test_ca_validity_checked(ca):
    old = make_ca("Stare CA", days=30, not_before=NOW - dt.timedelta(days=400))
    cert, _ = make_leaf(old)
    store = TrustStore()
    store.add(old.cert, "t")
    r = verify_certificate(cert, VerifyContext(now=NOW, trust=store))
    assert r.checks["trust"].status is F


def test_validity_checked_against_injected_clock(ca, auth_cert):
    later = NOW + dt.timedelta(days=1000)
    assert run(auth_cert[0], ca, now=later).verdict is Verdict.INVALID


# --- identyfikacja podmiotu -------------------------------------------------


def test_pesel_nip_checksums():
    assert valid_pesel("44051401359") and not valid_pesel("44051401358")
    assert valid_nip("1234563218") and not valid_nip("1234563217")
    assert not valid_nip("abc")


def test_subject_nip_from_serial_and_orgid():
    info, notes = parse_subject(_name(cn="Firma", given="A", sn="B", serial="TINPL-1234563218"))
    assert info.nip == "1234563218" and info.pesel is None and info.kind == "person"
    info, _ = parse_subject(_name(cn="Firma Sp. z o.o.", o="Firma", orgid="VATPL-1234563218"))
    assert info.nip == "1234563218" and info.kind == "organization"


def test_no_guessing_identifiers_from_random_digits():
    info, notes = parse_subject(_name(cn="Jan 12345678901", given="Jan", sn="X", serial="ABC12345678901"))
    assert info.pesel is None and info.nip is None


def test_bad_checksum_identifier_not_reported():
    info, notes = parse_subject(_name(cn="J", given="J", sn="K", serial="PNOPL44051401358"))
    assert info.pesel is None and notes


def test_critical_name_constraints_on_ca_not_silently_accepted(ca):
    """Rozszerzenia niegwarantowane przez silnik (NameConstraints) – krytyczne → FAIL (fail-closed)."""
    nc = x509.NameConstraints(permitted_subtrees=[x509.DNSName("example.com")], excluded_subtrees=None)
    constrained = make_ca("CA z NameConstraints")
    # przebuduj CA z krytycznym NameConstraints
    b = (
        x509.CertificateBuilder()
        .subject_name(constrained.name)
        .issuer_name(constrained.name)
        .public_key(constrained.key.public_key())
        .serial_number(5)
        .not_valid_before(NOW - dt.timedelta(days=10))
        .not_valid_after(NOW + dt.timedelta(days=100))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True
        )
        .add_extension(nc, critical=True)
    )
    from tests.conftest import CA

    cacert = b.sign(constrained.key, hashes.SHA256())
    cc = CA(cacert, constrained.key, constrained.name)
    leaf, _ = make_leaf(cc)
    r = run(leaf, cc)
    assert r.checks["trust"].status is F and r.verdict is Verdict.INVALID


def test_self_signed_with_corrupted_signature_is_invalid(ca):
    from cryptography import x509 as x

    selfsigned = make_ca("Samopodpisany")
    raw = bytearray(
        selfsigned.cert.public_bytes(
            __import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.DER
        )
    )
    raw[-5] ^= 0x01  # uszkodzenie podpisu
    broken = x.load_der_x509_certificate(bytes(raw))
    r = run(broken, ca)
    assert r.checks["crypto"].status is F and r.verdict is Verdict.INVALID


def test_no_key_never_valid(ca, auth_cert):
    r = run(auth_cert[0], ca, with_key=False)
    assert r.checks["key_decrypt"].status is N and r.checks["key_match"].status is N
    assert r.verdict is Verdict.INDETERMINATE
