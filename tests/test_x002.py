from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from hashlib import sha256

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from lxml import etree

from ebics_read import (
    SecurityError,
    SelfSignedH005BankCertificateProfile,
    TrustedBankKeys,
    XmlSecurityError,
)
from ebics_read.h005 import H005_NAMESPACE, ParsedH005Response, parse_h005_response
from ebics_read.models import BankKeyRole
from ebics_read.testing import synthetic_out_of_band_identity
from ebics_read.x002 import (
    AuthenticatedH005Response,
    _append_x002_auth_signature,
    verify_x002_response,
)

_DS = "http://www.w3.org/2000/09/xmldsig#"
_C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
_REFERENCE = "#xpointer(//*[@authenticate='true'])"
_NOW = datetime(2026, 8, 8, tzinfo=timezone.utc)


def _certificate(key: rsa.RSAPrivateKey, role: BankKeyRole) -> bytes:
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, f"Synthetic X002 {role.value}")]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - timedelta(days=1))
        .not_valid_after(_NOW + timedelta(days=365))
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=role is BankKeyRole.ENCRYPTION,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


def _trusted_keys() -> tuple[TrustedBankKeys, rsa.RSAPrivateKey]:
    authentication_key = rsa.generate_private_key(public_exponent=65_537, key_size=2048)
    encryption_key = rsa.generate_private_key(public_exponent=65_537, key_size=2048)
    candidate = SelfSignedH005BankCertificateProfile().validate_pair(
        _certificate(authentication_key, BankKeyRole.AUTHENTICATION),
        _certificate(encryption_key, BankKeyRole.ENCRYPTION),
        _NOW,
    )
    return (
        TrustedBankKeys.accept_out_of_band(
            candidate, synthetic_out_of_band_identity(candidate)
        ),
        authentication_key,
    )


def _signed_response(
    key: rsa.RSAPrivateKey, report_text: str = "[EBICS_OK] OK"
) -> ParsedH005Response:
    root = etree.Element(
        etree.QName(H005_NAMESPACE, "ebicsResponse"),
        nsmap={None: H005_NAMESPACE, "ds": _DS},  # type: ignore[dict-item]
        Version="H005",
        Revision="1",
    )
    header = etree.SubElement(root, etree.QName(H005_NAMESPACE, "header"))
    header.set("authenticate", "true")
    etree.SubElement(header, etree.QName(H005_NAMESPACE, "static"))
    mutable = etree.SubElement(header, etree.QName(H005_NAMESPACE, "mutable"))
    etree.SubElement(
        mutable, etree.QName(H005_NAMESPACE, "TransactionPhase")
    ).text = "Initialisation"
    etree.SubElement(mutable, etree.QName(H005_NAMESPACE, "ReturnCode")).text = "000000"
    etree.SubElement(
        mutable, etree.QName(H005_NAMESPACE, "ReportText")
    ).text = report_text
    auth_signature = etree.SubElement(
        root, etree.QName(H005_NAMESPACE, "AuthSignature")
    )
    signed_info = etree.SubElement(auth_signature, etree.QName(_DS, "SignedInfo"))
    etree.SubElement(
        signed_info, etree.QName(_DS, "CanonicalizationMethod"), Algorithm=_C14N
    )
    etree.SubElement(
        signed_info, etree.QName(_DS, "SignatureMethod"), Algorithm=_RSA_SHA256
    )
    reference = etree.SubElement(
        signed_info, etree.QName(_DS, "Reference"), URI=_REFERENCE
    )
    transforms = etree.SubElement(reference, etree.QName(_DS, "Transforms"))
    etree.SubElement(transforms, etree.QName(_DS, "Transform"), Algorithm=_C14N)
    etree.SubElement(reference, etree.QName(_DS, "DigestMethod"), Algorithm=_SHA256)
    digest = etree.SubElement(reference, etree.QName(_DS, "DigestValue"))
    signature = etree.SubElement(auth_signature, etree.QName(_DS, "SignatureValue"))
    body = etree.SubElement(root, etree.QName(H005_NAMESPACE, "body"))
    business = etree.SubElement(body, etree.QName(H005_NAMESPACE, "ReturnCode"))
    business.set("authenticate", "true")
    business.text = "000000"

    authenticated = _canonical(header) + _canonical(business)
    digest.text = base64.b64encode(sha256(authenticated).digest()).decode("ascii")
    signature.text = base64.b64encode(
        key.sign(_canonical(signed_info), padding.PKCS1v15(), hashes.SHA256())
    ).decode("ascii")
    return parse_h005_response(etree.tostring(root))


def _canonical(element: etree._Element) -> bytes:
    return etree.tostring(element, method="c14n", exclusive=False, with_comments=False)


def _signature_parts(
    parsed: ParsedH005Response,
) -> tuple[etree._Element, etree._Element, etree._Element]:
    signature = list(parsed.root)[1]
    signed_info, signature_value = list(signature)
    reference = list(signed_info)[2]
    return signed_info, reference, signature_value


def _reparse(parsed: ParsedH005Response) -> ParsedH005Response:
    return parse_h005_response(etree.tostring(parsed.root))


def test_x002_verifies_only_with_pinned_bank_authentication_key() -> None:
    trusted, private_key = _trusted_keys()
    parsed = _signed_response(private_key)
    authenticated = verify_x002_response(parsed, trusted)
    assert authenticated.document == parsed.document
    assert authenticated.return_codes == parsed.return_codes
    with pytest.raises(TypeError):
        AuthenticatedH005Response(parsed.document, parsed.return_codes)
    with pytest.raises(TypeError):
        verify_x002_response(object(), trusted)  # type: ignore[arg-type]

    other_trusted, _ = _trusted_keys()
    with pytest.raises(SecurityError, match="signature"):
        verify_x002_response(parsed, other_trusted)


def test_x002_rejects_digest_signature_and_marker_tampering() -> None:
    trusted, private_key = _trusted_keys()

    parsed = _signed_response(private_key)
    next(iter(parsed.body)).text = "090005"
    with pytest.raises(SecurityError, match="digest"):
        verify_x002_response(_reparse(parsed), trusted)

    parsed = _signed_response(private_key)
    _, _, signature_value = _signature_parts(parsed)
    signature_value.text = base64.b64encode(b"invalid").decode("ascii")
    with pytest.raises(SecurityError, match="signature"):
        verify_x002_response(_reparse(parsed), trusted)

    parsed = _signed_response(private_key)
    _, _, signature_value = _signature_parts(parsed)
    signature_value.text = "\u00a0" + (signature_value.text or "")
    with pytest.raises(XmlSecurityError, match="base64"):
        verify_x002_response(_reparse(parsed), trusted)

    parsed = _signed_response(private_key)
    extension = etree.SubElement(
        list(parsed.header)[1], etree.QName("urn:synthetic", "Extension")
    )
    extension.set("authenticate", "1")
    with pytest.raises(XmlSecurityError, match="marker"):
        verify_x002_response(_reparse(parsed), trusted)


def test_x002_accepts_ebics_short_signatures_but_rejects_invalid_lengths() -> None:
    trusted, private_key = _trusted_keys()
    for attempt in range(4096):
        parsed = _signed_response(private_key, f"[EBICS_OK] OK {attempt}")
        _, _, signature_value = _signature_parts(parsed)
        signature = base64.b64decode(signature_value.text or "", validate=True)
        if signature.startswith(b"\0"):
            signature_value.text = base64.b64encode(signature.lstrip(b"\0")).decode(
                "ascii"
            )
            assert verify_x002_response(_reparse(parsed), trusted)
            break
    else:
        pytest.fail("could not synthesize an RSA signature with a leading zero octet")

    parsed = _signed_response(private_key)
    _, _, signature_value = _signature_parts(parsed)
    signature_value.text = base64.b64encode(b"x" * 257).decode("ascii")
    with pytest.raises(SecurityError, match="length"):
        verify_x002_response(_reparse(parsed), trusted)


def test_x002_rejects_algorithm_reference_and_structure_changes() -> None:
    trusted, private_key = _trusted_keys()

    parsed = _signed_response(private_key)
    signed_info, _, _ = _signature_parts(parsed)
    next(iter(signed_info)).set("Algorithm", "unknown")
    with pytest.raises(XmlSecurityError, match="algorithm"):
        verify_x002_response(_reparse(parsed), trusted)

    parsed = _signed_response(private_key)
    _, reference, _ = _signature_parts(parsed)
    reference.set("URI", "#other")
    with pytest.raises(XmlSecurityError, match="structure"):
        verify_x002_response(_reparse(parsed), trusted)

    parsed = _signed_response(private_key)
    relative_namespace = parsed.document.replace(
        b'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"',
        b'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:p="relative"',
    )
    with pytest.raises(XmlSecurityError, match="canonicalization"):
        verify_x002_response(parse_h005_response(relative_namespace), trusted)

    parsed = _signed_response(private_key)
    signature = list(parsed.root)[1]
    etree.SubElement(signature, etree.QName(_DS, "KeyInfo"))
    with pytest.raises(XmlSecurityError, match="structure"):
        verify_x002_response(_reparse(parsed), trusted)


class _RecordingProvider:
    """Signs correctly and records the exact bytes the library asked it to sign."""

    def __init__(self, key: rsa.RSAPrivateKey, *, strip: bool = False) -> None:
        self._key = key
        self._strip = strip
        self.signature = b""

    def certificate_der(self, purpose: object) -> bytes:
        raise AssertionError("request signing must not fetch certificates")

    def sign_x002(self, canonical_signed_info: bytes) -> bytes:
        self.signature = self._key.sign(
            canonical_signed_info, padding.PKCS1v15(), hashes.SHA256()
        )
        # Some HSM and bignum providers return the integer, not the octet string.
        return self.signature.lstrip(b"\x00") if self._strip else self.signature

    def decrypt_e002_transaction_key(self, wrapped_key: bytes) -> bytes:
        raise AssertionError("request signing must not unwrap transaction keys")


def _request(marker: str) -> etree._Element:
    root = etree.Element(etree.QName(H005_NAMESPACE, "ebicsRequest"))
    etree.SubElement(
        root, etree.QName(H005_NAMESPACE, "header"), authenticate="true"
    ).text = marker
    return root


def test_x002_request_signature_value_is_always_one_modulus_wide() -> None:
    key = rsa.generate_private_key(public_exponent=65_537, key_size=2048)
    certificate_der = _certificate(key, BankKeyRole.AUTHENTICATION)
    key_bytes = key.key_size // 8

    # Roughly one signature in 256 has a leading zero octet; find one so that a
    # stripping provider actually returns a short value.
    for attempt in range(4096):
        marker = f"synthetic {attempt}"
        probe = _RecordingProvider(key)
        _append_x002_auth_signature(_request(marker), probe, certificate_der)
        if probe.signature.startswith(b"\x00"):
            break
    else:  # pragma: no cover - 4096 misses is a broken RSA implementation
        pytest.fail("no signature with a leading zero octet was found")

    provider = _RecordingProvider(key, strip=True)
    root = _request(marker)
    _append_x002_auth_signature(root, provider, certificate_der)

    value = root.findtext(f".//{{{_DS}}}SignatureValue")
    assert value is not None
    emitted = base64.b64decode(value, validate=True)
    assert len(emitted) == key_bytes
    assert emitted == provider.signature
