from __future__ import annotations

import base64
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import shake_256

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree

from ebics_read import (
    AmbiguousInitializationError,
    Bank,
    CertificateValidationError,
    ConfigurationError,
    EbicsBackend,
    EbicsReturnCodeError,
    KeyPurpose,
    NegotiatedProtocol,
    ReadOnlyClient,
    Subscriber,
    TransientTransportError,
    TransportResponse,
)
from ebics_read.testing import FixedClock, InMemoryBankKeyTrustStore
from ebics_read.transport import _PreparedTransportRequest

_NOW = datetime(2026, 8, 8, 12, 30, tzinfo=timezone.utc)
_H005 = "urn:org:ebics:H005"
_DS = "http://www.w3.org/2000/09/xmldsig#"
_HEV_RESPONSE = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<ebicsHEVResponse xmlns="http://www.ebics.org/H000">'
    b"<SystemReturnCode><ReturnCode>000000</ReturnCode>"
    b"<ReportText>EBICS_OK</ReportText></SystemReturnCode>"
    b'<VersionNumber ProtocolVersion="H005">03.00</VersionNumber>'
    b"</ebicsHEVResponse>"
)
_HIA_RESPONSE = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<ebicsKeyManagementResponse xmlns="urn:org:ebics:H005" '
    b'Version="H005" Revision="1">'
    b'<header authenticate="true"><static/><mutable><OrderID>A001</OrderID>'
    b"<ReturnCode>000000</ReturnCode><ReportText>synthetic result</ReportText>"
    b'</mutable></header><body><ReturnCode authenticate="true">000000</ReturnCode>'
    b"</body></ebicsKeyManagementResponse>"
)


def _certificate(
    *,
    digital_signature: bool,
    key_encipherment: bool,
    content_commitment: bool = False,
    key_agreement: bool = False,
    key_size: int = 2048,
    extra_extension: bytes | None = None,
    common_name: bool = True,
) -> bytes:
    key = rsa.generate_private_key(public_exponent=65_537, key_size=key_size)
    name = x509.Name(
        [
            x509.NameAttribute(
                NameOID.COMMON_NAME if common_name else NameOID.ORGANIZATION_NAME,
                "Synthetic HIA",
            )
        ]
    )
    serial = x509.random_serial_number()
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(_NOW - timedelta(days=1))
        .not_valid_after(_NOW + timedelta(days=730))
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=digital_signature,
                content_commitment=content_commitment,
                key_encipherment=key_encipherment,
                data_encipherment=False,
                key_agreement=key_agreement,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False if key_agreement else None,
                decipher_only=False if key_agreement else None,
            ),
            critical=True,
        )
    )
    if extra_extension is not None:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier("1.2.3.4.6"), extra_extension
            ),
            critical=False,
        )
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


@dataclass(frozen=True)
class _Provider:
    signature: bytes
    authentication: bytes
    encryption: bytes
    requested: list[KeyPurpose] = field(default_factory=list, compare=False)

    def certificate_der(self, purpose: KeyPurpose) -> bytes:
        self.requested.append(purpose)
        if purpose is KeyPurpose.SIGNATURE:
            return self.signature
        if purpose is KeyPurpose.AUTHENTICATION:
            return self.authentication
        if purpose is KeyPurpose.ENCRYPTION:
            return self.encryption
        raise AssertionError("unexpected HIA key purpose")

    def sign_x002(self, canonical_signed_info: bytes) -> bytes:
        raise AssertionError("HIA must not create X002")

    def decrypt_e002_transaction_key(self, wrapped_key: bytes) -> bytes:
        raise AssertionError("HIA must not decrypt E002")


@dataclass
class _Transport:
    response: bytes = _HIA_RESPONSE
    requests: list[_PreparedTransportRequest] = field(default_factory=list)

    def exchange(
        self, request: _PreparedTransportRequest, control: object
    ) -> TransportResponse:
        self.requests.append(request)
        return TransportResponse(
            _HEV_RESPONSE if request.order.value == "HEV" else self.response
        )


def test_hia_runs_through_client_with_exact_unsecured_request_and_letter() -> None:
    authentication_der = _certificate(digital_signature=True, key_encipherment=False)
    encryption_der = _certificate(digital_signature=False, key_encipherment=True)
    signature_der = _certificate(
        digital_signature=False,
        key_encipherment=False,
        content_commitment=True,
    )
    provider = _Provider(signature_der, authentication_der, encryption_der)
    transport = _Transport()
    client = ReadOnlyClient(
        Bank("https://bank.invalid/ebics", "HOST", "Synthetic Bank AG"),
        Subscriber("PARTNER=1", "USER,1", "SYSTEM1"),
        EbicsBackend(
            transport,  # type: ignore[arg-type]
            key_provider=provider,
            clock=FixedClock(_NOW),
        ),
        InMemoryBankKeyTrustStore(),
    )

    letter = client.initialize_auth_encryption_keys(object())  # type: ignore[arg-type]

    assert [request.order.value for request in transport.requests] == ["HEV", "HIA"]
    assert provider.requested == [
        KeyPurpose.SIGNATURE,
        KeyPurpose.AUTHENTICATION,
        KeyPurpose.ENCRYPTION,
    ]
    root = etree.fromstring(transport.requests[-1].body)
    assert root.tag == f"{{{_H005}}}ebicsUnsecuredRequest"
    assert root.attrib == {"Version": "H005", "Revision": "1"}
    names = [etree.QName(element).localname for element in root.iter()]
    assert names == [
        "ebicsUnsecuredRequest",
        "header",
        "static",
        "HostID",
        "PartnerID",
        "UserID",
        "SystemID",
        "OrderDetails",
        "AdminOrderType",
        "SecurityMedium",
        "mutable",
        "body",
        "DataTransfer",
        "OrderData",
    ]
    assert root.findtext(f".//{{{_H005}}}AdminOrderType") == "HIA"
    assert root.findtext(f".//{{{_H005}}}SecurityMedium") == "0000"
    assert not any(name in names for name in ("Nonce", "Timestamp", "AuthSignature"))

    encoded = root.findtext(f".//{{{_H005}}}OrderData")
    assert encoded is not None
    inner = etree.fromstring(zlib.decompress(base64.b64decode(encoded, validate=True)))
    assert [etree.QName(element).localname for element in inner.iter()] == [
        "HIARequestOrderData",
        "AuthenticationPubKeyInfo",
        "X509Data",
        "X509Certificate",
        "AuthenticationVersion",
        "EncryptionPubKeyInfo",
        "X509Data",
        "X509Certificate",
        "EncryptionVersion",
        "PartnerID",
        "UserID",
    ]
    assert inner.findtext(f".//{{{_H005}}}AuthenticationVersion") == "X002"
    assert inner.findtext(f".//{{{_H005}}}EncryptionVersion") == "E002"
    embedded = inner.findall(f".//{{{_DS}}}X509Certificate")
    assert [
        base64.b64decode(value.text or "", validate=True) for value in embedded
    ] == [
        authentication_der,
        encryption_der,
    ]

    assert letter.order.value == "HIA"
    assert b"Synthetic Bank AG" in letter.content
    assert b"bank.invalid" not in letter.content
    assert b"X002 / E002" in letter.content
    assert len(letter.public_key_digests) == 2
    for certificate_der in (authentication_der, encryption_der):
        pem = x509.load_der_x509_certificate(certificate_der).public_bytes(
            serialization.Encoding.PEM
        )
        assert pem.rstrip() in letter.content


def test_hia_certificate_profiles_fail_closed_but_allow_one_dual_use_key() -> None:
    dual_use = _certificate(digital_signature=True, key_encipherment=True)
    signature = _certificate(
        digital_signature=False,
        key_encipherment=False,
        content_commitment=True,
    )
    backend = EbicsBackend(
        _Transport(),  # type: ignore[arg-type]
        key_provider=_Provider(signature, dual_use, dual_use),
        clock=FixedClock(_NOW),
    )
    assert backend.initialize_auth_encryption_keys(
        Bank("https://bank.invalid/ebics", "HOST", "Synthetic Bank AG"),
        Subscriber("PARTNER", "USER"),
        NegotiatedProtocol(),
        object(),  # type: ignore[arg-type]
    )
    key_agreement = _certificate(
        digital_signature=False,
        key_encipherment=False,
        key_agreement=True,
    )
    assert EbicsBackend(
        _Transport(),  # type: ignore[arg-type]
        key_provider=_Provider(signature, dual_use, key_agreement),
        clock=FixedClock(_NOW),
    ).initialize_auth_encryption_keys(
        Bank("https://bank.invalid/ebics", "HOST", "Synthetic Bank AG"),
        Subscriber("PARTNER", "USER"),
        NegotiatedProtocol(),
        object(),  # type: ignore[arg-type]
    )

    invalid_pairs = (
        (
            _certificate(digital_signature=False, key_encipherment=True),
            _certificate(digital_signature=False, key_encipherment=True),
        ),
        (
            _certificate(digital_signature=True, key_encipherment=False),
            _certificate(digital_signature=True, key_encipherment=False),
        ),
        (
            _certificate(digital_signature=True, key_encipherment=False, key_size=1024),
            _certificate(digital_signature=False, key_encipherment=True),
        ),
        (
            _certificate(digital_signature=True, key_encipherment=False),
            _certificate(
                digital_signature=False,
                key_encipherment=True,
                common_name=False,
            ),
        ),
    )
    for authentication_der, encryption_der in invalid_pairs:
        transport = _Transport()
        invalid_backend = EbicsBackend(
            transport,  # type: ignore[arg-type]
            key_provider=_Provider(signature, authentication_der, encryption_der),
            clock=FixedClock(_NOW),
        )
        with pytest.raises(CertificateValidationError):
            invalid_backend.initialize_auth_encryption_keys(
                Bank("https://bank.invalid/ebics", "HOST", "Synthetic Bank AG"),
                Subscriber("PARTNER", "USER"),
                NegotiatedProtocol(),
                object(),  # type: ignore[arg-type]
            )
        assert transport.requests == []

    signature_and_authentication = _certificate(
        digital_signature=True,
        key_encipherment=False,
        content_commitment=True,
    )
    signature_and_encryption = _certificate(
        digital_signature=False,
        key_encipherment=True,
        content_commitment=True,
    )
    for signature_der, authentication_der, encryption_der in (
        (signature_and_authentication, signature_and_authentication, dual_use),
        (signature_and_encryption, dual_use, signature_and_encryption),
    ):
        with pytest.raises(CertificateValidationError, match="different RSA keys"):
            EbicsBackend(
                _Transport(),  # type: ignore[arg-type]
                key_provider=_Provider(
                    signature_der, authentication_der, encryption_der
                ),
                clock=FixedClock(_NOW),
            ).initialize_auth_encryption_keys(
                Bank("https://bank.invalid/ebics", "HOST", "Synthetic Bank AG"),
                Subscriber("PARTNER", "USER"),
                NegotiatedProtocol(),
                object(),  # type: ignore[arg-type]
            )


def test_hia_configuration_size_protocol_and_ambiguity_fail_safely() -> None:
    authentication_der = _certificate(digital_signature=True, key_encipherment=False)
    encryption_der = _certificate(digital_signature=False, key_encipherment=True)
    signature_der = _certificate(
        digital_signature=False,
        key_encipherment=False,
        content_commitment=True,
    )
    provider = _Provider(signature_der, authentication_der, encryption_der)
    backend = EbicsBackend(
        _Transport(),  # type: ignore[arg-type]
        key_provider=provider,
        clock=FixedClock(_NOW),
    )
    with pytest.raises(ConfigurationError, match="institution name"):
        backend.initialize_auth_encryption_keys(
            Bank("https://bank.invalid/ebics", "HOST"),
            Subscriber("PARTNER", "USER"),
            NegotiatedProtocol(),
            object(),  # type: ignore[arg-type]
        )

    oversized = _certificate(
        digital_signature=False,
        key_encipherment=True,
        extra_extension=shake_256(b"synthetic oversized HIA").digest(1_100_000),
    )
    transport = _Transport()
    oversized_backend = EbicsBackend(
        transport,  # type: ignore[arg-type]
        key_provider=_Provider(signature_der, authentication_der, oversized),
        clock=FixedClock(_NOW),
    )
    with pytest.raises(ConfigurationError, match="one-message limit"):
        oversized_backend.initialize_auth_encryption_keys(
            Bank("https://bank.invalid/ebics", "HOST", "Synthetic Bank AG"),
            Subscriber("PARTNER", "USER"),
            NegotiatedProtocol(),
            object(),  # type: ignore[arg-type]
        )
    assert transport.requests == []

    fake_protocol = type("FakeProtocol", (), {"protocol_version": "H004"})()
    with pytest.raises(TypeError, match="exact NegotiatedProtocol"):
        _PreparedTransportRequest._for_hia(
            Bank("https://bank.invalid/ebics", "HOST"),
            Subscriber("PARTNER", "USER"),
            fake_protocol,  # type: ignore[arg-type]
            authentication_der,
            encryption_der,
        )

    ambiguous_backend = EbicsBackend(
        _Transport(response=b"malformed response"),  # type: ignore[arg-type]
        key_provider=provider,
        clock=FixedClock(_NOW),
    )
    with pytest.raises(AmbiguousInitializationError) as ambiguous:
        ambiguous_backend.initialize_auth_encryption_keys(
            Bank("https://bank.invalid/ebics", "HOST", "Synthetic Bank AG"),
            Subscriber("PARTNER", "USER"),
            NegotiatedProtocol(),
            object(),  # type: ignore[arg-type]
        )
    assert ambiguous.value.pending_letter.order.value == "HIA"
    assert len(ambiguous.value.pending_letter.public_key_digests) == 2

    rejected_response = _HIA_RESPONSE.replace(
        b'<ReturnCode authenticate="true">000000</ReturnCode>',
        b'<ReturnCode authenticate="true">091203</ReturnCode>',
    )
    rejected_backend = EbicsBackend(
        _Transport(response=rejected_response),  # type: ignore[arg-type]
        key_provider=provider,
        clock=FixedClock(_NOW),
    )
    with pytest.raises(EbicsReturnCodeError) as rejected:
        rejected_backend.initialize_auth_encryption_keys(
            Bank("https://bank.invalid/ebics", "HOST", "Synthetic Bank AG"),
            Subscriber("PARTNER", "USER"),
            NegotiatedProtocol(),
            object(),  # type: ignore[arg-type]
        )
    assert (rejected.value.technical, rejected.value.business) == (
        "000000",
        "091203",
    )

    class TransientTransport(_Transport):
        def exchange(
            self, request: _PreparedTransportRequest, control: object
        ) -> TransportResponse:
            raise TransientTransportError("synthetic proven no-send")

    transient_backend = EbicsBackend(
        TransientTransport(),  # type: ignore[arg-type]
        key_provider=provider,
        clock=FixedClock(_NOW),
    )
    with pytest.raises(TransientTransportError):
        transient_backend.initialize_auth_encryption_keys(
            Bank("https://bank.invalid/ebics", "HOST", "Synthetic Bank AG"),
            Subscriber("PARTNER", "USER"),
            NegotiatedProtocol(),
            object(),  # type: ignore[arg-type]
        )


def test_client_missing_hia_dependencies_sends_only_mandatory_hev() -> None:
    transport = _Transport()
    client = ReadOnlyClient(
        Bank("https://bank.invalid/ebics", "HOST", "Synthetic Bank AG"),
        Subscriber("PARTNER", "USER"),
        EbicsBackend(transport),  # type: ignore[arg-type]
        InMemoryBankKeyTrustStore(),
    )
    with pytest.raises(ConfigurationError, match="key provider and clock"):
        client.initialize_auth_encryption_keys(object())  # type: ignore[arg-type]
    assert [request.order.value for request in transport.requests] == ["HEV"]
