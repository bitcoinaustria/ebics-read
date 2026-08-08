from __future__ import annotations

import base64
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import shake_256

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from lxml import etree

from ebics_read import (
    AmbiguousInitializationError,
    AmbiguousTransportError,
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
from ebics_read.ini import _parse_key_initialization_response
from ebics_read.testing import FixedClock, InMemoryBankKeyTrustStore
from ebics_read.transport import _PreparedTransportRequest
from ebics_read.xml import XmlLimits

_NOW = datetime(2026, 8, 8, 12, 30, tzinfo=timezone.utc)
_H005 = "urn:org:ebics:H005"
_S002 = "http://www.ebics.org/S002"
_DS = "http://www.w3.org/2000/09/xmldsig#"
_HEV_RESPONSE = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<ebicsHEVResponse xmlns="http://www.ebics.org/H000">'
    b"<SystemReturnCode><ReturnCode>000000</ReturnCode>"
    b"<ReportText>EBICS_OK</ReportText></SystemReturnCode>"
    b'<VersionNumber ProtocolVersion="H005">03.00</VersionNumber>'
    b"</ebicsHEVResponse>"
)


def _signature_certificate(
    *,
    now: datetime = _NOW,
    content_commitment: bool = True,
    digital_signature: bool | None = None,
    expired: bool = False,
    key_size: int = 2048,
    self_issued: bool = True,
    validity_days: int = 730,
    matching_aki: bool = True,
    include_ski: bool = True,
    extended_key_usage: bool = False,
    extra_extension: bytes | None = None,
    aki_issuer_serial: bool = False,
    aki_serial_delta: int = 0,
    not_after_override: datetime | None = None,
    signature_hash: hashes.HashAlgorithm | None = None,
) -> bytes:
    key = rsa.generate_private_key(public_exponent=65_537, key_size=key_size)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic INI")])
    issuer = (
        name
        if self_issued
        else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Other issuer")])
    )
    not_before = now - timedelta(days=365)
    not_after = not_after_override or (
        now - timedelta(days=1)
        if expired
        else not_before + timedelta(days=validity_days)
    )
    serial_number = x509.random_serial_number()
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(serial_number)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if include_ski:
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
    authority_key = (
        key.public_key()
        if matching_aki
        else rsa.generate_private_key(
            public_exponent=65_537, key_size=2048
        ).public_key()
    )
    key_identifier = x509.SubjectKeyIdentifier.from_public_key(authority_key).digest
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier(
            key_identifier,
            [x509.DirectoryName(name)] if aki_issuer_serial else None,
            serial_number + aki_serial_delta if aki_issuer_serial else None,
        ),
        critical=False,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=(
                not content_commitment
                if digital_signature is None
                else digital_signature
            ),
            content_commitment=content_commitment,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    if extended_key_usage:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
    if extra_extension is not None:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier("1.2.3.4.5"), extra_extension
            ),
            critical=False,
        )
    certificate = builder.sign(key, signature_hash or hashes.SHA256())
    return certificate.public_bytes(serialization.Encoding.DER)


def _ec_certificate() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic EC")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - timedelta(days=1))
        .not_valid_after(_NOW + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


def _rsa_signed_ec_certificate() -> bytes:
    subject_key = ec.generate_private_key(ec.SECP256R1())
    signer = rsa.generate_private_key(public_exponent=65_537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic EC")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - timedelta(days=1))
        .not_valid_after(_NOW + timedelta(days=1))
        .sign(signer, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


def _ini_response(
    *,
    technical: str = "000000",
    business: str = "000000",
    order_id: bool = True,
    data_transfer: bool = False,
) -> bytes:
    order = b"<OrderID>A001</OrderID>" if order_id else b""
    transfer = b"<DataTransfer/>" if data_transfer else b""
    return (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<ebicsKeyManagementResponse xmlns="urn:org:ebics:H005" '
        b'Version="H005" Revision="1">'
        b'<header authenticate="true"><static/><mutable>'
        + order
        + b"<ReturnCode>"
        + technical.encode("ascii")
        + b"</ReturnCode><ReportText>synthetic result</ReportText>"
        b"</mutable></header><body>"
        + transfer
        + b'<ReturnCode authenticate="true">'
        + business.encode("ascii")
        + b"</ReturnCode></body></ebicsKeyManagementResponse>"
    )


@dataclass(frozen=True)
class _Provider:
    signature_certificate: bytes

    def certificate_der(self, purpose: KeyPurpose) -> bytes:
        assert purpose is KeyPurpose.SIGNATURE
        return self.signature_certificate

    def sign_x002(self, canonical_signed_info: bytes) -> bytes:
        raise AssertionError("INI must not create X002")

    def decrypt_e002_transaction_key(self, wrapped_key: bytes) -> bytes:
        raise AssertionError("INI must not decrypt E002")


@dataclass
class _Transport:
    requests: list[_PreparedTransportRequest] = field(default_factory=list)

    def exchange(
        self, request: _PreparedTransportRequest, control: object
    ) -> TransportResponse:
        self.requests.append(request)
        return TransportResponse(
            _HEV_RESPONSE if request.order.value == "HEV" else _ini_response()
        )


@dataclass
class _SingleUseClock:
    calls: int = 0

    def now(self) -> datetime:
        self.calls += 1
        if self.calls != 1:
            raise AssertionError(
                "successful INI must not depend on a second clock read"
            )
        return _NOW


def test_ini_runs_through_client_with_exact_unsecured_request_and_letter() -> None:
    certificate_der = _signature_certificate()
    transport = _Transport()
    clock = _SingleUseClock()
    bank = Bank("https://bank.invalid/ebics", "HOST", "Synthetic Bank AG")
    subscriber = Subscriber("PARTNER=1", "USER,1", "SYSTEM1")
    client = ReadOnlyClient(
        bank,
        subscriber,
        EbicsBackend(
            transport,  # type: ignore[arg-type]
            key_provider=_Provider(certificate_der),
            clock=clock,
        ),
        InMemoryBankKeyTrustStore(),
    )

    letter = client.initialize_signature_key(object())  # type: ignore[arg-type]

    assert [request.order.value for request in transport.requests] == ["HEV", "INI"]
    assert clock.calls == 1
    request = transport.requests[-1]
    root = etree.fromstring(request.body)
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
    assert root.findtext(f".//{{{_H005}}}AdminOrderType") == "INI"
    assert root.findtext(f".//{{{_H005}}}SecurityMedium") == "0000"

    encoded = root.findtext(f".//{{{_H005}}}OrderData")
    assert encoded is not None
    inner = etree.fromstring(zlib.decompress(base64.b64decode(encoded, validate=True)))
    assert [etree.QName(element).localname for element in inner.iter()] == [
        "SignaturePubKeyOrderData",
        "SignaturePubKeyInfo",
        "X509Data",
        "X509Certificate",
        "SignatureVersion",
        "PartnerID",
        "UserID",
    ]
    assert inner.findtext(f".//{{{_S002}}}SignatureVersion") == "A006"
    assert inner.findtext(f"{{{_S002}}}PartnerID") == subscriber.partner_id
    assert inner.findtext(f"{{{_S002}}}UserID") == subscriber.user_id
    embedded = inner.findtext(f".//{{{_DS}}}X509Certificate")
    assert embedded is not None
    assert base64.b64decode(embedded, validate=True) == certificate_der

    digest = letter.public_key_digests[0].sha256_hex
    first_digest_line = " ".join(digest[index : index + 2] for index in range(0, 16, 2))
    assert first_digest_line.encode() in letter.content
    assert b"A006" in letter.content
    assert b"2026-08-08" in letter.content
    assert b"Synthetic Bank AG" in letter.content
    assert b"bank.invalid" not in letter.content
    pem = x509.load_der_x509_certificate(certificate_der).public_bytes(
        serialization.Encoding.PEM
    )
    assert pem.rstrip() in letter.content


def test_ini_rejects_invalid_subscriber_certificates_before_transport() -> None:
    invalid = (
        b"not-der",
        _signature_certificate(content_commitment=False),
        _signature_certificate(expired=True),
        _ec_certificate(),
    )
    bank = Bank("https://bank.invalid/ebics", "HOST", "Synthetic Bank AG")
    subscriber = Subscriber("PARTNER", "USER")
    for certificate_der in invalid:
        transport = _Transport()
        backend = EbicsBackend(
            transport,  # type: ignore[arg-type]
            key_provider=_Provider(certificate_der),
            clock=FixedClock(_NOW),
        )
        with pytest.raises(CertificateValidationError):
            backend.initialize_signature_key(
                bank,
                subscriber,
                NegotiatedProtocol(),
                object(),  # type: ignore[arg-type]
            )
        assert transport.requests == []


def test_ini_signature_certificate_profile_fails_closed() -> None:
    from ebics_read.certificates import _validate_subscriber_signature_certificate

    assert _validate_subscriber_signature_certificate(
        _signature_certificate(digital_signature=True), _NOW
    )
    assert _validate_subscriber_signature_certificate(
        _signature_certificate(aki_issuer_serial=True), _NOW
    )
    leap_now = datetime(2025, 2, 28, tzinfo=timezone.utc)
    assert _validate_subscriber_signature_certificate(
        _signature_certificate(now=leap_now), leap_now
    )
    assert _validate_subscriber_signature_certificate(
        _signature_certificate(
            not_after_override=datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        ),
        _NOW,
    )
    valid = _signature_certificate()
    damaged = valid[:-1] + bytes([valid[-1] ^ 1])
    invalid = (
        b"",
        valid + b"trailing",
        _signature_certificate(self_issued=False),
        _signature_certificate(signature_hash=hashes.SHA384()),
        _rsa_signed_ec_certificate(),
        _signature_certificate(key_size=1024),
        _signature_certificate(validity_days=5 * 366),
        _signature_certificate(
            not_after_override=datetime(9999, 12, 31, tzinfo=timezone.utc)
        ),
        _signature_certificate(include_ski=False),
        _signature_certificate(matching_aki=False),
        _signature_certificate(aki_issuer_serial=True, aki_serial_delta=1),
        _signature_certificate(extended_key_usage=True),
        damaged,
    )
    for certificate_der in invalid:
        with pytest.raises(CertificateValidationError):
            _validate_subscriber_signature_certificate(certificate_der, _NOW)
    with pytest.raises(CertificateValidationError, match="time"):
        _validate_subscriber_signature_certificate(
            valid,
            datetime(2026, 8, 8),  # noqa: DTZ001 - deliberate invalid input
        )


def test_ini_rejects_oversized_order_data_and_fake_protocol_before_transport() -> None:
    oversized_certificate = _signature_certificate(
        extra_extension=shake_256(b"synthetic oversized INI").digest(1_100_000)
    )
    transport = _Transport()
    bank = Bank("https://bank.invalid/ebics", "HOST", "Synthetic Bank AG")
    subscriber = Subscriber("PARTNER", "USER")
    backend = EbicsBackend(
        transport,  # type: ignore[arg-type]
        key_provider=_Provider(oversized_certificate),
        clock=FixedClock(_NOW),
    )
    with pytest.raises(ConfigurationError, match="one-message limit"):
        backend.initialize_signature_key(
            bank,
            subscriber,
            NegotiatedProtocol(),
            object(),  # type: ignore[arg-type]
        )
    assert transport.requests == []

    fake_protocol = type("FakeProtocol", (), {"protocol_version": "H004"})()
    with pytest.raises(TypeError, match="exact NegotiatedProtocol"):
        _PreparedTransportRequest._for_ini(
            bank,
            subscriber,
            fake_protocol,  # type: ignore[arg-type]
            b"synthetic-certificate",
        )


def test_ini_response_requires_exact_success_without_order_data() -> None:
    _parse_key_initialization_response(_ini_response(), XmlLimits())
    for response, expected in (
        (_ini_response(technical="091002", order_id=False), ("091002", "000000")),
        (_ini_response(business="091201", order_id=False), ("000000", "091201")),
    ):
        with pytest.raises(EbicsReturnCodeError) as rejected:
            _parse_key_initialization_response(response, XmlLimits())
        assert (rejected.value.technical, rejected.value.business) == expected
    for response in (
        _ini_response(technical="091002", business="091201", order_id=False),
        _ini_response(order_id=False),
        _ini_response(data_transfer=True),
        b"malformed response",
    ):
        with pytest.raises(AmbiguousTransportError, match="ambiguous"):
            _parse_key_initialization_response(response, XmlLimits())


def test_ini_configuration_fails_before_ini_and_ambiguous_attempt_keeps_letter() -> (
    None
):
    certificate_der = _signature_certificate()
    subscriber = Subscriber("PARTNER", "USER")
    transport = _Transport()
    backend = EbicsBackend(
        transport,  # type: ignore[arg-type]
        key_provider=_Provider(certificate_der),
        clock=FixedClock(_NOW),
    )
    with pytest.raises(ConfigurationError, match="institution name"):
        backend.initialize_signature_key(
            Bank("https://bank.invalid/ebics", "HOST"),
            subscriber,
            NegotiatedProtocol(),
            object(),  # type: ignore[arg-type]
        )
    assert transport.requests == []

    class AmbiguousTransport(_Transport):
        def exchange(
            self, request: _PreparedTransportRequest, control: object
        ) -> TransportResponse:
            self.requests.append(request)
            raise AmbiguousTransportError("synthetic unknown delivery")

    ambiguous_transport = AmbiguousTransport()
    ambiguous_backend = EbicsBackend(
        ambiguous_transport,  # type: ignore[arg-type]
        key_provider=_Provider(certificate_der),
        clock=FixedClock(_NOW),
    )
    with pytest.raises(AmbiguousInitializationError) as ambiguous:
        ambiguous_backend.initialize_signature_key(
            Bank("https://bank.invalid/ebics", "HOST", "Synthetic Bank AG"),
            subscriber,
            NegotiatedProtocol(),
            object(),  # type: ignore[arg-type]
        )
    assert ambiguous.value.pending_letter.order.value == "INI"
    assert ambiguous.value.pending_letter.content
    assert [request.order.value for request in ambiguous_transport.requests] == ["INI"]

    class TransientTransport(_Transport):
        def exchange(
            self, request: _PreparedTransportRequest, control: object
        ) -> TransportResponse:
            raise TransientTransportError("synthetic proven no-send")

    transient_backend = EbicsBackend(
        TransientTransport(),  # type: ignore[arg-type]
        key_provider=_Provider(certificate_der),
        clock=FixedClock(_NOW),
    )
    with pytest.raises(TransientTransportError):
        transient_backend.initialize_signature_key(
            Bank("https://bank.invalid/ebics", "HOST", "Synthetic Bank AG"),
            subscriber,
            NegotiatedProtocol(),
            object(),  # type: ignore[arg-type]
        )


def test_client_missing_ini_dependencies_sends_only_mandatory_hev() -> None:
    transport = _Transport()
    client = ReadOnlyClient(
        Bank("https://bank.invalid/ebics", "HOST", "Synthetic Bank AG"),
        Subscriber("PARTNER", "USER"),
        EbicsBackend(transport),  # type: ignore[arg-type]
        InMemoryBankKeyTrustStore(),
    )
    with pytest.raises(ConfigurationError, match="key provider and clock"):
        client.initialize_signature_key(object())  # type: ignore[arg-type]
    assert [request.order.value for request in transport.requests] == ["HEV"]
