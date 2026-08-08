from __future__ import annotations

import base64
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID
from lxml import etree

from ebics_read import (
    Bank,
    BankKeyRole,
    CapabilityDiscovery,
    ConfigurationError,
    ContainerType,
    EbicsBackend,
    EbicsPublicKeyDigest,
    EbicsReturnCodeError,
    KeyPurpose,
    NegotiatedProtocol,
    OrderType,
    ProtocolLimits,
    ReplayError,
    ResponseLimitError,
    SecurityError,
    SelfSignedH005BankCertificateProfile,
    Subscriber,
    TransportResponse,
    TrustedBankKeys,
    XmlSecurityError,
)
from ebics_read.haa import _parse_haa_initial_response, _parse_haa_services
from ebics_read.testing import (
    DeterministicNonceSource,
    FixedClock,
    InMemorySessionStore,
    synthetic_out_of_band_identity,
)
from ebics_read.transport import _PreparedTransportRequest

_NOW = datetime(2026, 8, 8, 12, 30, 45, 123000, tzinfo=timezone.utc)
_H005 = "urn:org:ebics:H005"
_DS = "http://www.w3.org/2000/09/xmldsig#"
_C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
_REFERENCE = "#xpointer(//*[@authenticate='true'])"
_TRANSACTION_ID = "00112233445566778899AABBCCDDEEFF"
_TRANSACTION_KEY = b"0123456789ABCDEF"


def _certificate(
    role: KeyPurpose | BankKeyRole,
) -> tuple[rsa.RSAPrivateKey, bytes]:
    key = rsa.generate_private_key(public_exponent=65_537, key_size=2048)
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, f"Synthetic HAA {role.value}")]
    )
    encryption = role in {KeyPurpose.ENCRYPTION, BankKeyRole.ENCRYPTION}
    bank = isinstance(role, BankKeyRole)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(_NOW - timedelta(days=1))
        .not_valid_after(_NOW + timedelta(days=365))
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
                digital_signature=not encryption or bank,
                content_commitment=False,
                key_encipherment=encryption,
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
    return key, certificate.public_bytes(serialization.Encoding.DER)


@dataclass
class _Provider:
    authentication_key: rsa.RSAPrivateKey
    authentication_der: bytes
    encryption_der: bytes

    def certificate_der(self, purpose: KeyPurpose) -> bytes:
        if purpose is KeyPurpose.AUTHENTICATION:
            return self.authentication_der
        if purpose is KeyPurpose.ENCRYPTION:
            return self.encryption_der
        raise AssertionError("HAA must not request A006")

    def sign_x002(self, canonical_signed_info: bytes) -> bytes:
        return self.authentication_key.sign(
            canonical_signed_info, padding.PKCS1v15(), hashes.SHA256()
        )

    def decrypt_e002_transaction_key(self, wrapped_key: bytes) -> bytes:
        assert wrapped_key == b"synthetic wrapped key"
        return _TRANSACTION_KEY


@dataclass
class _Transport:
    bank_key: rsa.RSAPrivateKey
    encryption_der: bytes
    fragments: tuple[str, ...]
    technical: str = "000000"
    business: str = "000000"
    transfer_technical: str | None = None
    tamper_segment: int | None = None
    fragments_by_order: dict[OrderType, tuple[str, ...]] | None = None
    transaction_ids_by_order: dict[OrderType, str] | None = None
    technical_by_order: dict[OrderType, str] | None = None
    transaction_id: str = _TRANSACTION_ID
    bank_parameter_timestamp: datetime | None = None
    requests: list[_PreparedTransportRequest] = field(default_factory=list)

    def exchange(
        self, request: _PreparedTransportRequest, control: object
    ) -> TransportResponse:
        self.requests.append(request)
        root = etree.fromstring(request.body)
        phase = root.findtext(f".//{{{_H005}}}TransactionPhase")
        if phase == "Initialisation":
            if self.fragments_by_order is not None:
                self.fragments = self.fragments_by_order[request.order]
            if self.transaction_ids_by_order is not None:
                self.transaction_id = self.transaction_ids_by_order[request.order]
            technical = (
                self.technical_by_order.get(request.order, self.technical)
                if self.technical_by_order is not None
                else self.technical
            )
            if technical != "000000" or self.business != "000000":
                return TransportResponse(
                    _response(
                        self.bank_key,
                        phase,
                        transaction_id=(
                            self.transaction_id if technical == "000000" else None
                        ),
                        technical=technical,
                        business=self.business,
                    )
                )
            return TransportResponse(
                _response(
                    self.bank_key,
                    phase,
                    transaction_id=self.transaction_id,
                    total_segments=len(self.fragments),
                    segment_number=1,
                    fragment=self.fragments[0],
                    encryption_der=self.encryption_der,
                    bank_parameter_timestamp=self.bank_parameter_timestamp,
                )
            )
        if phase == "Transfer":
            segment = int(root.findtext(f".//{{{_H005}}}SegmentNumber") or "0")
            if self.transfer_technical is not None:
                return TransportResponse(
                    _response(
                        self.bank_key,
                        phase,
                        transaction_id=self.transaction_id,
                        segment_number=segment,
                        total_segments=len(self.fragments),
                        technical=self.transfer_technical,
                    )
                )
            response = _response(
                self.bank_key,
                phase,
                transaction_id=self.transaction_id,
                segment_number=segment,
                total_segments=len(self.fragments),
                fragment=self.fragments[segment - 1],
            )
            if self.tamper_segment == segment:
                response = response.replace(
                    f">{segment}</SegmentNumber>".encode(),
                    b">9</SegmentNumber>",
                    1,
                )
            return TransportResponse(response)
        if phase == "Receipt":
            code = root.findtext(f".//{{{_H005}}}ReceiptCode")
            return TransportResponse(
                _response(
                    self.bank_key,
                    phase,
                    transaction_id=self.transaction_id,
                    technical="011000" if code == "0" else "011001",
                )
            )
        raise AssertionError("unexpected HAA transaction phase")


def _response(
    bank_key: rsa.RSAPrivateKey,
    phase: str,
    *,
    transaction_id: str | None = None,
    total_segments: int | None = None,
    segment_number: int | None = None,
    fragment: str | None = None,
    encryption_der: bytes | None = None,
    technical: str = "000000",
    business: str = "000000",
    bank_parameter_timestamp: datetime | None = None,
) -> bytes:
    root = etree.Element(
        etree.QName(_H005, "ebicsResponse"),
        nsmap={None: _H005, "ds": _DS},  # type: ignore[dict-item]
        Version="H005",
        Revision="1",
    )
    header = etree.SubElement(root, etree.QName(_H005, "header"), authenticate="true")
    static = etree.SubElement(header, etree.QName(_H005, "static"))
    if transaction_id is not None:
        etree.SubElement(
            static, etree.QName(_H005, "TransactionID")
        ).text = transaction_id
    if total_segments is not None and phase == "Initialisation":
        etree.SubElement(static, etree.QName(_H005, "NumSegments")).text = str(
            total_segments
        )
    mutable = etree.SubElement(header, etree.QName(_H005, "mutable"))
    etree.SubElement(mutable, etree.QName(_H005, "TransactionPhase")).text = phase
    if segment_number is not None:
        segment = etree.SubElement(mutable, etree.QName(_H005, "SegmentNumber"))
        segment.set("lastSegment", str(segment_number == total_segments).lower())
        segment.text = str(segment_number)
    etree.SubElement(mutable, etree.QName(_H005, "ReturnCode")).text = technical
    etree.SubElement(mutable, etree.QName(_H005, "ReportText")).text = "synthetic"

    body = etree.SubElement(root, etree.QName(_H005, "body"))
    if fragment is not None:
        transfer = etree.SubElement(body, etree.QName(_H005, "DataTransfer"))
        if phase == "Initialisation":
            assert encryption_der is not None
            info = etree.SubElement(
                transfer,
                etree.QName(_H005, "DataEncryptionInfo"),
                authenticate="true",
            )
            digest = etree.SubElement(
                info,
                etree.QName(_H005, "EncryptionPubKeyDigest"),
                Version="E002",
                Algorithm=_SHA256,
            )
            digest.text = base64.b64encode(
                bytes.fromhex(
                    EbicsPublicKeyDigest.from_h005_certificate_der(
                        encryption_der
                    ).sha256_hex
                )
            ).decode()
            etree.SubElement(
                info, etree.QName(_H005, "TransactionKey")
            ).text = base64.b64encode(b"synthetic wrapped key").decode()
        etree.SubElement(transfer, etree.QName(_H005, "OrderData")).text = fragment
    etree.SubElement(
        body, etree.QName(_H005, "ReturnCode"), authenticate="true"
    ).text = business
    if bank_parameter_timestamp is not None:
        etree.SubElement(
            body,
            etree.QName(_H005, "TimestampBankParameter"),
            authenticate="true",
        ).text = bank_parameter_timestamp.isoformat().replace("+00:00", "Z")
    _sign_response(root, bank_key)
    return etree.tostring(root, encoding="UTF-8", xml_declaration=True)


def _sign_response(root: etree._Element, key: rsa.RSAPrivateKey) -> None:
    signature = etree.Element(etree.QName(_H005, "AuthSignature"))
    root.insert(1, signature)
    signed_info = etree.SubElement(signature, etree.QName(_DS, "SignedInfo"))
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
    authenticated = [
        element
        for element in root.iter()
        if element.get("authenticate") == "true"
        and not any(
            ancestor.get("authenticate") == "true"
            for ancestor in element.iterancestors()
        )
    ]
    etree.SubElement(
        reference, etree.QName(_DS, "DigestValue")
    ).text = base64.b64encode(
        sha256(
            b"".join(
                etree.tostring(element, method="c14n", exclusive=False)
                for element in authenticated
            )
        ).digest()
    ).decode()
    etree.SubElement(
        signature, etree.QName(_DS, "SignatureValue")
    ).text = base64.b64encode(
        key.sign(
            etree.tostring(signed_info, method="c14n", exclusive=False),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    ).decode()


def _order_data(*, invalid: bool = False) -> bytes:
    root = etree.Element(
        etree.QName(_H005, "HAAResponseOrderData"), nsmap={None: _H005}
    )
    if invalid:
        etree.SubElement(root, etree.QName(_H005, "Unsupported"))
        return etree.tostring(root)
    for index, container in enumerate(
        (ContainerType.NONE, ContainerType.ZIP, ContainerType.XML, ContainerType.SVC)
    ):
        service = etree.SubElement(root, etree.QName(_H005, "Service"))
        etree.SubElement(service, etree.QName(_H005, "ServiceName")).text = f"S{index}A"
        etree.SubElement(service, etree.QName(_H005, "Scope")).text = "AT"
        etree.SubElement(service, etree.QName(_H005, "ServiceOption")).text = "OPT"
        if container is not ContainerType.NONE:
            etree.SubElement(
                service,
                etree.QName(_H005, "Container"),
                containerType=container.value,
            )
        etree.SubElement(
            service,
            etree.QName(_H005, "MsgName"),
            version="08",
            variant="001",
            format="XML",
        ).text = f"camt.05{index}"
    return etree.tostring(root)


def _fragments(
    *, invalid: bool = False, order_data: bytes | None = None
) -> tuple[str, str]:
    compressed = zlib.compress(
        _order_data(invalid=invalid) if order_data is None else order_data
    )
    padding_length = 16 - len(compressed) % 16
    padded = compressed + b"\0" * (padding_length - 1) + bytes((padding_length,))
    encryptor = Cipher(
        algorithms.AES(_TRANSACTION_KEY), modes.CBC(b"\0" * 16)
    ).encryptor()
    encoded = base64.b64encode(encryptor.update(padded) + encryptor.finalize()).decode()
    return encoded[:8], encoded[8:]


def _setup(
    *,
    invalid: bool = False,
    technical: str = "000000",
    business: str = "000000",
    limits: ProtocolLimits | None = None,
    order_data: bytes | None = None,
) -> tuple[EbicsBackend, _Transport, TrustedBankKeys]:
    subscriber_key, subscriber_authentication = _certificate(KeyPurpose.AUTHENTICATION)
    _, subscriber_encryption = _certificate(KeyPurpose.ENCRYPTION)
    bank_key, bank_authentication = _certificate(BankKeyRole.AUTHENTICATION)
    _, bank_encryption = _certificate(BankKeyRole.ENCRYPTION)
    candidate = SelfSignedH005BankCertificateProfile().validate_pair(
        bank_authentication, bank_encryption, _NOW
    )
    trusted = TrustedBankKeys.accept_out_of_band(
        candidate, synthetic_out_of_band_identity(candidate)
    )
    transport = _Transport(
        bank_key,
        subscriber_encryption,
        _fragments(invalid=invalid, order_data=order_data),
        technical,
        business,
    )
    backend = EbicsBackend(
        transport,  # type: ignore[arg-type]
        key_provider=_Provider(
            subscriber_key, subscriber_authentication, subscriber_encryption
        ),
        clock=FixedClock(_NOW),
        nonce_source=DeterministicNonceSource(bytes(range(16))),
        session_store=InMemorySessionStore(),
        protocol_limits=limits or ProtocolLimits(),
    )
    return backend, transport, trusted


def _discover(backend: EbicsBackend, trusted: TrustedBankKeys) -> CapabilityDiscovery:
    return backend._discover_haa(
        Bank("https://bank.invalid/ebics", "HOST"),
        Subscriber("PARTNER=1", "USER,1", "SYSTEM1"),
        NegotiatedProtocol(),
        trusted,
        object(),  # type: ignore[arg-type]
    )


def _assert_request_signature(request: bytes, key: rsa.RSAPrivateKey) -> None:
    root = etree.fromstring(request)
    authenticated = [
        element
        for element in root.iter()
        if element.get("authenticate") == "true"
        and not any(
            ancestor.get("authenticate") == "true"
            for ancestor in element.iterancestors()
        )
    ]
    digest = root.findtext(f".//{{{_DS}}}DigestValue")
    signed_info = root.find(f".//{{{_DS}}}SignedInfo")
    signature = root.findtext(f".//{{{_DS}}}SignatureValue")
    assert digest is not None and signed_info is not None and signature is not None
    assert (
        base64.b64decode(digest, validate=True)
        == sha256(
            b"".join(
                etree.tostring(element, method="c14n", exclusive=False)
                for element in authenticated
            )
        ).digest()
    )
    key.public_key().verify(
        base64.b64decode(signature, validate=True),
        etree.tostring(signed_info, method="c14n", exclusive=False),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def test_haa_downloads_split_capabilities_then_sends_positive_receipt() -> None:
    backend, transport, trusted = _setup()

    result = _discover(backend, trusted)

    assert result.completed_orders == (OrderType.HAA,)
    assert [service.descriptor.container_type for service in result.services] == [
        ContainerType.NONE,
        ContainerType.ZIP,
        ContainerType.XML,
        ContainerType.SVC,
    ]
    assert len(transport.requests) == 3
    phases = [
        etree.fromstring(request.body).findtext(f".//{{{_H005}}}TransactionPhase")
        for request in transport.requests
    ]
    assert phases == ["Initialisation", "Transfer", "Receipt"]
    initialization = etree.fromstring(transport.requests[0].body)
    assert initialization.findtext(f".//{{{_H005}}}AdminOrderType") == "HAA"
    assert initialization.findtext(f".//{{{_H005}}}Nonce") == (
        "000102030405060708090A0B0C0D0E0F"
    )
    assert initialization.findtext(f".//{{{_H005}}}Timestamp") == (
        "2026-08-08T12:30:45.123Z"
    )
    assert initialization.findall(f".//{{{_H005}}}StandardOrderParams")
    receipt = etree.fromstring(transport.requests[-1].body)
    assert receipt.findtext(f".//{{{_H005}}}ReceiptCode") == "0"
    assert isinstance(backend.key_provider, _Provider)
    for request in transport.requests:
        _assert_request_signature(request.body, backend.key_provider.authentication_key)


def test_haa_sends_negative_receipt_only_after_complete_invalid_data() -> None:
    backend, transport, trusted = _setup(invalid=True)

    with pytest.raises(XmlSecurityError, match="unsupported extension"):
        _discover(backend, trusted)

    assert len(transport.requests) == 3
    receipt = etree.fromstring(transport.requests[-1].body)
    assert receipt.findtext(f".//{{{_H005}}}ReceiptCode") == "1"


def test_haa_maps_only_authenticated_unsupported_order_and_rejects_replay() -> None:
    backend, transport, trusted = _setup(technical="091006")
    result = _discover(backend, trusted)
    assert result.unsupported_orders == (OrderType.HAA,)
    assert len(transport.requests) == 1

    backend, transport, trusted = _setup()
    _discover(backend, trusted)
    with pytest.raises(ReplayError):
        _discover(backend, trusted)
    assert len(transport.requests) == 4

    backend, _, trusted = _setup(business="090005")
    with pytest.raises(EbicsReturnCodeError) as rejected:
        _discover(backend, trusted)
    assert (rejected.value.technical, rejected.value.business) == (
        "000000",
        "090005",
    )

    backend, transport, trusted = _setup()
    transport.transfer_technical = "091006"
    with pytest.raises(EbicsReturnCodeError) as mid_transaction:
        _discover(backend, trusted)
    assert mid_transaction.value.technical == "091006"
    assert len(transport.requests) == 2


def test_haa_rejects_malformed_unsupported_response() -> None:
    backend, transport, trusted = _setup()
    assert backend.key_provider is not None
    with pytest.raises(XmlSecurityError, match="phase"):
        _parse_haa_initial_response(
            _response(transport.bank_key, "Transfer", technical="091006"),
            trusted,
            transport.encryption_der,
            backend.key_provider,
            backend.xml_limits,
            backend.protocol_limits,
        )


def test_haa_distinguishes_incomplete_from_complete_payload_failures() -> None:
    backend, transport, trusted = _setup()
    transport.tamper_segment = 2
    with pytest.raises(SecurityError, match="digest"):
        _discover(backend, trusted)
    assert len(transport.requests) == 2

    backend, transport, trusted = _setup(limits=ProtocolLimits(max_segments=1))
    with pytest.raises(ResponseLimitError, match="segment count"):
        _discover(backend, trusted)
    assert len(transport.requests) == 1

    backend, transport, trusted = _setup()
    encoded = "".join(transport.fragments)
    transport.fragments = (encoded[:5], encoded[5:])
    with pytest.raises(XmlSecurityError, match="valid base64"):
        _discover(backend, trusted)
    assert len(transport.requests) == 1

    backend, transport, trusted = _setup()
    transport.fragments = ("BaHCI",)
    with pytest.raises(XmlSecurityError, match="valid base64"):
        _discover(backend, trusted)
    assert len(transport.requests) == 2
    receipt = etree.fromstring(transport.requests[-1].body)
    assert receipt.findtext(f".//{{{_H005}}}ReceiptCode") == "1"

    backend, transport, trusted = _setup()
    transport.fragments = ("QUFB", "x")
    with pytest.raises(XmlSecurityError, match="valid base64"):
        _discover(backend, trusted)
    assert len(transport.requests) == 3
    receipt = etree.fromstring(transport.requests[-1].body)
    assert receipt.findtext(f".//{{{_H005}}}ReceiptCode") == "1"

    backend, transport, trusted = _setup()
    transport.fragments = ("QUFB", "")
    with pytest.raises(XmlSecurityError, match="invalid shape"):
        _discover(backend, trusted)
    assert len(transport.requests) == 3
    receipt = etree.fromstring(transport.requests[-1].body)
    assert receipt.findtext(f".//{{{_H005}}}ReceiptCode") == "1"

    backend, transport, trusted = _setup(limits=ProtocolLimits(max_compressed_bytes=1))
    encoded = "".join(transport.fragments)
    transport.fragments = (encoded[:16], encoded[16:32], encoded[32:])
    with pytest.raises(ResponseLimitError, match="encoded order data"):
        _discover(backend, trusted)
    assert len(transport.requests) == 2

    backend, transport, trusted = _setup(limits=ProtocolLimits(max_compressed_bytes=1))
    transport.fragments = ("".join(transport.fragments),)
    with pytest.raises(ResponseLimitError, match="encoded order data"):
        _discover(backend, trusted)
    assert len(transport.requests) == 2
    receipt = etree.fromstring(transport.requests[-1].body)
    assert receipt.findtext(f".//{{{_H005}}}ReceiptCode") == "1"


@pytest.mark.parametrize(
    "xml",
    (
        f'<HAAResponseOrderData xmlns="{_H005}"><Service/></HAAResponseOrderData>',
        f'<HAAResponseOrderData xmlns="{_H005}"><Service>'
        "<ServiceName>BAD!</ServiceName><MsgName>x</MsgName>"
        "</Service></HAAResponseOrderData>",
        f'<HAAResponseOrderData xmlns="{_H005}"><Service>'
        '<ServiceName>STM</ServiceName><Container containerType="NONE"/>'
        "<MsgName>x</MsgName></Service></HAAResponseOrderData>",
        f'<HAAResponseOrderData xmlns="{_H005}"><Service>'
        '<ServiceName>STM</ServiceName><MsgName bad="x">x</MsgName>'
        "</Service></HAAResponseOrderData>",
    ),
)
def test_haa_rejects_invalid_service_shapes(xml: str) -> None:
    with pytest.raises(XmlSecurityError):
        _parse_haa_services(etree.fromstring(xml.encode()))


def test_haa_requires_all_state_and_crypto_dependencies() -> None:
    backend = EbicsBackend(object())  # type: ignore[arg-type]
    with pytest.raises(ConfigurationError, match="session store"):
        _discover(backend, object())  # type: ignore[arg-type]
