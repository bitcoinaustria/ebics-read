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
    BankKeyNotTrustedError,
    BankKeyRole,
    ConfigurationError,
    EbicsBackend,
    EbicsPublicKeyDigest,
    EbicsReturnCodeError,
    KeyPurpose,
    ReadOnlyClient,
    ResponseLimitError,
    SecurityError,
    SelfSignedH005BankCertificateProfile,
    Subscriber,
    TransportResponse,
    UntrustedBankKeys,
    XmlSecurityError,
)
from ebics_read.hpb import _decompress_zlib
from ebics_read.testing import (
    DeterministicNonceSource,
    FixedClock,
    InMemoryBankKeyTrustStore,
    synthetic_out_of_band_identity,
)
from ebics_read.transport import _PreparedTransportRequest

_NOW = datetime(2026, 8, 8, 12, 30, 45, 123000, tzinfo=timezone.utc)
_H005 = "urn:org:ebics:H005"
_DS = "http://www.w3.org/2000/09/xmldsig#"
_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
_TRANSACTION_KEY = b"0123456789ABCDEF"
_HEV_RESPONSE = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<ebicsHEVResponse xmlns="http://www.ebics.org/H000">'
    b"<SystemReturnCode><ReturnCode>000000</ReturnCode>"
    b"<ReportText>EBICS_OK</ReportText></SystemReturnCode>"
    b'<VersionNumber ProtocolVersion="H005">03.00</VersionNumber>'
    b"</ebicsHEVResponse>"
)


def _certificate(role: KeyPurpose | BankKeyRole) -> tuple[rsa.RSAPrivateKey, bytes]:
    key = rsa.generate_private_key(public_exponent=65_537, key_size=2048)
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, f"Synthetic {role.value}")]
    )
    encryption = role in {KeyPurpose.ENCRYPTION, BankKeyRole.ENCRYPTION}
    bank = isinstance(role, BankKeyRole)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
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
    valid_signature: bool = True
    calls: list[object] = field(default_factory=list)

    def certificate_der(self, purpose: KeyPurpose) -> bytes:
        self.calls.append(purpose)
        if purpose is KeyPurpose.AUTHENTICATION:
            return self.authentication_der
        if purpose is KeyPurpose.ENCRYPTION:
            return self.encryption_der
        raise AssertionError("HPB must not request A006")

    def sign_x002(self, canonical_signed_info: bytes) -> bytes:
        self.calls.append(canonical_signed_info)
        if not self.valid_signature:
            return b"invalid"
        return self.authentication_key.sign(
            canonical_signed_info, padding.PKCS1v15(), hashes.SHA256()
        )

    def decrypt_e002_transaction_key(self, wrapped_key: bytes) -> bytes:
        self.calls.append(wrapped_key)
        assert wrapped_key == b"synthetic wrapped key"
        return _TRANSACTION_KEY


@dataclass
class _Transport:
    hpb_response: bytes
    requests: list[_PreparedTransportRequest] = field(default_factory=list)

    def exchange(
        self, request: _PreparedTransportRequest, control: object
    ) -> TransportResponse:
        self.requests.append(request)
        return TransportResponse(
            _HEV_RESPONSE if request.order.value == "HEV" else self.hpb_response
        )


def _response(
    subscriber_encryption_der: bytes,
    bank_authentication_der: bytes,
    bank_encryption_der: bytes,
    *,
    host_id: str = "HOST",
    authentication_version: str = "X002",
    digest: bytes | None = None,
    technical: str = "000000",
    business: str = "000000",
    include_transfer: bool = True,
    order_id: bool = False,
    trailing_zlib: bool = False,
) -> bytes:
    order = etree.Element(
        etree.QName(_H005, "HPBResponseOrderData"),
        nsmap={None: _H005, "ds": _DS},  # type: ignore[dict-item]
    )
    for info_name, version_name, version, certificate_der in (
        (
            "AuthenticationPubKeyInfo",
            "AuthenticationVersion",
            authentication_version,
            bank_authentication_der,
        ),
        (
            "EncryptionPubKeyInfo",
            "EncryptionVersion",
            "E002",
            bank_encryption_der,
        ),
    ):
        info = etree.SubElement(order, etree.QName(_H005, info_name))
        x509_data = etree.SubElement(info, etree.QName(_DS, "X509Data"))
        etree.SubElement(
            x509_data, etree.QName(_DS, "X509Certificate")
        ).text = base64.b64encode(certificate_der).decode("ascii")
        etree.SubElement(info, etree.QName(_H005, version_name)).text = version
    etree.SubElement(order, etree.QName(_H005, "HostID")).text = host_id
    compressed = zlib.compress(etree.tostring(order)) + (
        b"trailing" if trailing_zlib else b""
    )
    pad_length = 16 - len(compressed) % 16
    padded = compressed + b"\0" * (pad_length - 1) + bytes((pad_length,))
    encryptor = Cipher(
        algorithms.AES(_TRANSACTION_KEY), modes.CBC(b"\0" * 16)
    ).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    root = etree.Element(
        etree.QName(_H005, "ebicsKeyManagementResponse"),
        nsmap={None: _H005},  # type: ignore[dict-item]
        Version="H005",
        Revision="1",
    )
    header = etree.SubElement(root, etree.QName(_H005, "header"), authenticate="true")
    etree.SubElement(header, etree.QName(_H005, "static"))
    mutable = etree.SubElement(header, etree.QName(_H005, "mutable"))
    if order_id:
        etree.SubElement(mutable, etree.QName(_H005, "OrderID")).text = "A001"
    etree.SubElement(mutable, etree.QName(_H005, "ReturnCode")).text = technical
    etree.SubElement(mutable, etree.QName(_H005, "ReportText")).text = "synthetic"
    body = etree.SubElement(root, etree.QName(_H005, "body"))
    if include_transfer:
        transfer = etree.SubElement(body, etree.QName(_H005, "DataTransfer"))
        info = etree.SubElement(
            transfer, etree.QName(_H005, "DataEncryptionInfo"), authenticate="true"
        )
        recipient = etree.SubElement(
            info,
            etree.QName(_H005, "EncryptionPubKeyDigest"),
            Version="E002",
            Algorithm=_SHA256,
        )
        recipient.text = base64.b64encode(
            digest
            if digest is not None
            else bytes.fromhex(
                EbicsPublicKeyDigest.from_h005_certificate_der(
                    subscriber_encryption_der
                ).sha256_hex
            )
        ).decode("ascii")
        etree.SubElement(
            info, etree.QName(_H005, "TransactionKey")
        ).text = base64.b64encode(b"synthetic wrapped key").decode("ascii")
        etree.SubElement(
            transfer, etree.QName(_H005, "OrderData")
        ).text = base64.b64encode(ciphertext).decode("ascii")
    etree.SubElement(
        body, etree.QName(_H005, "ReturnCode"), authenticate="true"
    ).text = business
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def _setup(**response_options: object):
    authentication_key, authentication_der = _certificate(KeyPurpose.AUTHENTICATION)
    _, encryption_der = _certificate(KeyPurpose.ENCRYPTION)
    _, bank_authentication_der = _certificate(BankKeyRole.AUTHENTICATION)
    _, bank_encryption_der = _certificate(BankKeyRole.ENCRYPTION)
    provider = _Provider(authentication_key, authentication_der, encryption_der)
    transport = _Transport(
        _response(
            encryption_der,
            bank_authentication_der,
            bank_encryption_der,
            **response_options,  # type: ignore[arg-type]
        )
    )
    trust = InMemoryBankKeyTrustStore()
    bank = Bank("https://bank.invalid/ebics", "HOST")
    client = ReadOnlyClient(
        bank,
        Subscriber("PARTNER=1", "USER,1", "SYSTEM1"),
        EbicsBackend(
            transport,  # type: ignore[arg-type]
            key_provider=provider,
            clock=FixedClock(_NOW),
            nonce_source=DeterministicNonceSource(bytes(range(16))),
        ),
        trust,
    )
    return client, provider, transport, trust, bank


def test_hpb_fetches_validated_but_untrusted_bank_keys() -> None:
    client, provider, transport, trust, bank = _setup()

    candidate = client.fetch_bank_keys(object())  # type: ignore[arg-type]

    assert isinstance(candidate, UntrustedBankKeys)
    assert [request.order.value for request in transport.requests] == ["HEV", "HPB"]
    assert provider.calls[:2] == [KeyPurpose.AUTHENTICATION, KeyPurpose.ENCRYPTION]
    request = etree.fromstring(transport.requests[-1].body)
    assert request.tag == f"{{{_H005}}}ebicsNoPubKeyDigestsRequest"
    assert set(request.attrib) == {"Version", "Revision"}
    assert request.get("Version") == "H005"
    assert request.get("Revision") == "1"
    assert (
        request.findtext(f".//{{{_H005}}}Nonce") == "000102030405060708090A0B0C0D0E0F"
    )
    assert request.findtext(f".//{{{_H005}}}Timestamp") == "2026-08-08T12:30:45.123Z"
    assert request.findtext(f".//{{{_H005}}}AdminOrderType") == "HPB"
    assert request.findtext(f".//{{{_H005}}}SecurityMedium") == "0000"
    assert list(request)[-1].tag == f"{{{_H005}}}body" and not list(list(request)[-1])
    assert not request.xpath(
        "//*[local-name()='BankPubKeyDigests' or local-name()='OrderData']"
    )

    signed_info = request.find(f".//{{{_DS}}}SignedInfo")
    header = request.find(f"{{{_H005}}}header")
    digest = request.findtext(f".//{{{_DS}}}DigestValue")
    signature = request.findtext(f".//{{{_DS}}}SignatureValue")
    assert signed_info is not None and header is not None and digest and signature
    canonical_header = etree.tostring(header, method="c14n", exclusive=False)
    assert base64.b64decode(digest) == sha256(canonical_header).digest()
    provider.authentication_key.public_key().verify(
        base64.b64decode(signature),
        etree.tostring(signed_info, method="c14n", exclusive=False),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    with pytest.raises(BankKeyNotTrustedError):
        trust.require_trusted(bank)
    trusted = client.accept_bank_keys(
        candidate, synthetic_out_of_band_identity(candidate)
    )
    assert trust.require_trusted(bank) is trusted


@pytest.mark.parametrize(
    ("options", "error"),
    (
        ({"technical": "091103", "include_transfer": False}, EbicsReturnCodeError),
        ({"include_transfer": False}, XmlSecurityError),
        ({"technical": "091103"}, XmlSecurityError),
        ({"order_id": True}, XmlSecurityError),
        ({"digest": b"x" * 32}, SecurityError),
        ({"host_id": "OTHER"}, SecurityError),
        ({"authentication_version": "X001"}, SecurityError),
        ({"trailing_zlib": True}, SecurityError),
    ),
)
def test_hpb_rejects_invalid_or_failed_responses(
    options: dict[str, object], error: type[Exception]
) -> None:
    client, _, _, _, _ = _setup(**options)
    with pytest.raises(error):
        client.fetch_bank_keys(object())  # type: ignore[arg-type]


def test_hpb_rejects_bad_nonce_signature_and_decompression_limit() -> None:
    class BadNonceSource:
        def __init__(self, value: object) -> None:
            self.value = value

        def random_bytes(self, length: int) -> object:
            return self.value

    for nonce in (b"x" * 15, bytearray(16)):
        client, _, transport, _, _ = _setup()
        backend = client.backend
        assert isinstance(backend, EbicsBackend)
        object.__setattr__(backend, "nonce_source", BadNonceSource(nonce))
        with pytest.raises(ConfigurationError, match="exactly 16 bytes"):
            client.fetch_bank_keys(object())  # type: ignore[arg-type]
        assert [request.order.value for request in transport.requests] == ["HEV"]

    client, provider, _, _, _ = _setup()
    provider.valid_signature = False
    with pytest.raises(SecurityError, match="provider"):
        client.fetch_bank_keys(object())  # type: ignore[arg-type]

    with pytest.raises(ResponseLimitError):
        _decompress_zlib(zlib.compress(b"x" * 257), 256)
    with pytest.raises(SecurityError, match="complete"):
        _decompress_zlib(zlib.compress(b"content")[:-1], 256)
    with pytest.raises(SecurityError, match="complete"):
        _decompress_zlib(zlib.compress(b"content") + b"trailing", 256)


def test_hpb_uses_request_and_post_response_times() -> None:
    requested_at = _NOW + timedelta(seconds=1)
    received_at = _NOW + timedelta(seconds=2)

    @dataclass
    class SequenceClock:
        values: list[datetime] = field(
            default_factory=lambda: [requested_at, received_at]
        )

        def now(self) -> datetime:
            return self.values.pop(0)

    @dataclass
    class RecordingProfile:
        seen: list[datetime] = field(default_factory=list)

        def validate_pair(
            self,
            authentication_certificate_der: bytes,
            encryption_certificate_der: bytes,
            now: datetime,
        ) -> UntrustedBankKeys:
            self.seen.append(now)
            return SelfSignedH005BankCertificateProfile().validate_pair(
                authentication_certificate_der, encryption_certificate_der, now
            )

    client, _, transport, _, _ = _setup()
    backend = client.backend
    assert isinstance(backend, EbicsBackend)
    clock = SequenceClock()
    profile = RecordingProfile()
    object.__setattr__(backend, "clock", clock)
    object.__setattr__(backend, "bank_certificate_profile", profile)

    client.fetch_bank_keys(object())  # type: ignore[arg-type]

    request = etree.fromstring(transport.requests[-1].body)
    assert request.findtext(f".//{{{_H005}}}Timestamp") == "2026-08-08T12:30:46.123Z"
    assert profile.seen == [received_at]
    assert clock.values == []
