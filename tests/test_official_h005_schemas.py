"""Opt-in compilation of the hash-pinned, separately supplied H005 schemas."""

# ruff: noqa: E501 -- reviewed SHA-256 values stay contiguous for auditability.

import base64
import os
import zlib
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from test_haa import _discover as _discover_haa
from test_haa import _order_data as _haa_order_data
from test_haa import _response as _haa_response
from test_haa import _setup as _setup_haa
from test_hpd import _order_data as _hpd_order_data

from ebics_read import Bank, KeyPurpose, NegotiatedProtocol, Subscriber
from ebics_read.transport import _PreparedTransportRequest

_OFFICIAL_SCHEMA_SHA256 = {
    "ebics_H005.xsd": "cf9d5d29fac0950f810c2a0018312fe476ab3415d804f5fc00cd4e3aa216136e",
    "ebics_keymgmt_request_H005.xsd": "7165cd441a0c68f6e93c384de743f97d0d768ac444d1adc6daf89d0e1edb0505",
    "ebics_keymgmt_response_H005.xsd": "9671ccf4282df1a4089f5d61a86378fa78e38d80292550a34422e15aa802ef3f",
    "ebics_orders_H005.xsd": "ce19f0e0b8cdfa05678a9e2123e09634f131107e08552e7a1371e6dbbf82e2f1",
    "ebics_request_H005.xsd": "48838ffd60275549849a7054223085154746b920e5f438cd16878fc62004d874",
    "ebics_response_H005.xsd": "19226688cd598581b37a7b32cb1df874c525aac710f68dbcc10e11b820eabd4d",
    "ebics_signature_S002.xsd": "6fcee44bdb80d656e05f11da86303bb25de2cf545203eef30dffbd6c662f8d93",
    "ebics_types_H005.xsd": "0c94813782e725b7698449f117a8f2e6e47d6560b3df83ca53a720d6f6fc4351",
    "xmldsig-core-schema.xsd": "43f97eddd32ca6df482ff1757cd55d784054fa36cb35d882ddc1e52669a37af6",
}


def _reviewed_schema_bundle(directory: Path) -> None:
    for name, expected_digest in _OFFICIAL_SCHEMA_SHA256.items():
        path = directory / name
        if (
            not path.is_file()
            or sha256(path.read_bytes()).hexdigest() != expected_digest
        ):
            raise ValueError(f"{name} does not match the reviewed official file")


def _official_schema_directory() -> Path:
    configured = os.environ.get("EBICS_READ_H005_XSD_DIR")
    if configured is None:
        pytest.skip(
            "set EBICS_READ_H005_XSD_DIR to the separately downloaded schema directory"
        )
    directory = Path(configured)
    if not directory.is_dir():
        pytest.fail("EBICS_READ_H005_XSD_DIR does not identify a directory")
    try:
        _reviewed_schema_bundle(directory)
    except ValueError as exc:
        pytest.fail(str(exc))
    return directory


@pytest.mark.schema
def test_external_official_h005_and_s002_schema_sets_compile() -> None:
    directory = _official_schema_directory()
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        recover=False,
        huge_tree=False,
    )

    assert etree.XMLSchema(etree.parse(directory / "ebics_H005.xsd", parser))
    assert etree.XMLSchema(etree.parse(directory / "ebics_signature_S002.xsd", parser))


@pytest.mark.schema
def test_generated_ini_matches_external_official_h005_and_s002_schemas() -> None:
    directory = _official_schema_directory()
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        recover=False,
        huge_tree=False,
    )
    request = _PreparedTransportRequest._for_ini(
        Bank("https://bank.invalid/ebics", "HOST"),
        Subscriber("PARTNER=1", "USER,1", "SYSTEM1"),
        NegotiatedProtocol(),
        b"synthetic-certificate",
    )
    outer = etree.fromstring(request.body, parser)
    request_schema = etree.XMLSchema(
        etree.parse(directory / "ebics_keymgmt_request_H005.xsd", parser)
    )
    request_schema.assertValid(outer)

    encoded = outer.findtext(".//{urn:org:ebics:H005}OrderData")
    assert encoded is not None
    inner = etree.fromstring(zlib.decompress(base64.b64decode(encoded)), parser)
    signature_schema = etree.XMLSchema(
        etree.parse(directory / "ebics_signature_S002.xsd", parser)
    )
    signature_schema.assertValid(inner)


@pytest.mark.schema
def test_generated_hia_matches_external_official_h005_schemas() -> None:
    directory = _official_schema_directory()
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        recover=False,
        huge_tree=False,
    )
    authentication_der = b"synthetic authentication certificate"
    encryption_der = b"synthetic encryption certificate"
    request = _PreparedTransportRequest._for_hia(
        Bank("https://bank.invalid/ebics", "HOST"),
        Subscriber("PARTNER=1", "USER,1", "SYSTEM1"),
        NegotiatedProtocol(),
        authentication_der,
        encryption_der,
    )
    outer = etree.fromstring(request.body, parser)
    etree.XMLSchema(
        etree.parse(directory / "ebics_keymgmt_request_H005.xsd", parser)
    ).assertValid(outer)
    assert outer.findtext(".//{urn:org:ebics:H005}AdminOrderType") == "HIA"
    assert outer.findtext(".//{urn:org:ebics:H005}SecurityMedium") == "0000"
    assert not outer.xpath("//*[local-name()='Nonce' or local-name()='Timestamp']")

    encoded = outer.findtext(".//{urn:org:ebics:H005}OrderData")
    assert encoded is not None
    inner = etree.fromstring(
        zlib.decompress(base64.b64decode(encoded, validate=True)), parser
    )
    etree.XMLSchema(
        etree.parse(directory / "ebics_orders_H005.xsd", parser)
    ).assertValid(inner)
    assert inner.findtext(".//{urn:org:ebics:H005}AuthenticationVersion") == "X002"
    assert inner.findtext(".//{urn:org:ebics:H005}EncryptionVersion") == "E002"
    certificates = inner.findall(
        ".//{http://www.w3.org/2000/09/xmldsig#}X509Certificate"
    )
    assert [
        base64.b64decode(value.text or "", validate=True) for value in certificates
    ] == [
        authentication_der,
        encryption_der,
    ]


@pytest.mark.schema
def test_generated_hpb_request_and_synthetic_response_match_official_schemas() -> None:
    directory = _official_schema_directory()
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        recover=False,
        huge_tree=False,
    )
    now = datetime(2026, 8, 8, tzinfo=timezone.utc)
    key = rsa.generate_private_key(public_exponent=65_537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic HPB")])
    certificate_der = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )

    class Provider:
        def certificate_der(self, purpose: KeyPurpose) -> bytes:
            return certificate_der

        def sign_x002(self, canonical_signed_info: bytes) -> bytes:
            return key.sign(canonical_signed_info, padding.PKCS1v15(), hashes.SHA256())

        def decrypt_e002_transaction_key(self, wrapped_key: bytes) -> bytes:
            raise AssertionError("schema test must not decrypt")

    request = _PreparedTransportRequest._for_hpb(
        Bank("https://bank.invalid/ebics", "HOST"),
        Subscriber("PARTNER=1", "USER,1", "SYSTEM1"),
        NegotiatedProtocol(),
        bytes(range(16)),
        now,
        Provider(),
        certificate_der,
    )
    outer = etree.fromstring(request.body, parser)
    etree.XMLSchema(
        etree.parse(directory / "ebics_keymgmt_request_H005.xsd", parser)
    ).assertValid(outer)
    assert outer.findtext(".//{urn:org:ebics:H005}AdminOrderType") == "HPB"
    assert not outer.xpath(
        "//*[local-name()='BankPubKeyDigests' or local-name()='OrderData']"
    )

    h005 = "urn:org:ebics:H005"
    ds = "http://www.w3.org/2000/09/xmldsig#"
    order = etree.Element(
        etree.QName(h005, "HPBResponseOrderData"),
        nsmap={None: h005, "ds": ds},  # type: ignore[dict-item]
    )
    for info_name, version_name, version in (
        ("AuthenticationPubKeyInfo", "AuthenticationVersion", "X002"),
        ("EncryptionPubKeyInfo", "EncryptionVersion", "E002"),
    ):
        info = etree.SubElement(order, etree.QName(h005, info_name))
        x509_data = etree.SubElement(info, etree.QName(ds, "X509Data"))
        etree.SubElement(
            x509_data, etree.QName(ds, "X509Certificate")
        ).text = base64.b64encode(certificate_der).decode("ascii")
        etree.SubElement(info, etree.QName(h005, version_name)).text = version
    etree.SubElement(order, etree.QName(h005, "HostID")).text = "HOST"
    etree.XMLSchema(
        etree.parse(directory / "ebics_orders_H005.xsd", parser)
    ).assertValid(order)

    response = etree.Element(
        etree.QName(h005, "ebicsKeyManagementResponse"),
        nsmap={None: h005},  # type: ignore[dict-item]
        Version="H005",
        Revision="1",
    )
    header = etree.SubElement(
        response, etree.QName(h005, "header"), authenticate="true"
    )
    etree.SubElement(header, etree.QName(h005, "static"))
    mutable = etree.SubElement(header, etree.QName(h005, "mutable"))
    etree.SubElement(mutable, etree.QName(h005, "ReturnCode")).text = "000000"
    etree.SubElement(mutable, etree.QName(h005, "ReportText")).text = "synthetic"
    body = etree.SubElement(response, etree.QName(h005, "body"))
    transfer = etree.SubElement(body, etree.QName(h005, "DataTransfer"))
    encryption = etree.SubElement(
        transfer, etree.QName(h005, "DataEncryptionInfo"), authenticate="true"
    )
    etree.SubElement(
        encryption,
        etree.QName(h005, "EncryptionPubKeyDigest"),
        Version="E002",
        Algorithm="http://www.w3.org/2001/04/xmlenc#sha256",
    ).text = base64.b64encode(b"x" * 32).decode("ascii")
    etree.SubElement(encryption, etree.QName(h005, "TransactionKey")).text = "eA=="
    etree.SubElement(transfer, etree.QName(h005, "OrderData")).text = "eA=="
    etree.SubElement(
        body, etree.QName(h005, "ReturnCode"), authenticate="true"
    ).text = "000000"
    etree.XMLSchema(
        etree.parse(directory / "ebics_keymgmt_response_H005.xsd", parser)
    ).assertValid(response)


@pytest.mark.schema
def test_generated_haa_transaction_matches_external_official_h005_schemas() -> None:
    directory = _official_schema_directory()
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        recover=False,
        huge_tree=False,
    )
    backend, transport, trusted = _setup_haa()
    _discover_haa(backend, trusted)
    request_schema = etree.XMLSchema(
        etree.parse(directory / "ebics_request_H005.xsd", parser)
    )
    for request in transport.requests:
        request_schema.assertValid(etree.fromstring(request.body, parser))
    response_schema = etree.XMLSchema(
        etree.parse(directory / "ebics_response_H005.xsd", parser)
    )
    for response in (
        _haa_response(
            transport.bank_key,
            "Initialisation",
            transaction_id="00112233445566778899AABBCCDDEEFF",
            total_segments=2,
            segment_number=1,
            fragment=transport.fragments[0],
            encryption_der=transport.encryption_der,
        ),
        _haa_response(
            transport.bank_key,
            "Transfer",
            transaction_id="00112233445566778899AABBCCDDEEFF",
            total_segments=2,
            segment_number=2,
            fragment=transport.fragments[1],
        ),
        _haa_response(
            transport.bank_key,
            "Receipt",
            transaction_id="00112233445566778899AABBCCDDEEFF",
            technical="011000",
        ),
    ):
        response_schema.assertValid(etree.fromstring(response, parser))
    etree.XMLSchema(
        etree.parse(directory / "ebics_orders_H005.xsd", parser)
    ).assertValid(etree.fromstring(_haa_order_data(), parser))


@pytest.mark.schema
def test_synthetic_hpd_order_data_matches_external_official_h005_schema() -> None:
    directory = _official_schema_directory()
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        recover=False,
        huge_tree=False,
    )
    etree.XMLSchema(
        etree.parse(directory / "ebics_orders_H005.xsd", parser)
    ).assertValid(etree.fromstring(_hpd_order_data(), parser))


def test_rejects_replacement_h005_schema_bundle(tmp_path: Path) -> None:
    for name in _OFFICIAL_SCHEMA_SHA256:
        (tmp_path / name).write_bytes(b"<not-the-reviewed-schema/>")

    with pytest.raises(ValueError, match="reviewed official file"):
        _reviewed_schema_bundle(tmp_path)
