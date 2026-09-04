"""Exact H005 INI request data, key-initialization response, and letter."""

from __future__ import annotations

import base64
import zlib
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from lxml import etree

from .errors import (
    AmbiguousTransportError,
    ConfigurationError,
    EbicsReturnCodeError,
    ProtocolError,
)
from .h005 import H005_NAMESPACE, parse_h005_response
from .models import (
    Bank,
    EbicsPublicKeyDigest,
    InitializationLetter,
    NegotiatedProtocol,
    Subscriber,
)
from .orders import OrderType
from .xml import XmlLimits

_S002_NAMESPACE = "http://www.ebics.org/S002"
_DS_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#"
_MAX_ORDER_DATA_BYTES = 1024 * 1024


def _build_ini_request_xml(
    bank: Bank,
    subscriber: Subscriber,
    protocol: NegotiatedProtocol,
    certificate_der: bytes,
) -> bytes:
    if type(protocol) is not NegotiatedProtocol:
        raise TypeError("INI protocol must be an exact NegotiatedProtocol")
    order_data = etree.Element(
        etree.QName(_S002_NAMESPACE, "SignaturePubKeyOrderData"),
        nsmap={None: _S002_NAMESPACE, "ds": _DS_NAMESPACE},  # type: ignore[dict-item]
    )
    key_info = etree.SubElement(
        order_data, etree.QName(_S002_NAMESPACE, "SignaturePubKeyInfo")
    )
    x509_data = etree.SubElement(key_info, etree.QName(_DS_NAMESPACE, "X509Data"))
    certificate = etree.SubElement(
        x509_data, etree.QName(_DS_NAMESPACE, "X509Certificate")
    )
    certificate.text = base64.b64encode(certificate_der).decode("ascii")
    etree.SubElement(
        key_info, etree.QName(_S002_NAMESPACE, "SignatureVersion")
    ).text = "A006"
    etree.SubElement(
        order_data, etree.QName(_S002_NAMESPACE, "PartnerID")
    ).text = subscriber.partner_id
    etree.SubElement(
        order_data, etree.QName(_S002_NAMESPACE, "UserID")
    ).text = subscriber.user_id
    encoded_order_data = base64.b64encode(
        zlib.compress(
            etree.tostring(order_data, encoding="UTF-8", xml_declaration=True)
        )
    )
    if len(encoded_order_data) > _MAX_ORDER_DATA_BYTES:
        raise ConfigurationError("INI order data exceeds the EBICS one-message limit")

    root = etree.Element(
        etree.QName(H005_NAMESPACE, "ebicsUnsecuredRequest"),
        nsmap={None: H005_NAMESPACE},  # type: ignore[dict-item]
        Version=protocol.protocol_version,
        Revision="1",
    )
    header = etree.SubElement(root, etree.QName(H005_NAMESPACE, "header"))
    header.set("authenticate", "true")
    static = etree.SubElement(header, etree.QName(H005_NAMESPACE, "static"))
    etree.SubElement(static, etree.QName(H005_NAMESPACE, "HostID")).text = bank.host_id
    etree.SubElement(
        static, etree.QName(H005_NAMESPACE, "PartnerID")
    ).text = subscriber.partner_id
    etree.SubElement(
        static, etree.QName(H005_NAMESPACE, "UserID")
    ).text = subscriber.user_id
    if subscriber.system_id is not None:
        etree.SubElement(
            static, etree.QName(H005_NAMESPACE, "SystemID")
        ).text = subscriber.system_id
    details = etree.SubElement(static, etree.QName(H005_NAMESPACE, "OrderDetails"))
    etree.SubElement(
        details, etree.QName(H005_NAMESPACE, "AdminOrderType")
    ).text = "INI"
    etree.SubElement(
        static, etree.QName(H005_NAMESPACE, "SecurityMedium")
    ).text = "0000"
    etree.SubElement(header, etree.QName(H005_NAMESPACE, "mutable"))
    body = etree.SubElement(root, etree.QName(H005_NAMESPACE, "body"))
    transfer = etree.SubElement(body, etree.QName(H005_NAMESPACE, "DataTransfer"))
    etree.SubElement(
        transfer, etree.QName(H005_NAMESPACE, "OrderData")
    ).text = encoded_order_data.decode("ascii")
    return etree.tostring(root, encoding="UTF-8", xml_declaration=True)


def _parse_key_initialization_response(response_xml: bytes, limits: XmlLimits) -> None:
    try:
        parsed = parse_h005_response(response_xml, key_management=True, limits=limits)
    except ProtocolError as exc:
        raise AmbiguousTransportError(
            "key initialization outcome is ambiguous"
        ) from exc
    if any(child.tag == f"{{{H005_NAMESPACE}}}DataTransfer" for child in parsed.body):
        raise AmbiguousTransportError("key initialization outcome is ambiguous")
    if (
        parsed.return_codes.technical != "000000"
        and parsed.return_codes.business != "000000"
    ):
        raise AmbiguousTransportError("key initialization outcome is ambiguous")
    if (
        parsed.return_codes.technical != "000000"
        or parsed.return_codes.business != "000000"
    ):
        raise EbicsReturnCodeError(
            parsed.return_codes.technical, parsed.return_codes.business
        )
    mutable = list(parsed.header)[1]
    if not any(child.tag == f"{{{H005_NAMESPACE}}}OrderID" for child in mutable):
        raise AmbiguousTransportError("key initialization outcome is ambiguous")


def _render_ini_letter(
    bank: Bank,
    subscriber: Subscriber,
    certificate: x509.Certificate,
    processed_at: datetime,
) -> InitializationLetter:
    certificate_der = certificate.public_bytes(serialization.Encoding.DER)
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode(
        "ascii"
    )
    digest = EbicsPublicKeyDigest.from_h005_certificate_der(certificate_der)
    digest_bytes = bytes.fromhex(digest.sha256_hex)
    digest_lines = [
        " ".join(f"{value:02X}" for value in digest_bytes[offset : offset + 8])
        for offset in range(0, len(digest_bytes), 8)
    ]
    content = "\n".join(
        (
            "EBICS INI INITIALISATION LETTER",
            f"Date: {processed_at.date().isoformat()}",
            f"Time: {processed_at.timetz().isoformat(timespec='seconds')}",
            f"Recipient bank: {bank.institution_name}",
            f"Host ID: {bank.host_id}",
            f"User ID: {subscriber.user_id}",
            f"Partner ID: {subscriber.partner_id}",
            "Purpose: Bank-technical electronic signature",
            "Version: A006",
            "",
            "Signature certificate:",
            certificate_pem.rstrip("\n"),
            "",
            "SHA-256 hash of the signature certificate:",
            *digest_lines,
            "",
            "I confirm the above public key for my electronic signature.",
            "Signing date: ____________________  Signature: ____________________",
            "",
        )
    ).encode("utf-8")
    return InitializationLetter(OrderType.INI, content, (digest,))
