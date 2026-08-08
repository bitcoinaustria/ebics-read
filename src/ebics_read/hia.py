"""Exact H005 HIA request data and initialization-letter rendering."""

from __future__ import annotations

import base64
import zlib
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from lxml import etree

from .errors import ConfigurationError
from .h005 import H005_NAMESPACE
from .models import (
    Bank,
    EbicsPublicKeyDigest,
    InitializationLetter,
    NegotiatedProtocol,
    Subscriber,
)
from .orders import OrderType

_DS_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#"
_MAX_ORDER_DATA_BYTES = 1024 * 1024


def _build_hia_request_xml(
    bank: Bank,
    subscriber: Subscriber,
    protocol: NegotiatedProtocol,
    authentication_certificate_der: bytes,
    encryption_certificate_der: bytes,
) -> bytes:
    if type(protocol) is not NegotiatedProtocol:
        raise TypeError("HIA protocol must be an exact NegotiatedProtocol")
    order_data = etree.Element(
        etree.QName(H005_NAMESPACE, "HIARequestOrderData"),
        nsmap={None: H005_NAMESPACE, "ds": _DS_NAMESPACE},  # type: ignore[dict-item]
    )
    _add_key_info(
        order_data,
        "AuthenticationPubKeyInfo",
        "AuthenticationVersion",
        "X002",
        authentication_certificate_der,
    )
    _add_key_info(
        order_data,
        "EncryptionPubKeyInfo",
        "EncryptionVersion",
        "E002",
        encryption_certificate_der,
    )
    etree.SubElement(
        order_data, etree.QName(H005_NAMESPACE, "PartnerID")
    ).text = subscriber.partner_id
    etree.SubElement(
        order_data, etree.QName(H005_NAMESPACE, "UserID")
    ).text = subscriber.user_id
    encoded_order_data = base64.b64encode(
        zlib.compress(
            etree.tostring(order_data, encoding="UTF-8", xml_declaration=True)
        )
    )
    if len(encoded_order_data) > _MAX_ORDER_DATA_BYTES:
        raise ConfigurationError("HIA order data exceeds the EBICS one-message limit")

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
    ).text = "HIA"
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


def _add_key_info(
    parent: etree._Element,
    info_name: str,
    version_name: str,
    version: str,
    certificate_der: bytes,
) -> None:
    info = etree.SubElement(parent, etree.QName(H005_NAMESPACE, info_name))
    x509_data = etree.SubElement(info, etree.QName(_DS_NAMESPACE, "X509Data"))
    certificate = etree.SubElement(
        x509_data, etree.QName(_DS_NAMESPACE, "X509Certificate")
    )
    certificate.text = base64.b64encode(certificate_der).decode("ascii")
    etree.SubElement(info, etree.QName(H005_NAMESPACE, version_name)).text = version


def _render_hia_letter(
    bank: Bank,
    subscriber: Subscriber,
    authentication_certificate: x509.Certificate,
    encryption_certificate: x509.Certificate,
    processed_at: datetime,
) -> InitializationLetter:
    authentication_der = authentication_certificate.public_bytes(
        serialization.Encoding.DER
    )
    encryption_der = encryption_certificate.public_bytes(serialization.Encoding.DER)
    authentication_digest = EbicsPublicKeyDigest.from_h005_certificate_der(
        authentication_der
    )
    encryption_digest = EbicsPublicKeyDigest.from_h005_certificate_der(encryption_der)
    content = "\n".join(
        (
            "EBICS HIA INITIALISATION LETTER",
            f"Date: {processed_at.date().isoformat()}",
            f"Time: {processed_at.timetz().isoformat(timespec='seconds')}",
            f"Recipient bank: {bank.institution_name}",
            f"Host ID: {bank.host_id}",
            f"User ID: {subscriber.user_id}",
            f"Partner ID: {subscriber.partner_id}",
            "Versions: X002 / E002",
            "",
            "Identification and authentication certificate (X002):",
            authentication_certificate.public_bytes(serialization.Encoding.PEM)
            .decode("ascii")
            .rstrip("\n"),
            "",
            "SHA-256 hash of the authentication certificate:",
            *_digest_lines(authentication_digest),
            "",
            "Encryption certificate (E002):",
            encryption_certificate.public_bytes(serialization.Encoding.PEM)
            .decode("ascii")
            .rstrip("\n"),
            "",
            "SHA-256 hash of the encryption certificate:",
            *_digest_lines(encryption_digest),
            "",
            "I confirm the above public keys for authentication and encryption.",
            "Signing date: ____________________  Signature: ____________________",
            "",
        )
    ).encode("utf-8")
    return InitializationLetter(
        OrderType.HIA, content, (authentication_digest, encryption_digest)
    )


def _digest_lines(digest: EbicsPublicKeyDigest) -> list[str]:
    digest_bytes = bytes.fromhex(digest.sha256_hex)
    return [
        " ".join(f"{value:02X}" for value in digest_bytes[offset : offset + 8])
        for offset in range(0, len(digest_bytes), 8)
    ]
