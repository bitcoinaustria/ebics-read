"""Exact H005 HPB bank-key retrieval."""

from __future__ import annotations

import base64
import binascii
import hmac
import zlib
from datetime import datetime, timezone

from lxml import etree

from .e002 import iter_decrypt_e002, unwrap_e002_transaction_key
from .errors import (
    ConfigurationError,
    EbicsReturnCodeError,
    ResponseLimitError,
    SecurityError,
    XmlSecurityError,
)
from .h005 import H005_NAMESPACE, parse_h005_response
from .interfaces import BankCertificateProfile, KeyProvider
from .models import (
    Bank,
    EbicsPublicKeyDigest,
    NegotiatedProtocol,
    Subscriber,
    UntrustedBankKeys,
)
from .x002 import _append_x002_auth_signature
from .xml import XmlLimits, parse_xml_document

_DS_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#"
_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
_MAX_CERTIFICATE_BYTES = 1024 * 1024


def _build_hpb_request_xml(
    bank: Bank,
    subscriber: Subscriber,
    protocol: NegotiatedProtocol,
    nonce: bytes,
    timestamp: datetime,
    key_provider: KeyProvider,
    authentication_certificate_der: bytes,
) -> bytes:
    if type(protocol) is not NegotiatedProtocol:
        raise TypeError("HPB protocol must be an exact NegotiatedProtocol")
    if type(nonce) is not bytes or len(nonce) != 16:
        raise ConfigurationError("HPB nonce must be exactly 16 bytes")
    if (
        not isinstance(timestamp, datetime)
        or timestamp.tzinfo is None
        or timestamp.utcoffset() is None
    ):
        raise ConfigurationError("HPB timestamp must be timezone-aware")

    root = etree.Element(
        etree.QName(H005_NAMESPACE, "ebicsNoPubKeyDigestsRequest"),
        nsmap={None: H005_NAMESPACE, "ds": _DS_NAMESPACE},  # type: ignore[dict-item]
        Version=protocol.protocol_version,
        Revision="1",
    )
    header = etree.SubElement(root, etree.QName(H005_NAMESPACE, "header"))
    header.set("authenticate", "true")
    static = etree.SubElement(header, etree.QName(H005_NAMESPACE, "static"))
    etree.SubElement(static, etree.QName(H005_NAMESPACE, "HostID")).text = bank.host_id
    etree.SubElement(
        static, etree.QName(H005_NAMESPACE, "Nonce")
    ).text = nonce.hex().upper()
    etree.SubElement(static, etree.QName(H005_NAMESPACE, "Timestamp")).text = (
        timestamp.astimezone(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )
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
    ).text = "HPB"
    etree.SubElement(
        static, etree.QName(H005_NAMESPACE, "SecurityMedium")
    ).text = "0000"
    etree.SubElement(header, etree.QName(H005_NAMESPACE, "mutable"))
    _append_x002_auth_signature(root, key_provider, authentication_certificate_der)
    etree.SubElement(root, etree.QName(H005_NAMESPACE, "body"))
    return etree.tostring(root, encoding="UTF-8", xml_declaration=True)


def _parse_hpb_response(
    response_xml: bytes,
    bank: Bank,
    subscriber_encryption_certificate_der: bytes,
    key_provider: KeyProvider,
    profile: BankCertificateProfile,
    now: datetime,
    limits: XmlLimits,
) -> UntrustedBankKeys:
    parsed = parse_h005_response(response_xml, key_management=True, limits=limits)
    mutable = list(parsed.header)[1]
    if [etree.QName(child).localname for child in mutable] != [
        "ReturnCode",
        "ReportText",
    ]:
        raise XmlSecurityError("HPB response header has an invalid shape")

    transfer = [
        child
        for child in parsed.body
        if child.tag == f"{{{H005_NAMESPACE}}}DataTransfer"
    ]
    success = (
        parsed.return_codes.technical == "000000"
        and parsed.return_codes.business == "000000"
    )
    if not success:
        if transfer:
            raise XmlSecurityError("rejected HPB response contains order data")
        raise EbicsReturnCodeError(
            parsed.return_codes.technical, parsed.return_codes.business
        )
    if len(transfer) != 1:
        raise XmlSecurityError("successful HPB response requires order data")

    encryption_info, order_data = _exact_children(
        transfer[0],
        (
            f"{{{H005_NAMESPACE}}}DataEncryptionInfo",
            f"{{{H005_NAMESPACE}}}OrderData",
        ),
    )
    if (
        set(encryption_info.attrib) != {"authenticate"}
        or encryption_info.get("authenticate") != "true"
    ):
        raise XmlSecurityError("HPB encryption info authentication marker is invalid")
    digest, wrapped_key = _exact_children(
        encryption_info,
        (
            f"{{{H005_NAMESPACE}}}EncryptionPubKeyDigest",
            f"{{{H005_NAMESPACE}}}TransactionKey",
        ),
        attributes_allowed=True,
    )
    if (
        set(digest.attrib) != {"Version", "Algorithm"}
        or digest.get("Version") != "E002"
        or digest.get("Algorithm") != _SHA256
    ):
        raise SecurityError("HPB recipient key digest algorithm is invalid")
    expected_digest = bytes.fromhex(
        EbicsPublicKeyDigest.from_h005_certificate_der(
            subscriber_encryption_certificate_der
        ).sha256_hex
    )
    supplied_digest = _base64_value(digest, 32, attributes_allowed=True)
    if len(supplied_digest) != 32 or not hmac.compare_digest(
        supplied_digest, expected_digest
    ):
        raise SecurityError("HPB recipient encryption key digest mismatch")
    transaction_key = unwrap_e002_transaction_key(
        _base64_value(wrapped_key, 2048), key_provider
    )
    ciphertext = _base64_value(order_data, limits.max_input_bytes)
    plaintext = b"".join(iter_decrypt_e002((ciphertext,), transaction_key))
    order_xml = _decompress_zlib(plaintext, limits.max_input_bytes)
    authentication_der, encryption_der = _parse_hpb_order_data(
        parse_xml_document(order_xml, limits), bank
    )
    return profile.validate_pair(authentication_der, encryption_der, now)


def _parse_hpb_order_data(root: etree._Element, bank: Bank) -> tuple[bytes, bytes]:
    if root.tag != f"{{{H005_NAMESPACE}}}HPBResponseOrderData" or root.attrib:
        raise XmlSecurityError("HPB order-data root is invalid")
    authentication, encryption, host_id = _exact_children(
        root,
        (
            f"{{{H005_NAMESPACE}}}AuthenticationPubKeyInfo",
            f"{{{H005_NAMESPACE}}}EncryptionPubKeyInfo",
            f"{{{H005_NAMESPACE}}}HostID",
        ),
    )
    authentication_der = _key_info(authentication, "AuthenticationVersion", "X002")
    encryption_der = _key_info(encryption, "EncryptionVersion", "E002")
    if host_id.attrib or list(host_id) or host_id.text != bank.host_id:
        raise SecurityError("HPB order data belongs to another host")
    return authentication_der, encryption_der


def _key_info(element: etree._Element, version_name: str, version: str) -> bytes:
    x509_data, supplied_version = _exact_children(
        element,
        (
            f"{{{_DS_NAMESPACE}}}X509Data",
            f"{{{H005_NAMESPACE}}}{version_name}",
        ),
    )
    (certificate,) = _exact_children(
        x509_data, (f"{{{_DS_NAMESPACE}}}X509Certificate",)
    )
    if (
        supplied_version.attrib
        or list(supplied_version)
        or supplied_version.text != version
    ):
        raise SecurityError(f"HPB {version_name} is unsupported")
    return _base64_value(certificate, _MAX_CERTIFICATE_BYTES)


def _exact_children(
    parent: etree._Element,
    tags: tuple[str, ...],
    *,
    attributes_allowed: bool = False,
) -> tuple[etree._Element, ...]:
    if (parent.attrib and not attributes_allowed) or (
        parent.text is not None and parent.text.strip()
    ):
        raise XmlSecurityError("HPB structure contains unexpected content")
    children = tuple(parent)
    if len(children) != len(tags) or any(
        child.tag != tag or (child.tail is not None and child.tail.strip())
        for child, tag in zip(children, tags, strict=True)
    ):
        raise XmlSecurityError("HPB structure or element order is invalid")
    return children


def _base64_value(
    element: etree._Element,
    maximum_bytes: int,
    *,
    attributes_allowed: bool = False,
) -> bytes:
    if (
        (element.attrib and not attributes_allowed)
        or list(element)
        or element.text is None
    ):
        raise XmlSecurityError("HPB binary value has an invalid shape")
    try:
        compact = (
            element.text.replace(" ", "")
            .replace("\t", "")
            .replace("\r", "")
            .replace("\n", "")
            .encode("ascii")
        )
        decoded = base64.b64decode(compact, validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise XmlSecurityError("HPB binary value is not strict base64") from exc
    if not decoded or len(decoded) > maximum_bytes:
        raise ResponseLimitError("HPB binary value exceeds its size limit")
    return decoded


def _decompress_zlib(data: bytes, maximum_bytes: int) -> bytes:
    inflater = zlib.decompressobj()
    try:
        result = inflater.decompress(data, maximum_bytes + 1)
        if len(result) > maximum_bytes or inflater.unconsumed_tail:
            raise ResponseLimitError("EBICS order data exceeds its byte limit")
        result += inflater.flush(maximum_bytes + 1 - len(result))
    except zlib.error as exc:
        raise SecurityError("EBICS order data is not one valid zlib stream") from exc
    if len(result) > maximum_bytes:
        raise ResponseLimitError("EBICS order data exceeds its byte limit")
    if not inflater.eof or inflater.unused_data:
        raise SecurityError("EBICS order data is not one complete zlib stream")
    return result
