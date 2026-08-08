"""Exact H005 HAA capability discovery transaction."""

from __future__ import annotations

import base64
import binascii
import hmac
import re
from dataclasses import dataclass
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
from .h005 import H005_NAMESPACE, ParsedH005Response, parse_h005_response
from .hpb import _base64_value, _decompress_zlib
from .interfaces import KeyProvider
from .models import (
    Bank,
    BtfDescriptor,
    ContainerType,
    EbicsPublicKeyDigest,
    NegotiatedProtocol,
    ProtocolLimits,
    ReceiptKind,
    ServiceCapability,
    Subscriber,
    TransactionId,
    TrustedBankKeys,
)
from .orders import OrderType
from .x002 import _append_x002_auth_signature, verify_x002_response
from .xml import XmlLimits, parse_xml_document

_DS_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#"
_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
_SERVICE_NAME = re.compile(r"[A-Z0-9]{3}")
_SCOPE = re.compile(r"[A-Z0-9]{2,3}")
_SERVICE_OPTION = re.compile(r"[A-Z0-9]{3,10}")
_MESSAGE_NAME = re.compile(r"[a-z.0-9]{1,10}")
_NUMBER = re.compile(r"[0-9]{2,3}")
_FORMAT = re.compile(r"[A-Z0-9]{1,4}")
_BASE64_FRAGMENT = re.compile(r"[A-Za-z0-9+/=]+")
_MAX_SEGMENT_CHARACTERS = 1024 * 1024


@dataclass(frozen=True, slots=True)
class _HaaOrderDataFragment:
    text: str | None
    valid_shape: bool


@dataclass(frozen=True, slots=True)
class _HaaInitialResponse:
    transaction_id: TransactionId
    total_segments: int
    transaction_key: bytes
    first_fragment: _HaaOrderDataFragment
    bank_parameter_timestamp: datetime | None


def _build_haa_initialization_request_xml(
    bank: Bank,
    subscriber: Subscriber,
    protocol: NegotiatedProtocol,
    trusted_bank_keys: TrustedBankKeys,
    nonce: bytes,
    timestamp: datetime,
    key_provider: KeyProvider,
    authentication_certificate_der: bytes,
) -> bytes:
    return _build_metadata_initialization_request_xml(
        "HAA",
        bank,
        subscriber,
        protocol,
        trusted_bank_keys,
        nonce,
        timestamp,
        key_provider,
        authentication_certificate_der,
    )


def _build_metadata_initialization_request_xml(
    admin_order: str,
    bank: Bank,
    subscriber: Subscriber,
    protocol: NegotiatedProtocol,
    trusted_bank_keys: TrustedBankKeys,
    nonce: bytes,
    timestamp: datetime,
    key_provider: KeyProvider,
    authentication_certificate_der: bytes,
) -> bytes:
    if admin_order not in {"HAA", "HPD", "HKD"}:
        raise AssertionError("metadata download order is not fixed and allowlisted")
    if type(protocol) is not NegotiatedProtocol:
        raise TypeError("metadata protocol must be an exact NegotiatedProtocol")
    if type(trusted_bank_keys) is not TrustedBankKeys:
        raise TypeError("metadata download requires exact TrustedBankKeys")
    if type(nonce) is not bytes or len(nonce) != 16:
        raise ConfigurationError("metadata nonce must be exactly 16 bytes")
    if (
        not isinstance(timestamp, datetime)
        or timestamp.tzinfo is None
        or timestamp.utcoffset() is None
    ):
        raise ConfigurationError("metadata timestamp must be timezone-aware")

    root, header, static, mutable = _request_root(bank, protocol)
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
    ).text = admin_order
    etree.SubElement(details, etree.QName(H005_NAMESPACE, "StandardOrderParams"))
    digests = etree.SubElement(static, etree.QName(H005_NAMESPACE, "BankPubKeyDigests"))
    _add_bank_digest(
        digests,
        "Authentication",
        "X002",
        trusted_bank_keys.authentication.ebics_public_key_digest.sha256_hex,
    )
    _add_bank_digest(
        digests,
        "Encryption",
        "E002",
        trusted_bank_keys.encryption.ebics_public_key_digest.sha256_hex,
    )
    etree.SubElement(
        static, etree.QName(H005_NAMESPACE, "SecurityMedium")
    ).text = "0000"
    etree.SubElement(
        mutable, etree.QName(H005_NAMESPACE, "TransactionPhase")
    ).text = "Initialisation"
    _finish_request(root, header, key_provider, authentication_certificate_der)
    return etree.tostring(root, encoding="UTF-8", xml_declaration=True)


def _build_haa_transfer_request_xml(
    bank: Bank,
    protocol: NegotiatedProtocol,
    transaction_id: TransactionId,
    segment_number: int,
    key_provider: KeyProvider,
    authentication_certificate_der: bytes,
) -> bytes:
    if type(protocol) is not NegotiatedProtocol:
        raise TypeError("HAA protocol must be an exact NegotiatedProtocol")
    if not isinstance(transaction_id, TransactionId):
        raise TypeError("HAA transaction_id must be a TransactionId")
    if type(segment_number) is not int or segment_number < 2:
        raise ConfigurationError("HAA transfer segment must be at least 2")
    root, header, static, mutable = _request_root(bank, protocol)
    etree.SubElement(
        static, etree.QName(H005_NAMESPACE, "TransactionID")
    ).text = transaction_id.value
    etree.SubElement(
        mutable, etree.QName(H005_NAMESPACE, "TransactionPhase")
    ).text = "Transfer"
    segment = etree.SubElement(mutable, etree.QName(H005_NAMESPACE, "SegmentNumber"))
    segment.set("lastSegment", "false")
    segment.text = str(segment_number)
    _finish_request(root, header, key_provider, authentication_certificate_der)
    return etree.tostring(root, encoding="UTF-8", xml_declaration=True)


def _build_haa_receipt_request_xml(
    bank: Bank,
    protocol: NegotiatedProtocol,
    transaction_id: TransactionId,
    receipt: ReceiptKind,
    key_provider: KeyProvider,
    authentication_certificate_der: bytes,
) -> bytes:
    if type(protocol) is not NegotiatedProtocol:
        raise TypeError("HAA protocol must be an exact NegotiatedProtocol")
    if not isinstance(transaction_id, TransactionId):
        raise TypeError("HAA transaction_id must be a TransactionId")
    if not isinstance(receipt, ReceiptKind):
        raise TypeError("HAA receipt must be a ReceiptKind")
    root, _header, static, mutable = _request_root(bank, protocol)
    etree.SubElement(
        static, etree.QName(H005_NAMESPACE, "TransactionID")
    ).text = transaction_id.value
    etree.SubElement(
        mutable, etree.QName(H005_NAMESPACE, "TransactionPhase")
    ).text = "Receipt"
    body = etree.SubElement(root, etree.QName(H005_NAMESPACE, "body"))
    transfer_receipt = etree.SubElement(
        body, etree.QName(H005_NAMESPACE, "TransferReceipt")
    )
    transfer_receipt.set("authenticate", "true")
    etree.SubElement(
        transfer_receipt, etree.QName(H005_NAMESPACE, "ReceiptCode")
    ).text = "0" if receipt is ReceiptKind.POSITIVE else "1"
    _append_x002_auth_signature(root, key_provider, authentication_certificate_der)
    root.insert(1, root[-1])
    return etree.tostring(root, encoding="UTF-8", xml_declaration=True)


def _request_root(
    bank: Bank, protocol: NegotiatedProtocol
) -> tuple[etree._Element, etree._Element, etree._Element, etree._Element]:
    root = etree.Element(
        etree.QName(H005_NAMESPACE, "ebicsRequest"),
        nsmap={None: H005_NAMESPACE, "ds": _DS_NAMESPACE},  # type: ignore[dict-item]
        Version=protocol.protocol_version,
        Revision="1",
    )
    header = etree.SubElement(root, etree.QName(H005_NAMESPACE, "header"))
    header.set("authenticate", "true")
    static = etree.SubElement(header, etree.QName(H005_NAMESPACE, "static"))
    etree.SubElement(static, etree.QName(H005_NAMESPACE, "HostID")).text = bank.host_id
    mutable = etree.SubElement(header, etree.QName(H005_NAMESPACE, "mutable"))
    return root, header, static, mutable


def _finish_request(
    root: etree._Element,
    header: etree._Element,
    key_provider: KeyProvider,
    authentication_certificate_der: bytes,
) -> None:
    if list(root) != [header]:
        raise AssertionError("HAA request must be signed before adding its body")
    _append_x002_auth_signature(root, key_provider, authentication_certificate_der)
    etree.SubElement(root, etree.QName(H005_NAMESPACE, "body"))


def _add_bank_digest(
    parent: etree._Element, name: str, version: str, digest_hex: str
) -> None:
    element = etree.SubElement(parent, etree.QName(H005_NAMESPACE, name))
    element.set("Version", version)
    element.set("Algorithm", _SHA256)
    element.text = base64.b64encode(bytes.fromhex(digest_hex)).decode("ascii")


def _parse_haa_initial_response(
    response_xml: bytes,
    trusted_bank_keys: TrustedBankKeys,
    subscriber_encryption_certificate_der: bytes,
    key_provider: KeyProvider,
    xml_limits: XmlLimits,
    protocol_limits: ProtocolLimits,
) -> _HaaInitialResponse:
    parsed = _authenticated(response_xml, trusted_bank_keys, xml_limits)
    if not _successful(parsed):
        static, mutable = list(parsed.header)
        if parsed.return_codes.technical == "000000":
            (transaction,) = _exact_children(
                static, (f"{{{H005_NAMESPACE}}}TransactionID",)
            )
            _transaction_id(transaction)
        elif list(static):
            raise XmlSecurityError(
                "technically rejected HAA initialization has transaction data"
            )
        phase, _, _ = _exact_children(
            mutable,
            (
                f"{{{H005_NAMESPACE}}}TransactionPhase",
                f"{{{H005_NAMESPACE}}}ReturnCode",
                f"{{{H005_NAMESPACE}}}ReportText",
            ),
        )
        _require_phase(phase, "Initialisation")
        _raise_rejection(parsed, allow_bank_timestamp=True)
    static, mutable = list(parsed.header)
    transaction, count = _exact_children(
        static,
        (
            f"{{{H005_NAMESPACE}}}TransactionID",
            f"{{{H005_NAMESPACE}}}NumSegments",
        ),
    )
    phase, segment, _, _ = _exact_children(
        mutable,
        (
            f"{{{H005_NAMESPACE}}}TransactionPhase",
            f"{{{H005_NAMESPACE}}}SegmentNumber",
            f"{{{H005_NAMESPACE}}}ReturnCode",
            f"{{{H005_NAMESPACE}}}ReportText",
        ),
        attributes_allowed=True,
    )
    transaction_id = _transaction_id(transaction)
    total_segments = _positive_integer(count, "HAA segment count")
    if total_segments > protocol_limits.max_segments:
        raise ResponseLimitError("HAA segment count exceeds the configured limit")
    _require_phase(phase, "Initialisation")
    _require_segment(segment, 1, total_segments == 1)
    transfer = _only_data_transfer(parsed, allow_bank_timestamp=True)
    encryption_info, order_data = _exact_children(
        transfer,
        (
            f"{{{H005_NAMESPACE}}}DataEncryptionInfo",
            f"{{{H005_NAMESPACE}}}OrderData",
        ),
    )
    digest, wrapped_key = _data_encryption_info(encryption_info)
    expected_digest = bytes.fromhex(
        EbicsPublicKeyDigest.from_h005_certificate_der(
            subscriber_encryption_certificate_der
        ).sha256_hex
    )
    supplied_digest = _base64_value(digest, 32, attributes_allowed=True)
    if len(supplied_digest) != 32 or not hmac.compare_digest(
        supplied_digest, expected_digest
    ):
        raise SecurityError("HAA recipient encryption key digest mismatch")
    transaction_key = unwrap_e002_transaction_key(
        _base64_value(wrapped_key, 2048), key_provider
    )
    return _HaaInitialResponse(
        transaction_id,
        total_segments,
        transaction_key,
        _read_order_data_fragment(order_data),
        parsed.bank_parameter_timestamp,
    )


def _parse_haa_transfer_response(
    response_xml: bytes,
    trusted_bank_keys: TrustedBankKeys,
    transaction_id: TransactionId,
    segment_number: int,
    total_segments: int,
    xml_limits: XmlLimits,
) -> _HaaOrderDataFragment:
    parsed = _authenticated(response_xml, trusted_bank_keys, xml_limits)
    static, mutable = list(parsed.header)
    (transaction,) = _exact_children(static, (f"{{{H005_NAMESPACE}}}TransactionID",))
    phase, segment, _, _ = _exact_children(
        mutable,
        (
            f"{{{H005_NAMESPACE}}}TransactionPhase",
            f"{{{H005_NAMESPACE}}}SegmentNumber",
            f"{{{H005_NAMESPACE}}}ReturnCode",
            f"{{{H005_NAMESPACE}}}ReportText",
        ),
        attributes_allowed=True,
    )
    if _transaction_id(transaction) != transaction_id:
        raise SecurityError("HAA response transaction ID changed")
    _require_phase(phase, "Transfer")
    _require_segment(segment, segment_number, segment_number == total_segments)
    _raise_rejection(parsed, allow_bank_timestamp=False)
    transfer = _only_data_transfer(parsed, allow_bank_timestamp=False)
    (order_data,) = _exact_children(transfer, (f"{{{H005_NAMESPACE}}}OrderData",))
    return _read_order_data_fragment(order_data)


def _parse_haa_receipt_response(
    response_xml: bytes,
    trusted_bank_keys: TrustedBankKeys,
    transaction_id: TransactionId,
    receipt: ReceiptKind,
    xml_limits: XmlLimits,
) -> None:
    parsed = _authenticated(response_xml, trusted_bank_keys, xml_limits)
    expected_technical = "011000" if receipt is ReceiptKind.POSITIVE else "011001"
    if (
        parsed.return_codes.technical != expected_technical
        or parsed.return_codes.business != "000000"
    ):
        raise EbicsReturnCodeError(
            parsed.return_codes.technical, parsed.return_codes.business
        )
    static, mutable = list(parsed.header)
    (transaction,) = _exact_children(static, (f"{{{H005_NAMESPACE}}}TransactionID",))
    phase, _, _ = _exact_children(
        mutable,
        (
            f"{{{H005_NAMESPACE}}}TransactionPhase",
            f"{{{H005_NAMESPACE}}}ReturnCode",
            f"{{{H005_NAMESPACE}}}ReportText",
        ),
    )
    if _transaction_id(transaction) != transaction_id:
        raise SecurityError("HAA receipt transaction ID changed")
    _require_phase(phase, "Receipt")
    if [child.tag for child in parsed.body] != [f"{{{H005_NAMESPACE}}}ReturnCode"]:
        raise XmlSecurityError("HAA receipt response body is invalid")


def _authenticated(
    response_xml: bytes, trusted_bank_keys: TrustedBankKeys, limits: XmlLimits
) -> ParsedH005Response:
    parsed = parse_h005_response(response_xml, limits=limits)
    authenticated = verify_x002_response(parsed, trusted_bank_keys)
    return parse_h005_response(authenticated.document, limits=limits)


def _raise_rejection(parsed: ParsedH005Response, *, allow_bank_timestamp: bool) -> None:
    if _successful(parsed):
        return
    names = [etree.QName(child).localname for child in parsed.body]
    allowed = (["ReturnCode"], ["ReturnCode", "TimestampBankParameter"])
    if names not in (allowed if allow_bank_timestamp else allowed[:1]):
        raise XmlSecurityError("rejected HAA response body is invalid")
    raise EbicsReturnCodeError(
        parsed.return_codes.technical, parsed.return_codes.business
    )


def _successful(parsed: ParsedH005Response) -> bool:
    return (
        parsed.return_codes.technical == "000000"
        and parsed.return_codes.business == "000000"
    )


def _only_data_transfer(
    parsed: ParsedH005Response, *, allow_bank_timestamp: bool
) -> etree._Element:
    names = [etree.QName(child).localname for child in parsed.body]
    allowed = (
        ["DataTransfer", "ReturnCode"],
        ["DataTransfer", "ReturnCode", "TimestampBankParameter"],
    )
    if names not in (allowed if allow_bank_timestamp else allowed[:1]):
        raise XmlSecurityError("successful HAA response body is invalid")
    return next(iter(parsed.body))


def _data_encryption_info(
    element: etree._Element,
) -> tuple[etree._Element, etree._Element]:
    if set(element.attrib) != {"authenticate"} or element.get("authenticate") != "true":
        raise XmlSecurityError("HAA encryption info marker is invalid")
    digest, wrapped_key = _exact_children(
        element,
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
        raise SecurityError("HAA recipient key digest algorithm is invalid")
    return digest, wrapped_key


def _transaction_id(element: etree._Element) -> TransactionId:
    value = _leaf(element).upper()
    try:
        return TransactionId(value)
    except ConfigurationError as exc:
        raise XmlSecurityError("HAA transaction ID is invalid") from exc


def _positive_integer(element: etree._Element, name: str) -> int:
    value = _leaf(element)
    if not value.isascii() or not value.isdecimal() or value.startswith("0"):
        raise XmlSecurityError(f"{name} is invalid")
    return int(value)


def _require_phase(element: etree._Element, expected: str) -> None:
    if element.attrib or list(element) or element.text != expected:
        raise XmlSecurityError("HAA transaction phase is invalid")


def _require_segment(
    element: etree._Element, expected_number: int, expected_last: bool
) -> None:
    value = element.text
    if (
        set(element.attrib) != {"lastSegment"}
        or element.get("lastSegment")
        not in ({"true", "1"} if expected_last else {"false", "0"})
        or list(element)
        or value is None
        or not value.isascii()
        or not value.isdecimal()
        or value.startswith("0")
        or int(value) != expected_number
    ):
        raise XmlSecurityError("HAA segment metadata is inconsistent")


def _read_order_data_fragment(element: etree._Element) -> _HaaOrderDataFragment:
    return _HaaOrderDataFragment(
        element.text,
        not element.attrib and not list(element) and element.text is not None,
    )


def _validate_order_data_fragment(
    fragment: _HaaOrderDataFragment, *, last: bool
) -> str:
    if not fragment.valid_shape or fragment.text is None:
        raise XmlSecurityError("HAA order-data segment has an invalid shape")
    value = fragment.text
    if len(value) > _MAX_SEGMENT_CHARACTERS:
        raise ResponseLimitError("HAA order-data segment exceeds its size limit")
    if _BASE64_FRAGMENT.fullmatch(value) is None:
        raise XmlSecurityError("HAA order-data segment is not compact base64 text")
    try:
        base64.b64decode(value.encode("ascii"), validate=True)
    except binascii.Error as exc:
        raise XmlSecurityError("HAA order-data segment is not valid base64") from exc
    if not last and "=" in value:
        raise XmlSecurityError("HAA non-final order-data segment contains padding")
    return value


def _decode_haa_services(
    fragments: list[str],
    transaction_key: bytes,
    xml_limits: XmlLimits,
    protocol_limits: ProtocolLimits,
) -> tuple[ServiceCapability, ...]:
    return _parse_haa_services(
        _decode_metadata_order_data(
            fragments, transaction_key, xml_limits, protocol_limits
        )
    )


def _decode_metadata_order_data(
    fragments: list[str],
    transaction_key: bytes,
    xml_limits: XmlLimits,
    protocol_limits: ProtocolLimits,
) -> etree._Element:
    encoded_limit = _encoded_order_data_limit(protocol_limits)
    encoded_size = sum(len(value) for value in fragments)
    if encoded_size > encoded_limit:
        raise ResponseLimitError("HAA encoded order data exceeds the configured limit")
    try:
        ciphertext = base64.b64decode("".join(fragments).encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise XmlSecurityError("HAA order data is not strict base64") from exc
    if not ciphertext or len(ciphertext) > protocol_limits.max_compressed_bytes + 16:
        raise ResponseLimitError(
            "HAA encrypted order data exceeds the configured limit"
        )
    compressed = b"".join(iter_decrypt_e002((ciphertext,), transaction_key))
    if len(compressed) > protocol_limits.max_compressed_bytes:
        raise ResponseLimitError(
            "HAA compressed order data exceeds the configured limit"
        )
    output_limit = min(
        protocol_limits.max_decompressed_bytes, xml_limits.max_input_bytes
    )
    cleartext = _decompress_zlib(compressed, output_limit)
    if len(cleartext) > max(1, len(compressed)) * protocol_limits.max_compression_ratio:
        raise ResponseLimitError("HAA order data exceeds the compression-ratio limit")
    return parse_xml_document(cleartext, xml_limits)


def _encoded_order_data_limit(protocol_limits: ProtocolLimits) -> int:
    return ((protocol_limits.max_compressed_bytes + 18) // 3) * 4


def _parse_haa_services(root: etree._Element) -> tuple[ServiceCapability, ...]:
    if root.tag != f"{{{H005_NAMESPACE}}}HAAResponseOrderData" or root.attrib:
        raise XmlSecurityError("HAA order-data root is invalid")
    if root.text is not None and root.text.strip():
        raise XmlSecurityError("HAA order-data root contains unexpected text")
    services: list[ServiceCapability] = []
    for child in root:
        if child.tag != f"{{{H005_NAMESPACE}}}Service" or (
            child.tail is not None and child.tail.strip()
        ):
            raise XmlSecurityError("HAA order data contains an unsupported extension")
        services.append(_parse_service(child))
    if len(services) != len(set(services)):
        raise XmlSecurityError("HAA response contains duplicate services")
    return tuple(services)


def _parse_service(element: etree._Element) -> ServiceCapability:
    return ServiceCapability(_parse_btf_descriptor(element), OrderType.HAA)


def _parse_btf_descriptor(element: etree._Element) -> BtfDescriptor:
    if element.attrib or (element.text is not None and element.text.strip()):
        raise XmlSecurityError("HAA service contains unexpected content")
    children = list(element)
    if not children or children[0].tag != f"{{{H005_NAMESPACE}}}ServiceName":
        raise XmlSecurityError("HAA service requires ServiceName first")
    index = 1
    service_name = _pattern_leaf(children[0], _SERVICE_NAME, "ServiceName")
    scope = _optional_leaf(children, index, "Scope", _SCOPE)
    index += scope[1]
    service_option = _optional_leaf(children, index, "ServiceOption", _SERVICE_OPTION)
    index += service_option[1]
    container_type = ContainerType.NONE
    if (
        index < len(children)
        and children[index].tag == f"{{{H005_NAMESPACE}}}Container"
    ):
        container = children[index]
        if (
            set(container.attrib) != {"containerType"}
            or list(container)
            or (container.text is not None and container.text.strip())
        ):
            raise XmlSecurityError("HAA container is invalid")
        try:
            container_type = ContainerType(container.get("containerType"))
        except ValueError as exc:
            raise XmlSecurityError("HAA container type is unsupported") from exc
        if container_type is ContainerType.NONE:
            raise XmlSecurityError("HAA NONE container must be omitted")
        index += 1
    if index >= len(children) or children[index].tag != f"{{{H005_NAMESPACE}}}MsgName":
        raise XmlSecurityError("HAA service requires MsgName last")
    message = children[index]
    index += 1
    if index != len(children) or any(
        child.tail is not None and child.tail.strip() for child in children
    ):
        raise XmlSecurityError("HAA service shape or order is invalid")
    if set(message.attrib) - {"version", "variant", "format"}:
        raise XmlSecurityError("HAA message name has unknown attributes")
    message_name = _pattern_leaf(
        message, _MESSAGE_NAME, "MsgName", allow_attributes=True
    )
    version = _optional_attribute(message, "version", _NUMBER)
    variant = _optional_attribute(message, "variant", _NUMBER)
    format_value = _optional_attribute(message, "format", _FORMAT)
    return BtfDescriptor(
        service_name=service_name,
        message_name=message_name,
        message_version=version,
        variant=variant,
        format=format_value,
        service_option=service_option[0],
        container_type=container_type,
        scope=scope[0],
    )


def _optional_leaf(
    children: list[etree._Element],
    index: int,
    local_name: str,
    pattern: re.Pattern[str],
) -> tuple[str | None, int]:
    if (
        index >= len(children)
        or children[index].tag != f"{{{H005_NAMESPACE}}}{local_name}"
    ):
        return None, 0
    return _pattern_leaf(children[index], pattern, local_name), 1


def _pattern_leaf(
    element: etree._Element,
    pattern: re.Pattern[str],
    name: str,
    *,
    allow_attributes: bool = False,
) -> str:
    value = _leaf(element, allow_attributes=allow_attributes)
    if pattern.fullmatch(value) is None:
        raise XmlSecurityError(f"HAA {name} is invalid")
    return value


def _optional_attribute(
    element: etree._Element, name: str, pattern: re.Pattern[str]
) -> str | None:
    value = element.get(name)
    if value is not None and pattern.fullmatch(value) is None:
        raise XmlSecurityError(f"HAA MsgName {name} is invalid")
    return value


def _leaf(element: etree._Element, *, allow_attributes: bool = False) -> str:
    if (
        (element.attrib and not allow_attributes)
        or list(element)
        or element.text is None
    ):
        raise XmlSecurityError("HAA leaf value has an invalid shape")
    return element.text


def _exact_children(
    parent: etree._Element,
    tags: tuple[str, ...],
    *,
    attributes_allowed: bool = False,
) -> tuple[etree._Element, ...]:
    if (parent.attrib and not attributes_allowed) or (
        parent.text is not None and parent.text.strip()
    ):
        raise XmlSecurityError("HAA structure contains unexpected content")
    children = tuple(parent)
    if len(children) != len(tags) or any(
        child.tag != tag or (child.tail is not None and child.tail.strip())
        for child, tag in zip(children, tags, strict=True)
    ):
        raise XmlSecurityError("HAA structure or element order is invalid")
    return children
