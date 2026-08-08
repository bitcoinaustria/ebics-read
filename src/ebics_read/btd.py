"""Exact fixed H005 BTD download envelopes and response parsing."""

from __future__ import annotations

import base64
import binascii
import json
from datetime import datetime, timezone
from hashlib import sha256
from io import BytesIO
from stat import S_ISLNK
from zipfile import BadZipFile, LargeZipFile, ZipFile, is_zipfile

from lxml import etree

from .e002 import iter_decrypt_e002
from .errors import (
    ConfigurationError,
    OperationNotImplementedError,
    ResponseLimitError,
    SecurityError,
    XmlSecurityError,
)
from .h005 import H005_NAMESPACE
from .haa import (
    _add_bank_digest,
    _build_haa_receipt_request_xml,
    _build_haa_transfer_request_xml,
    _encoded_order_data_limit,
    _finish_request,
    _HaaInitialResponse,
    _HaaOrderDataFragment,
    _parse_haa_initial_response,
    _parse_haa_receipt_response,
    _parse_haa_transfer_response,
    _request_root,
)
from .hpb import _decompress_zlib
from .interfaces import KeyProvider
from .models import (
    Bank,
    BtfDescriptor,
    ContainerType,
    ContentSha256,
    DownloadOptions,
    DownloadRequestIdentity,
    NegotiatedProtocol,
    ProtocolLimits,
    ReceiptKind,
    Subscriber,
    TransactionId,
    TrustedBankKeys,
    ZipMemberIdentity,
)
from .xml import XmlLimits

_ZIP_CHUNK_BYTES = 64 * 1024


def _decode_btd_payload(
    fragments: tuple[str, ...],
    transaction_key: bytes,
    protocol_limits: ProtocolLimits,
) -> bytes:
    """Strictly decode, decrypt, and expand one bounded BTD payload."""

    if not fragments or any(type(fragment) is not str for fragment in fragments):
        raise XmlSecurityError("BTD order data fragments are invalid")
    encoded_size = sum(len(fragment) for fragment in fragments)
    if encoded_size > _encoded_order_data_limit(protocol_limits):
        raise ResponseLimitError("BTD encoded order data exceeds the configured limit")
    encoded = "".join(fragments)
    try:
        ciphertext = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise XmlSecurityError("BTD order data is not strict base64") from exc
    if not ciphertext or len(ciphertext) > protocol_limits.max_compressed_bytes + 16:
        raise ResponseLimitError(
            "BTD encrypted order data exceeds the configured limit"
        )
    compressed = b"".join(iter_decrypt_e002((ciphertext,), transaction_key))
    if not compressed or len(compressed) > protocol_limits.max_compressed_bytes:
        raise ResponseLimitError(
            "BTD compressed order data exceeds the configured limit"
        )
    payload = _decompress_zlib(compressed, protocol_limits.max_decompressed_bytes)
    if not payload:
        raise SecurityError("BTD payload is empty")
    if len(payload) > len(compressed) * protocol_limits.max_compression_ratio:
        raise ResponseLimitError("BTD payload exceeds the compression-ratio limit")
    return payload


def _extract_btd_documents(
    payload: bytes,
    container_type: ContainerType,
    protocol_limits: ProtocolLimits,
) -> tuple[tuple[bytes, tuple[ZipMemberIdentity, ...]], ...]:
    """Return bounded documents without ever exposing ZIP member names."""

    if type(payload) is not bytes or not payload:
        raise SecurityError("BTD payload is empty")
    if len(payload) > protocol_limits.max_decompressed_bytes:
        raise ResponseLimitError("BTD payload exceeds the configured limit")
    if container_type is ContainerType.NONE:
        return ((payload, ()),)
    if container_type is not ContainerType.ZIP:
        raise OperationNotImplementedError(
            "BTD XML and SVC container framing lacks a recorded public specification"
        )

    documents: list[tuple[bytes, tuple[ZipMemberIdentity, ...]]] = []
    names: set[str] = set()
    total_size = 0
    try:
        with ZipFile(BytesIO(payload), "r") as archive:
            members = archive.infolist()
            if not members or len(members) > protocol_limits.max_zip_members:
                raise ResponseLimitError("BTD ZIP member count exceeds its limit")
            for index, member in enumerate(members):
                name = member.filename
                path = name[:-1] if member.is_dir() else name
                parts = path.split("/")
                if (
                    not path
                    or name in names
                    or "\\" in name
                    or any(part in {"", ".", ".."} for part in parts)
                    or ":" in parts[0]
                    or any(ord(character) < 0x20 for character in name)
                ):
                    raise SecurityError("BTD ZIP member path is unsafe or duplicate")
                names.add(name)
                if member.flag_bits & 1:
                    raise SecurityError("BTD ZIP encrypted members are unsupported")
                mode = member.external_attr >> 16
                if member.create_system == 3 and S_ISLNK(mode):
                    raise SecurityError("BTD ZIP symbolic links are unsupported")
                if member.is_dir():
                    if member.file_size != 0 or member.compress_size != 0:
                        raise SecurityError("BTD ZIP directory entry contains data")
                    with archive.open(member, "r") as directory:
                        if directory.read(1):
                            raise SecurityError("BTD ZIP directory entry contains data")
                    continue
                if (
                    member.file_size <= 0
                    or member.file_size > protocol_limits.max_zip_member_bytes
                    or member.file_size
                    > max(1, member.compress_size)
                    * protocol_limits.max_compression_ratio
                ):
                    raise ResponseLimitError("BTD ZIP member exceeds its size limit")
                total_size += member.file_size
                if total_size > protocol_limits.max_decompressed_bytes:
                    raise ResponseLimitError(
                        "BTD ZIP contents exceed their total limit"
                    )
                content = bytearray()
                with archive.open(member, "r") as source:
                    while chunk := source.read(_ZIP_CHUNK_BYTES):
                        content.extend(chunk)
                        if (
                            len(content) > member.file_size
                            or len(content) > protocol_limits.max_zip_member_bytes
                        ):
                            raise ResponseLimitError(
                                "BTD ZIP member exceeds its size limit"
                            )
                if len(content) != member.file_size:
                    raise SecurityError("BTD ZIP member size is inconsistent")
                document = bytes(content)
                if is_zipfile(BytesIO(document)):
                    raise SecurityError("BTD nested ZIP archives are unsupported")
                identity = ZipMemberIdentity(
                    index,
                    ContentSha256.from_bytes(name.encode("utf-8")),
                    ContentSha256.from_bytes(document),
                    len(document),
                )
                documents.append((document, (identity,)))
    except (
        BadZipFile,
        LargeZipFile,
        NotImplementedError,
        RuntimeError,
        OSError,
    ) as exc:
        raise SecurityError("BTD payload is not a supported ZIP archive") from exc
    if not documents:
        raise SecurityError("BTD ZIP contains no documents")
    return tuple(documents)


def _download_request_identity(
    bank: Bank,
    subscriber: Subscriber,
    protocol: NegotiatedProtocol,
    trusted_bank_keys: TrustedBankKeys,
    descriptor: BtfDescriptor,
    options: DownloadOptions,
    protocol_limits: ProtocolLimits,
    xml_limits: XmlLimits,
    authentication_certificate_der: bytes,
    encryption_certificate_der: bytes,
) -> DownloadRequestIdentity:
    """Bind resumable state to every security-meaningful BTD input."""

    date_range = options.date_range
    values = (
        bank.endpoint,
        bank.host_id,
        subscriber.partner_id,
        subscriber.user_id,
        subscriber.system_id,
        protocol.protocol_version,
        protocol.version_number,
        protocol.request_namespace,
        protocol.hev_namespace,
        trusted_bank_keys.authentication.ebics_public_key_digest.sha256_hex,
        trusted_bank_keys.encryption.ebics_public_key_digest.sha256_hex,
        sha256(authentication_certificate_der).hexdigest().upper(),
        sha256(encryption_certificate_der).hexdigest().upper(),
        descriptor.service_name,
        descriptor.scope,
        descriptor.service_option,
        descriptor.container_type.value,
        descriptor.message_name,
        descriptor.message_version,
        descriptor.variant,
        descriptor.format,
        None if date_range is None else date_range.start.isoformat(),
        None if date_range is None else date_range.end.isoformat(),
        None
        if options.account is None
        else (
            options.account.iban,
            options.account.account_id,
            options.account.currency,
        ),
        protocol_limits.max_segments,
        protocol_limits.max_compressed_bytes,
        protocol_limits.max_decompressed_bytes,
        protocol_limits.max_zip_members,
        protocol_limits.max_zip_member_bytes,
        protocol_limits.max_compression_ratio,
        xml_limits.max_input_bytes,
        xml_limits.max_depth,
        xml_limits.max_elements,
        xml_limits.max_text_bytes,
        xml_limits.max_total_text_bytes,
        xml_limits.max_attributes_per_element,
        xml_limits.max_total_attribute_bytes,
        xml_limits.max_namespaces,
        xml_limits.max_namespace_bytes,
        xml_limits.max_total_namespace_bytes,
    )
    encoded = json.dumps(values, ensure_ascii=True, separators=(",", ":")).encode(
        "ascii"
    )
    return DownloadRequestIdentity(
        sha256(b"ebics-read:btd-request:v1\0" + encoded).hexdigest().upper()
    )


def _build_btd_initialization_request_xml(
    bank: Bank,
    subscriber: Subscriber,
    protocol: NegotiatedProtocol,
    trusted_bank_keys: TrustedBankKeys,
    descriptor: BtfDescriptor,
    options: DownloadOptions,
    nonce: bytes,
    timestamp: datetime,
    key_provider: KeyProvider,
    authentication_certificate_der: bytes,
) -> bytes:
    if type(protocol) is not NegotiatedProtocol:
        raise TypeError("BTD protocol must be an exact NegotiatedProtocol")
    if type(trusted_bank_keys) is not TrustedBankKeys:
        raise TypeError("BTD requires exact TrustedBankKeys")
    if not isinstance(descriptor, BtfDescriptor):
        raise TypeError("BTD descriptor must be a BtfDescriptor")
    if not isinstance(options, DownloadOptions):
        raise TypeError("BTD options must be DownloadOptions")
    if options.account is not None:
        raise ConfigurationError(
            "H005 defines no portable BTD account-selector parameter"
        )
    if type(nonce) is not bytes or len(nonce) != 16:
        raise ConfigurationError("BTD nonce must be exactly 16 bytes")
    if (
        not isinstance(timestamp, datetime)
        or timestamp.tzinfo is None
        or timestamp.utcoffset() is None
    ):
        raise ConfigurationError("BTD timestamp must be timezone-aware")

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
    ).text = "BTD"
    parameters = etree.SubElement(
        details, etree.QName(H005_NAMESPACE, "BTDOrderParams")
    )
    _append_service(parameters, descriptor)
    if options.date_range is not None:
        date_range = etree.SubElement(
            parameters, etree.QName(H005_NAMESPACE, "DateRange")
        )
        etree.SubElement(
            date_range, etree.QName(H005_NAMESPACE, "Start")
        ).text = options.date_range.start.isoformat()
        etree.SubElement(
            date_range, etree.QName(H005_NAMESPACE, "End")
        ).text = options.date_range.end.isoformat()
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


def _append_service(parent: etree._Element, descriptor: BtfDescriptor) -> None:
    service = etree.SubElement(parent, etree.QName(H005_NAMESPACE, "Service"))
    etree.SubElement(
        service, etree.QName(H005_NAMESPACE, "ServiceName")
    ).text = descriptor.service_name
    if descriptor.scope is not None:
        etree.SubElement(
            service, etree.QName(H005_NAMESPACE, "Scope")
        ).text = descriptor.scope
    if descriptor.service_option is not None:
        etree.SubElement(
            service, etree.QName(H005_NAMESPACE, "ServiceOption")
        ).text = descriptor.service_option
    if descriptor.container_type is not ContainerType.NONE:
        etree.SubElement(
            service,
            etree.QName(H005_NAMESPACE, "Container"),
            containerType=descriptor.container_type.value,
        )
    message = etree.SubElement(service, etree.QName(H005_NAMESPACE, "MsgName"))
    for name, value in (
        ("version", descriptor.message_version),
        ("variant", descriptor.variant),
        ("format", descriptor.format),
    ):
        if value is not None:
            message.set(name, value)
    message.text = descriptor.message_name


def _build_btd_transfer_request_xml(
    bank: Bank,
    protocol: NegotiatedProtocol,
    transaction_id: TransactionId,
    segment_number: int,
    key_provider: KeyProvider,
    authentication_certificate_der: bytes,
) -> bytes:
    return _build_haa_transfer_request_xml(
        bank,
        protocol,
        transaction_id,
        segment_number,
        key_provider,
        authentication_certificate_der,
    )


def _build_btd_receipt_request_xml(
    bank: Bank,
    protocol: NegotiatedProtocol,
    transaction_id: TransactionId,
    receipt: ReceiptKind,
    key_provider: KeyProvider,
    authentication_certificate_der: bytes,
) -> bytes:
    return _build_haa_receipt_request_xml(
        bank,
        protocol,
        transaction_id,
        receipt,
        key_provider,
        authentication_certificate_der,
    )


def _parse_btd_initial_response(
    response_xml: bytes,
    trusted_bank_keys: TrustedBankKeys,
    subscriber_encryption_certificate_der: bytes,
    key_provider: KeyProvider,
    xml_limits: XmlLimits,
    protocol_limits: ProtocolLimits,
) -> _HaaInitialResponse:
    return _parse_haa_initial_response(
        response_xml,
        trusted_bank_keys,
        subscriber_encryption_certificate_der,
        key_provider,
        xml_limits,
        protocol_limits,
    )


def _parse_btd_transfer_response(
    response_xml: bytes,
    trusted_bank_keys: TrustedBankKeys,
    transaction_id: TransactionId,
    segment_number: int,
    total_segments: int,
    xml_limits: XmlLimits,
) -> _HaaOrderDataFragment:
    return _parse_haa_transfer_response(
        response_xml,
        trusted_bank_keys,
        transaction_id,
        segment_number,
        total_segments,
        xml_limits,
    )


def _parse_btd_receipt_response(
    response_xml: bytes,
    trusted_bank_keys: TrustedBankKeys,
    transaction_id: TransactionId,
    receipt: ReceiptKind,
    xml_limits: XmlLimits,
) -> None:
    _parse_haa_receipt_response(
        response_xml, trusted_bank_keys, transaction_id, receipt, xml_limits
    )
