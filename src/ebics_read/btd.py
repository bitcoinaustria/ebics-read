"""Exact fixed H005 BTD download envelopes and response parsing."""

from __future__ import annotations

from datetime import datetime, timezone

from lxml import etree

from .errors import ConfigurationError
from .h005 import H005_NAMESPACE
from .haa import (
    _add_bank_digest,
    _build_haa_receipt_request_xml,
    _build_haa_transfer_request_xml,
    _finish_request,
    _HaaInitialResponse,
    _HaaOrderDataFragment,
    _parse_haa_initial_response,
    _parse_haa_receipt_response,
    _parse_haa_transfer_response,
    _request_root,
)
from .interfaces import KeyProvider
from .models import (
    Bank,
    BtfDescriptor,
    ContainerType,
    DownloadOptions,
    NegotiatedProtocol,
    ProtocolLimits,
    ReceiptKind,
    Subscriber,
    TransactionId,
    TrustedBankKeys,
)
from .xml import XmlLimits


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
