"""Strict H005 HTD subscriber order data."""

from __future__ import annotations

from datetime import datetime

from lxml import etree

from .haa import (
    _build_haa_receipt_request_xml,
    _build_haa_transfer_request_xml,
    _build_metadata_initialization_request_xml,
    _decode_metadata_order_data,
    _HaaInitialResponse,
    _HaaOrderDataFragment,
    _parse_haa_initial_response,
    _parse_haa_receipt_response,
    _parse_haa_transfer_response,
)
from .hkd import _parse_customer_information
from .interfaces import KeyProvider
from .models import (
    Bank,
    CustomerInformation,
    NegotiatedProtocol,
    ProtocolLimits,
    ReceiptKind,
    Subscriber,
    TransactionId,
    TrustedBankKeys,
)
from .orders import OrderType
from .xml import XmlLimits


def _build_htd_initialization_request_xml(
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
        "HTD",
        bank,
        subscriber,
        protocol,
        trusted_bank_keys,
        nonce,
        timestamp,
        key_provider,
        authentication_certificate_der,
    )


def _build_htd_transfer_request_xml(
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


def _build_htd_receipt_request_xml(
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


def _parse_htd_initial_response(
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


def _parse_htd_transfer_response(
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


def _parse_htd_receipt_response(
    response_xml: bytes,
    trusted_bank_keys: TrustedBankKeys,
    transaction_id: TransactionId,
    receipt: ReceiptKind,
    xml_limits: XmlLimits,
) -> None:
    _parse_haa_receipt_response(
        response_xml, trusted_bank_keys, transaction_id, receipt, xml_limits
    )


def _decode_htd_information(
    fragments: list[str],
    transaction_key: bytes,
    expected_host_id: str,
    expected_user_id: str,
    xml_limits: XmlLimits,
    protocol_limits: ProtocolLimits,
) -> CustomerInformation:
    return _parse_htd_information(
        _decode_metadata_order_data(
            fragments, transaction_key, xml_limits, protocol_limits
        ),
        expected_host_id,
        expected_user_id,
    )


def _parse_htd_information(
    root: etree._Element, expected_host_id: str, expected_user_id: str
) -> CustomerInformation:
    return _parse_customer_information(
        root, expected_host_id, expected_user_id, OrderType.HTD
    )
