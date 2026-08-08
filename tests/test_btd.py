from __future__ import annotations

from datetime import date

import pytest
from lxml import etree
from test_haa import (
    _NOW,
    _TRANSACTION_ID,
    _assert_request_signature,
    _Provider,
    _response,
    _setup,
)

from ebics_read import (
    AccountSelector,
    Bank,
    BtfDescriptor,
    ConfigurationError,
    ContainerType,
    DateRange,
    DownloadOptions,
    KeyPurpose,
    NegotiatedProtocol,
    ReceiptKind,
    Subscriber,
    TransactionId,
)
from ebics_read.btd import (
    _parse_btd_initial_response,
    _parse_btd_receipt_response,
    _parse_btd_transfer_response,
)
from ebics_read.transport import _PreparedTransportRequest

_H005 = "urn:org:ebics:H005"


def _descriptor(container: ContainerType = ContainerType.ZIP) -> BtfDescriptor:
    return BtfDescriptor("EOP", "camt.053", "08", "001", "XML", "STM", container, "AT")


def _initialization_request(
    *, options: DownloadOptions | None = None
) -> tuple[_PreparedTransportRequest, _Provider]:
    backend, _, trusted = _setup()
    assert isinstance(backend.key_provider, _Provider)
    provider = backend.key_provider
    request = _PreparedTransportRequest._for_btd_initialization(
        Bank("https://bank.invalid/ebics", "HOST"),
        Subscriber("PARTNER=1", "USER,1", "SYSTEM1"),
        NegotiatedProtocol(),
        trusted,
        _descriptor(),
        DownloadOptions() if options is None else options,
        bytes(range(16)),
        _NOW,
        provider,
        provider.certificate_der(KeyPurpose.AUTHENTICATION),
    )
    return request, provider


def test_btd_builds_only_the_exact_typed_download_parameters() -> None:
    request, provider = _initialization_request(
        options=DownloadOptions(DateRange(date(2026, 1, 1), date(2026, 1, 31)))
    )
    root = etree.fromstring(request.body)

    assert request.order.value == "BTD"
    assert root.findtext(f".//{{{_H005}}}AdminOrderType") == "BTD"
    parameters = root.find(f".//{{{_H005}}}BTDOrderParams")
    assert parameters is not None
    assert [etree.QName(child).localname for child in parameters] == [
        "Service",
        "DateRange",
    ]
    service = parameters[0]
    assert [etree.QName(child).localname for child in service] == [
        "ServiceName",
        "Scope",
        "ServiceOption",
        "Container",
        "MsgName",
    ]
    assert service.findtext(f"{{{_H005}}}ServiceName") == "EOP"
    assert service.find(f"{{{_H005}}}Container").get("containerType") == "ZIP"  # type: ignore[union-attr]
    assert service.find(f"{{{_H005}}}MsgName").attrib == {  # type: ignore[union-attr]
        "version": "08",
        "variant": "001",
        "format": "XML",
    }
    assert parameters.findtext(f"{{{_H005}}}DateRange/{{{_H005}}}Start") == (
        "2026-01-01"
    )
    assert not root.findall(f".//{{{_H005}}}Parameter")
    assert not root.findall(f".//{{{_H005}}}OrderID")
    _assert_request_signature(request.body, provider.authentication_key)


def test_btd_rejects_nonstandard_account_parameter_before_signing() -> None:
    with pytest.raises(ConfigurationError, match="no portable"):
        _initialization_request(
            options=DownloadOptions(account=AccountSelector(account_id="ACCOUNT-1"))
        )


def test_btd_reuses_the_exact_authenticated_download_response_contract() -> None:
    backend, transport, trusted = _setup()
    assert isinstance(backend.key_provider, _Provider)
    initial = _parse_btd_initial_response(
        _response(
            transport.bank_key,
            "Initialisation",
            transaction_id=_TRANSACTION_ID,
            total_segments=2,
            segment_number=1,
            fragment="QUJDRA==",
            encryption_der=transport.encryption_der,
        ),
        trusted,
        transport.encryption_der,
        backend.key_provider,
        backend.xml_limits,
        backend.protocol_limits,
    )
    assert initial.transaction_id == TransactionId(_TRANSACTION_ID)
    transfer = _parse_btd_transfer_response(
        _response(
            transport.bank_key,
            "Transfer",
            transaction_id=_TRANSACTION_ID,
            total_segments=2,
            segment_number=2,
            fragment="RUZHSA==",
        ),
        trusted,
        initial.transaction_id,
        2,
        2,
        backend.xml_limits,
    )
    assert transfer.text == "RUZHSA=="
    _parse_btd_receipt_response(
        _response(
            transport.bank_key,
            "Receipt",
            transaction_id=_TRANSACTION_ID,
            technical="011000",
        ),
        trusted,
        initial.transaction_id,
        ReceiptKind.POSITIVE,
        backend.xml_limits,
    )


def test_btd_transfer_and_receipt_builders_remain_fixed() -> None:
    _, provider = _initialization_request()
    bank = Bank("https://bank.invalid/ebics", "HOST")
    transaction_id = TransactionId(_TRANSACTION_ID)
    transfer = _PreparedTransportRequest._for_btd_transfer(
        bank,
        NegotiatedProtocol(),
        transaction_id,
        2,
        provider,
        provider.certificate_der(KeyPurpose.AUTHENTICATION),
    )
    receipt = _PreparedTransportRequest._for_btd_receipt(
        bank,
        NegotiatedProtocol(),
        transaction_id,
        ReceiptKind.NEGATIVE,
        provider,
        provider.certificate_der(KeyPurpose.AUTHENTICATION),
    )

    assert transfer.order.value == receipt.order.value == "BTD"
    assert (
        etree.fromstring(transfer.body).findtext(f".//{{{_H005}}}TransactionPhase")
        == "Transfer"
    )
    assert etree.fromstring(receipt.body).findtext(f".//{{{_H005}}}ReceiptCode") == "1"
    for request in (transfer, receipt):
        _assert_request_signature(request.body, provider.authentication_key)
