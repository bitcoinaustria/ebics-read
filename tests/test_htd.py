from __future__ import annotations

import pytest
from lxml import etree
from test_haa import (
    _TRANSACTION_ID,
    _assert_request_signature,
    _fragments,
    _Provider,
    _setup,
)
from test_hkd import _order_data as _hkd_order_data
from test_hpd import _order_data as _hpd_order_data

from ebics_read import (
    Bank,
    CapabilityDiscovery,
    EbicsBackend,
    NegotiatedProtocol,
    OrderType,
    Subscriber,
    TrustedBankKeys,
    XmlSecurityError,
)
from ebics_read.htd import _parse_htd_information

_H005 = "urn:org:ebics:H005"


def _order_data() -> bytes:
    root = etree.fromstring(_hkd_order_data())
    root.tag = etree.QName(_H005, "HTDResponseOrderData")
    root.remove(root.findall(f"{{{_H005}}}UserInfo")[1])
    return etree.tostring(root)


def _parse(xml: bytes | None = None):  # type: ignore[no-untyped-def]
    return _parse_htd_information(
        etree.fromstring(xml or _order_data()), "HOST", "CURRENT"
    )


def _discover(backend: EbicsBackend, trusted: TrustedBankKeys) -> CapabilityDiscovery:
    return backend.discover_capabilities(
        Bank("https://configured-bank.invalid/ebics", "HOST"),
        Subscriber("PARTNER=1", "CURRENT", "SYSTEM1"),
        NegotiatedProtocol(),
        trusted,
        object(),  # type: ignore[arg-type]
    )


def _discover_htd(
    backend: EbicsBackend, trusted: TrustedBankKeys
) -> CapabilityDiscovery:
    return backend._discover_htd(
        Bank("https://configured-bank.invalid/ebics", "HOST"),
        Subscriber("PARTNER=1", "CURRENT", "SYSTEM1"),
        NegotiatedProtocol(),
        trusted,
        object(),  # type: ignore[arg-type]
    )


def test_htd_maps_only_the_requesting_subscriber() -> None:
    result = _parse()

    assert result.source_order is OrderType.HTD
    assert [user.user_id for user in result.users] == ["CURRENT"]
    assert all(service.source_order is OrderType.HTD for service in result.services)


@pytest.mark.parametrize(
    "xml,match",
    (
        (_hkd_order_data(), "root"),
        (
            _order_data().replace(
                b"</HTDResponseOrderData>",
                b'<UserInfo><UserID Status="1">CURRENT</UserID></UserInfo>'
                b"</HTDResponseOrderData>",
            ),
            "root structure",
        ),
        (_order_data().replace(b">CURRENT</UserID>", b">OTHER</UserID>"), "subscriber"),
    ),
)
def test_htd_rejects_wrong_root_cardinality_or_subscriber(
    xml: bytes, match: str
) -> None:
    with pytest.raises(XmlSecurityError, match=match):
        _parse(xml)


def test_htd_downloads_and_aggregates_independently_of_hkd() -> None:
    hpd = _hpd_order_data()
    backend, transport, trusted = _setup(order_data=hpd)
    transport.fragments_by_order = {
        OrderType.HPD: _fragments(order_data=hpd),
        OrderType.HKD: _fragments(order_data=_hkd_order_data()),
        OrderType.HTD: _fragments(order_data=_order_data()),
    }
    transport.transaction_ids_by_order = {
        OrderType.HPD: _TRANSACTION_ID,
        OrderType.HKD: "22334455667788990011AABBCCDDEEFF",
        OrderType.HTD: "33445566778899001122AABBCCDDEEFF",
    }

    result = _discover(backend, trusted)

    assert result.completed_orders == (OrderType.HPD, OrderType.HKD, OrderType.HTD)
    assert result.unsupported_orders == (OrderType.HAA,)
    assert [value.source_order for value in result.customer_information] == [
        OrderType.HKD,
        OrderType.HTD,
    ]
    assert [request.order for request in transport.requests] == [
        *([OrderType.HPD] * 3),
        *([OrderType.HKD] * 3),
        *([OrderType.HTD] * 3),
    ]
    assert isinstance(backend.key_provider, _Provider)
    for request in transport.requests:
        _assert_request_signature(request.body, backend.key_provider.authentication_key)


def test_htd_actual_unsupported_does_not_discard_completed_hkd() -> None:
    hpd = _hpd_order_data()
    backend, transport, trusted = _setup(order_data=hpd)
    transport.fragments_by_order = {
        OrderType.HPD: _fragments(order_data=hpd),
        OrderType.HKD: _fragments(order_data=_hkd_order_data()),
        OrderType.HTD: _fragments(order_data=_order_data()),
    }
    transport.transaction_ids_by_order = {
        OrderType.HPD: _TRANSACTION_ID,
        OrderType.HKD: "22334455667788990011AABBCCDDEEFF",
        OrderType.HTD: "33445566778899001122AABBCCDDEEFF",
    }
    transport.technical_by_order = {OrderType.HTD: "091006"}

    result = _discover(backend, trusted)

    assert result.completed_orders == (OrderType.HPD, OrderType.HKD)
    assert result.unsupported_orders == (OrderType.HAA, OrderType.HTD)
    assert [value.source_order for value in result.customer_information] == [
        OrderType.HKD
    ]


def test_htd_complete_invalid_payload_gets_negative_receipt() -> None:
    invalid = _order_data().replace(b"<PartnerInfo>", b"<Unsupported/><PartnerInfo>", 1)
    backend, transport, trusted = _setup(order_data=invalid)

    with pytest.raises(XmlSecurityError, match="root structure"):
        _discover_htd(backend, trusted)

    assert [request.order for request in transport.requests] == [OrderType.HTD] * 3
    receipt = etree.fromstring(transport.requests[-1].body)
    assert receipt.findtext(f".//{{{_H005}}}ReceiptCode") == "1"
