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
from test_hpd import _order_data as _hpd_order_data

from ebics_read import (
    Bank,
    CapabilityDiscovery,
    ContainerType,
    CustomerInformation,
    EbicsBackend,
    NegotiatedProtocol,
    OrderType,
    ReplayError,
    Subscriber,
    TrustedBankKeys,
    XmlSecurityError,
)
from ebics_read.hkd import _parse_hkd_information

_H005 = "urn:org:ebics:H005"
_SERVICE = b"""
<Service>
  <ServiceName>EOP</ServiceName>
  <Scope>AT</Scope>
  <MsgName version="08" variant="001" format="XML">camt.053</MsgName>
</Service>
"""
_UPLOAD_SERVICE = b"""
<Service><ServiceName>SCT</ServiceName><MsgName>pain.001</MsgName></Service>
"""


def _order_data() -> bytes:
    return f"""
<HKDResponseOrderData xmlns="{_H005}"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xsi:schemaLocation="{_H005} ebics_orders_H005.xsd">
 <PartnerInfo>
  <AddressInfo><Name>Synthetic Customer</Name><PostCode>1010</PostCode></AddressInfo>
  <BankInfo>
   <HostID>HOST</HostID>
   <Parameter><Name>mode</Name><Value Type="string">synthetic</Value></Parameter>
  </BankInfo>
  <AccountInfo ID="ACCOUNT1" Currency="USD" Description="Statement account">
   <AccountNumber international="true">AT611904300234573201</AccountNumber>
   <BankCode international="true">BKAUATWW</BankCode>
   <UsageOrderTypes>{_SERVICE.decode()}</UsageOrderTypes>
  </AccountInfo>
  <AccountInfo ID="ACCOUNT2">
   <NationalAccountNumber format="other">synthetic-2</NationalAccountNumber>
   <UsageOrderTypes/>
  </AccountInfo>
  <OrderInfo>
   <AdminOrderType>BTD</AdminOrderType>{_SERVICE.decode()}
   <Description>Statement download</Description>
  </OrderInfo>
  <OrderInfo>
   <AdminOrderType>BTU</AdminOrderType>
   <Service><ServiceName>SCT</ServiceName><MsgName>pain.001</MsgName></Service>
   <Description>Discarded upload capability</Description>
   <NumSigRequired>2</NumSigRequired>
  </OrderInfo>
 </PartnerInfo>
 <UserInfo>
  <UserID Status="1">CURRENT</UserID><Name>Current User</Name>
  <Permission AuthorisationLevel="A">
   <AdminOrderType>BTD</AdminOrderType>{_SERVICE.decode()}
   <AccountID>ACCOUNT1</AccountID><MaxAmount Currency="EUR">6000.00</MaxAmount>
  </Permission>
  <Permission><AdminOrderType>BTU</AdminOrderType>
   <Service><ServiceName>SCT</ServiceName><MsgName>pain.001</MsgName></Service>
  </Permission>
 </UserInfo>
 <UserInfo><UserID Status="99">OTHER</UserID>
  <Permission><AdminOrderType>BTD</AdminOrderType>{_SERVICE.decode()}</Permission>
 </UserInfo>
</HKDResponseOrderData>
""".encode()


def _parse(xml: bytes | None = None) -> CustomerInformation:
    return _parse_hkd_information(
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


def _discover_hkd(
    backend: EbicsBackend, trusted: TrustedBankKeys
) -> CapabilityDiscovery:
    return backend._discover_hkd(
        Bank("https://configured-bank.invalid/ebics", "HOST"),
        Subscriber("PARTNER=1", "CURRENT", "SYSTEM1"),
        NegotiatedProtocol(),
        trusted,
        object(),  # type: ignore[arg-type]
    )


def test_hkd_downloads_and_aggregates_when_hpd_advertises_client_data() -> None:
    hpd = _hpd_order_data()
    backend, transport, trusted = _setup(order_data=hpd)
    transport.fragments_by_order = {
        OrderType.HPD: _fragments(order_data=hpd),
        OrderType.HKD: _fragments(order_data=_order_data()),
    }
    transport.transaction_ids_by_order = {
        OrderType.HPD: _TRANSACTION_ID,
        OrderType.HKD: "22334455667788990011AABBCCDDEEFF",
    }

    result = _discover(backend, trusted)

    assert result.completed_orders == (OrderType.HPD, OrderType.HKD)
    assert result.unsupported_orders == (OrderType.HAA,)
    assert len(result.services) == 1
    assert len(result.customer_information) == 1
    assert [request.order for request in transport.requests] == [
        OrderType.HPD,
        OrderType.HPD,
        OrderType.HPD,
        OrderType.HKD,
        OrderType.HKD,
        OrderType.HKD,
    ]
    assert all(
        request.bank.endpoint == "https://configured-bank.invalid/ebics"
        for request in transport.requests
    )
    assert isinstance(backend.key_provider, _Provider)
    for request in transport.requests:
        _assert_request_signature(request.body, backend.key_provider.authentication_key)


def test_hkd_gate_actual_unsupported_and_global_replay() -> None:
    hpd_disabled = _hpd_order_data(client_data=False)
    backend, transport, trusted = _setup(order_data=hpd_disabled)
    result = _discover(backend, trusted)
    assert result.completed_orders == (OrderType.HPD,)
    assert result.unsupported_orders == (OrderType.HAA, OrderType.HKD)
    assert [request.order for request in transport.requests] == [OrderType.HPD] * 3

    hpd = _hpd_order_data()
    backend, transport, trusted = _setup(order_data=hpd)
    transport.fragments_by_order = {
        OrderType.HPD: _fragments(order_data=hpd),
        OrderType.HKD: _fragments(order_data=_order_data()),
    }
    transport.technical_by_order = {OrderType.HKD: "091006"}
    result = _discover(backend, trusted)
    assert result.completed_orders == (OrderType.HPD,)
    assert result.unsupported_orders == (OrderType.HAA, OrderType.HKD)
    assert [request.order for request in transport.requests] == [
        OrderType.HPD,
        OrderType.HPD,
        OrderType.HPD,
        OrderType.HKD,
    ]

    backend, transport, trusted = _setup(order_data=hpd)
    transport.fragments_by_order = {
        OrderType.HPD: _fragments(order_data=hpd),
        OrderType.HKD: _fragments(order_data=_order_data()),
    }
    with pytest.raises(ReplayError):
        _discover(backend, trusted)
    assert [request.order for request in transport.requests] == [
        OrderType.HPD,
        OrderType.HPD,
        OrderType.HPD,
        OrderType.HKD,
    ]


def test_hkd_complete_invalid_payload_gets_negative_receipt() -> None:
    invalid = _order_data().replace(b"<PartnerInfo>", b"<Unsupported/><PartnerInfo>", 1)
    backend, transport, trusted = _setup(order_data=invalid)
    with pytest.raises(XmlSecurityError, match="root structure"):
        _discover_hkd(backend, trusted)
    assert [request.order for request in transport.requests] == [OrderType.HKD] * 3
    receipt = etree.fromstring(transport.requests[-1].body)
    assert receipt.findtext(f".//{{{_H005}}}ReceiptCode") == "1"


def test_hkd_maps_only_btd_accounts_services_and_user_permissions() -> None:
    result = _parse()

    assert result.source_order is OrderType.HKD
    assert result.host_id == "HOST"
    assert [
        (account.account_id, account.iban, account.currency)
        for account in result.accounts
    ] == [
        ("ACCOUNT1", "AT611904300234573201", "USD"),
        ("ACCOUNT2", None, "EUR"),
    ]
    assert result.accounts[0].restricted_services == (result.services[0].descriptor,)
    assert result.accounts[1].restricted_services == ()
    assert len(result.services) == 1
    assert result.services[0].source_order is OrderType.HKD
    assert result.services[0].descriptor.container_type is ContainerType.NONE
    assert [(user.user_id, user.status) for user in result.users] == [
        ("CURRENT", 1),
        ("OTHER", 99),
    ]
    assert result.users[0].permissions[0].account_id == "ACCOUNT1"
    assert result.users[1].permissions[0].account_id is None
    assert all(len(user.permissions) == 1 for user in result.users)
    assert "CURRENT" not in repr(result)
    assert "ACCOUNT1" not in repr(result)


def test_hkd_preserves_absent_empty_and_nonempty_account_restrictions() -> None:
    xml = _order_data().replace(b"   <UsageOrderTypes/>\n", b"", 1)
    result = _parse(xml)
    assert result.accounts[0].restricted_services
    assert result.accounts[1].restricted_services is None

    upload_only = _parse(_order_data().replace(_SERVICE, _UPLOAD_SERVICE, 1))
    assert upload_only.accounts[0].restricted_services == ()


@pytest.mark.parametrize(
    "old,new,match",
    (
        (b"<HostID>HOST</HostID>", b"<HostID>OTHER</HostID>", "HostID"),
        (b"<PartnerInfo>", b"<Unsupported/><PartnerInfo>", "root structure"),
        (b"</HostID>\n", b"</HostID>evil\n", "text"),
        (b"<AddressInfo>", b"<AddressInfo><!--comment-->", "comments"),
        (b"<AddressInfo>", b"<AddressInfo><?test value?>", "instructions"),
        (b'ID="ACCOUNT2"', b'ID="ACCOUNT1"', "inconsistent"),
        (
            b"<AccountID>ACCOUNT1</AccountID>",
            b"<AccountID>MISSING</AccountID>",
            "unknown account",
        ),
        (
            b'<UserID Status="1">CURRENT</UserID>',
            b'<UserID Status="1">ABSENT</UserID>',
            "requesting subscriber",
        ),
        (b'Status="99"', b'Status="100"', "status"),
        (b'AuthorisationLevel="A"', b'AuthorisationLevel="X"', "AuthorisationLevel"),
        (b'Type="string"', b'Type="bad:type"', "type"),
    ),
)
def test_hkd_rejects_ambiguous_cross_referenced_or_extended_data(
    old: bytes, new: bytes, match: str
) -> None:
    with pytest.raises(XmlSecurityError, match=match):
        _parse(_order_data().replace(old, new, 1))


def test_hkd_rejects_unknown_or_duplicate_btd_descriptors() -> None:
    changed_usage = _SERVICE.replace(b"EOP", b"STM", 1)
    with pytest.raises(XmlSecurityError, match="restriction"):
        _parse(_order_data().replace(_SERVICE, changed_usage, 1))

    duplicate = (
        _order_data()
        .replace(
            b"<AdminOrderType>BTU</AdminOrderType>",
            b"<AdminOrderType>BTD</AdminOrderType>",
            1,
        )
        .replace(
            b"<ServiceName>SCT</ServiceName>",
            b"<ServiceName>EOP</ServiceName><Scope>AT</Scope>",
            1,
        )
        .replace(
            b"<MsgName>pain.001</MsgName>",
            b'<MsgName version="08" variant="001" format="XML">camt.053</MsgName>',
            1,
        )
    )
    with pytest.raises(XmlSecurityError, match="duplicate BTD"):
        _parse(duplicate)

    without_service = _order_data().replace(_SERVICE, b"", 2)
    with pytest.raises(XmlSecurityError, match="BTD OrderInfo"):
        _parse(without_service)


def test_hkd_rejects_ambiguous_account_number_branches() -> None:
    duplicate = _order_data().replace(
        b'<AccountNumber international="true">AT611904300234573201</AccountNumber>',
        b'<AccountNumber international="true">AT611904300234573201</AccountNumber>'
        b'<AccountNumber international="true">AT611904300234573201</AccountNumber>',
        1,
    )
    with pytest.raises(XmlSecurityError, match="ambiguous account"):
        _parse(duplicate)


def test_hkd_validates_account_references_before_discarding_upload_permissions() -> (
    None
):
    invalid = _order_data().replace(
        b"<MsgName>pain.001</MsgName></Service>\n  </Permission>",
        b"<MsgName>pain.001</MsgName></Service>"
        b"<AccountID>MISSING</AccountID>\n  </Permission>",
        1,
    )
    with pytest.raises(XmlSecurityError, match="unknown account"):
        _parse(invalid)


@pytest.mark.parametrize("status", ("0", "1", "9", "99"))
def test_hkd_preserves_schema_valid_status_without_promoting_it(status: str) -> None:
    result = _parse(
        _order_data().replace(b'Status="99"', f'Status="{status}"'.encode(), 1)
    )
    assert result.users[1].status == int(status)
