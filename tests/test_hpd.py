from __future__ import annotations

from datetime import datetime, timezone

import pytest
from lxml import etree
from test_haa import (
    _NOW,
    _TRANSACTION_ID,
    _assert_request_signature,
    _fragments,
    _Provider,
    _setup,
)
from test_haa import (
    _order_data as _haa_order_data,
)

from ebics_read import (
    Bank,
    BankParameters,
    CapabilityDiscovery,
    EbicsBackend,
    EbicsReturnCodeError,
    NegotiatedProtocol,
    OrderType,
    ReplayError,
    Subscriber,
    TrustedBankKeys,
    XmlSecurityError,
)
from ebics_read.hpd import _parse_hpd_parameters

_H005 = "urn:org:ebics:H005"


def _order_data(*, downloadable: bool = False) -> bytes:
    return f"""
    <HPDResponseOrderData xmlns="{_H005}">
      <AccessParams>
        <URL valid_from="2027-01-02T03:04:05+01:00">http://future-bank.invalid/ebics</URL>
        <URL>192.0.2.1</URL>
        <Institute>Synthetic Bank</Institute>
        <HostID>HOST</HostID>
      </AccessParams>
      <ProtocolParams>
        <Version>
          <Protocol>H005 H004</Protocol>
          <Authentication>X002 X001</Authentication>
          <Encryption>E002 E001</Encryption>
          <Signature>A006 A005</Signature>
        </Version>
        <Recovery/>
        <PreValidation supported="false"/>
        <ClientDataDownload supported="1"/>
        <DownloadableOrderData supported="{str(downloadable).lower()}"/>
      </ProtocolParams>
    </HPDResponseOrderData>
    """.encode()


def _parse(xml: bytes | None = None) -> BankParameters:
    updated_at = datetime(2026, 8, 8, 12, tzinfo=timezone.utc)
    return _parse_hpd_parameters(
        etree.fromstring(xml or _order_data()), "HOST", updated_at
    )


def _discover(backend: EbicsBackend, trusted: TrustedBankKeys) -> CapabilityDiscovery:
    return backend.discover_capabilities(
        Bank("https://configured-bank.invalid/ebics", "HOST"),
        Subscriber("PARTNER=1", "USER,1", "SYSTEM1"),
        NegotiatedProtocol(),
        trusted,
        object(),  # type: ignore[arg-type]
    )


def test_hpd_downloads_parameters_then_gates_unadvertised_haa() -> None:
    backend, transport, trusted = _setup(order_data=_order_data())
    transport.bank_parameter_timestamp = _NOW

    result = _discover(backend, trusted)

    assert result.completed_orders == (OrderType.HPD,)
    assert result.unsupported_orders == (OrderType.HAA,)
    assert result.bank_parameters is not None
    assert result.bank_parameters.updated_at == _NOW
    assert [request.order for request in transport.requests] == [OrderType.HPD] * 3
    assert all(
        request.bank.endpoint == "https://configured-bank.invalid/ebics"
        for request in transport.requests
    )
    roots = [etree.fromstring(request.body) for request in transport.requests]
    assert [root.findtext(f".//{{{_H005}}}TransactionPhase") for root in roots] == [
        "Initialisation",
        "Transfer",
        "Receipt",
    ]
    assert roots[0].findtext(f".//{{{_H005}}}AdminOrderType") == "HPD"
    assert roots[-1].findtext(f".//{{{_H005}}}ReceiptCode") == "0"
    assert isinstance(backend.key_provider, _Provider)
    for request in transport.requests:
        _assert_request_signature(request.body, backend.key_provider.authentication_key)


def test_hpd_advertisement_aggregates_actual_haa_result() -> None:
    backend, transport, trusted = _setup(order_data=_order_data(downloadable=True))
    transport.fragments_by_order = {
        OrderType.HPD: _fragments(order_data=_order_data(downloadable=True)),
        OrderType.HAA: _fragments(order_data=_haa_order_data()),
    }
    transport.transaction_ids_by_order = {
        OrderType.HPD: _TRANSACTION_ID,
        OrderType.HAA: "11223344556677889900AABBCCDDEEFF",
    }

    result = _discover(backend, trusted)

    assert result.completed_orders == (OrderType.HPD, OrderType.HAA)
    assert len(result.services) == 4
    assert [request.order for request in transport.requests] == [
        OrderType.HPD,
        OrderType.HPD,
        OrderType.HPD,
        OrderType.HAA,
        OrderType.HAA,
        OrderType.HAA,
    ]

    backend, transport, trusted = _setup(order_data=_order_data(downloadable=True))
    transport.fragments_by_order = {
        OrderType.HPD: _fragments(order_data=_order_data(downloadable=True)),
        OrderType.HAA: _fragments(order_data=_haa_order_data()),
    }
    transport.technical_by_order = {OrderType.HAA: "091006"}
    result = _discover(backend, trusted)
    assert result.completed_orders == (OrderType.HPD,)
    assert result.unsupported_orders == (OrderType.HAA,)
    assert [request.order for request in transport.requests] == [
        OrderType.HPD,
        OrderType.HPD,
        OrderType.HPD,
        OrderType.HAA,
    ]


def test_hpd_unsupported_falls_back_to_haa_but_replay_stays_global() -> None:
    backend, transport, trusted = _setup()
    transport.technical_by_order = {OrderType.HPD: "091006"}
    result = _discover(backend, trusted)
    assert result.completed_orders == (OrderType.HAA,)
    assert result.unsupported_orders == (OrderType.HPD,)
    assert [request.order for request in transport.requests] == [
        OrderType.HPD,
        OrderType.HAA,
        OrderType.HAA,
        OrderType.HAA,
    ]

    backend, transport, trusted = _setup(order_data=_order_data(downloadable=True))
    transport.fragments_by_order = {
        OrderType.HPD: _fragments(order_data=_order_data(downloadable=True)),
        OrderType.HAA: _fragments(order_data=_haa_order_data()),
    }
    with pytest.raises(ReplayError):
        _discover(backend, trusted)
    assert [request.order for request in transport.requests] == [
        OrderType.HPD,
        OrderType.HPD,
        OrderType.HPD,
        OrderType.HAA,
    ]


def test_hpd_sends_negative_receipt_for_complete_invalid_parameters() -> None:
    invalid = _order_data().replace(
        b"<AccessParams>", b"<Unsupported/><AccessParams>", 1
    )
    backend, transport, trusted = _setup(order_data=invalid)

    with pytest.raises(XmlSecurityError, match="structure"):
        _discover(backend, trusted)

    assert [request.order for request in transport.requests] == [OrderType.HPD] * 3
    receipt = etree.fromstring(transport.requests[-1].body)
    assert receipt.findtext(f".//{{{_H005}}}ReceiptCode") == "1"


def test_hpd_business_rejection_aborts_without_partial_result_or_receipt() -> None:
    backend, transport, trusted = _setup(order_data=_order_data(), business="090005")
    with pytest.raises(EbicsReturnCodeError) as rejected:
        _discover(backend, trusted)
    assert (rejected.value.technical, rejected.value.business) == (
        "000000",
        "090005",
    )
    assert len(transport.requests) == 1


def test_hpd_maps_exact_read_relevant_parameters_without_following_urls() -> None:
    result = _parse()

    assert [url.value for url in result.urls] == [
        "http://future-bank.invalid/ebics",
        "192.0.2.1",
    ]
    assert result.urls[0].valid_from == datetime.fromisoformat(
        "2027-01-02T03:04:05+01:00"
    )
    assert result.institute == "Synthetic Bank"
    assert result.host_id == "HOST"
    assert result.protocol_versions == ("H005", "H004")
    assert result.authentication_versions == ("X002", "X001")
    assert result.encryption_versions == ("E002", "E001")
    assert result.signature_versions == ("A006", "A005")
    assert result.recovery_supported is True
    assert result.client_data_download_supported is True
    assert result.downloadable_order_data_supported is False
    assert result.updated_at == datetime(2026, 8, 8, 12, tzinfo=timezone.utc)


def test_hpd_support_flags_default_by_element_presence() -> None:
    xml = (
        _order_data()
        .replace(b"<Recovery/>", b'<Recovery supported="false"/>')
        .replace(b'<ClientDataDownload supported="1"/>', b"<ClientDataDownload/>")
        .replace(b'<DownloadableOrderData supported="0"/>', b"")
    )
    result = _parse(xml)
    assert result.recovery_supported is False
    assert result.client_data_download_supported is True
    assert result.downloadable_order_data_supported is False


def test_hpd_accepts_only_an_inert_bounded_schema_location() -> None:
    root = (
        f'<HPDResponseOrderData xmlns="{_H005}"'.encode()
        + b' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
        + b' xsi:schemaLocation="urn:org:ebics:H005 ebics_orders_H005.xsd">'
    )
    assert _parse(
        _order_data().replace(
            f'<HPDResponseOrderData xmlns="{_H005}">'.encode(), root, 1
        )
    )
    with pytest.raises(XmlSecurityError, match="schemaLocation"):
        _parse(
            _order_data().replace(
                f'<HPDResponseOrderData xmlns="{_H005}">'.encode(),
                root.replace(
                    b'xsi:schemaLocation="urn:org:ebics:H005',
                    b'xsi:schemaLocation="urn:foreign',
                    1,
                ),
                1,
            )
        )


@pytest.mark.parametrize(
    "old,new",
    (
        (f'xmlns="{_H005}"'.encode(), b'xmlns="urn:foreign"'),
        (b"<AccessParams>", b'<AccessParams bad="x">'),
        (b"</URL>\n        <URL>", b"</URL>evil<URL>"),
        (
            b"<Institute>Synthetic Bank</Institute>",
            b"<Unknown>Synthetic Bank</Unknown>",
        ),
        (b"<HostID>HOST</HostID>", b"<HostID>OTHER</HostID>"),
        (b"http://future-bank.invalid/ebics", b"http://future bank.invalid/ebics"),
        (b"2027-01-02T03:04:05+01:00", b"2027-02-30T03:04:05Z"),
        (b"H005 H004", b"H005 H005"),
        (b"X002 X001", b"X002  X001"),
        (b"E002 E001", b"E002 A001"),
        (b"<Recovery/>", b'<Recovery supported="yes"/>'),
        (b'<PreValidation supported="false"/>', b'<PreValidation bad="false"/>'),
        (
            b"</Version>",
            b"</Version><Extension/>",
        ),
        (b"<URL valid_from=", b"<!--comment--><URL valid_from="),
        (b"<URL valid_from=", b"<?test value?><URL valid_from="),
    ),
)
def test_hpd_rejects_ambiguous_or_extended_parameter_data(
    old: bytes, new: bytes
) -> None:
    with pytest.raises(XmlSecurityError):
        _parse(_order_data().replace(old, new, 1))


def test_hpd_rejects_duplicate_urls_and_missing_required_fields() -> None:
    duplicate = _order_data().replace(
        b"<Institute>", b"<URL>192.0.2.1</URL><Institute>", 1
    )
    with pytest.raises(XmlSecurityError, match="duplicated"):
        _parse(duplicate)
    with pytest.raises(XmlSecurityError, match="URL and Institute"):
        _parse(
            _order_data().replace(
                b'<URL valid_from="2027-01-02T03:04:05+01:00">'
                b"http://future-bank.invalid/ebics</URL>\n"
                b"        <URL>192.0.2.1</URL>",
                b"",
            )
        )
