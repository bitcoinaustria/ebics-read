from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ebics_read import UnknownReturnCodeError, XmlSecurityError
from ebics_read.h005 import H005_NAMESPACE, parse_h005_response


def response(
    *,
    root: str = "ebicsResponse",
    signature: bytes = b"<AuthSignature/>",
    technical: bytes = b"000000",
    business: bytes = b"000000",
    revision: bytes = b"1",
) -> bytes:
    mutable_prefix = (
        b""
        if root == "ebicsKeyManagementResponse"
        else b"<TransactionPhase>Initialisation</TransactionPhase>"
    )
    return (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b"<"
        + root.encode()
        + b' xmlns="urn:org:ebics:H005" Version="H005" Revision="'
        + revision
        + b'">'
        b'<header authenticate="true"><static/><mutable>'
        + mutable_prefix
        + b"<ReturnCode>"
        + technical
        + b"</ReturnCode><ReportText>[EBICS_OK] OK</ReportText>"
        b"</mutable></header>"
        + signature
        + b'<body><ReturnCode authenticate="true">'
        + business
        + b"</ReturnCode></body></"
        + root.encode()
        + b">"
    )


def test_common_standard_and_key_management_envelopes_are_distinct() -> None:
    parsed = parse_h005_response(response())
    assert parsed.root.tag == f"{{{H005_NAMESPACE}}}ebicsResponse"
    assert parsed.return_codes.technical == "000000"
    assert parsed.return_codes.business == "000000"
    assert "EBICS_OK" not in repr(parsed.return_codes)

    key_response = response(root="ebicsKeyManagementResponse", signature=b"")
    parsed_key = parse_h005_response(key_response, key_management=True)
    assert parsed_key.root.tag.endswith("ebicsKeyManagementResponse")
    assert parse_h005_response(response().replace(b' Revision="1"', b""))
    with pytest.raises(XmlSecurityError, match="root"):
        parse_h005_response(key_response)
    with pytest.raises(TypeError):
        parse_h005_response(response(), key_management=1)  # type: ignore[arg-type]


def test_h005_envelope_rejects_shape_and_authentication_marker_changes() -> None:
    valid = response()
    attacks = (
        valid.replace(b' Revision="1"', b' Revision="2"'),
        valid.replace(b' Revision="1"', b' Revision="1" bad="x"'),
        valid.replace(b"<AuthSignature/>", b""),
        valid.replace(b'<header authenticate="true">', b"<header>"),
        valid.replace(b"<static/>", b'<static bad="x"/>'),
        valid.replace(b'<ReturnCode authenticate="true">', b"<ReturnCode>", 1),
        valid.replace(b"<static/>", b"<unknown/>"),
        valid.replace(b"<static/>", b"<static><unknown/></static>"),
        valid.replace(b"<body>", b"<body><unknown/>"),
        valid.replace(
            b"<TransactionPhase>Initialisation</TransactionPhase>",
            b"<TransactionPhase>Invalid</TransactionPhase>",
        ),
        valid.replace(
            b"</TransactionPhase>",
            b"</TransactionPhase><SegmentNumber>1</SegmentNumber>",
            1,
        ),
        valid.replace(b"<header", b"ATTACK<header", 1),
    )
    for attack in attacks:
        with pytest.raises(XmlSecurityError):
            parse_h005_response(attack)


def test_h005_return_codes_are_bounded_and_fail_closed() -> None:
    assert (
        parse_h005_response(
            response(technical=b"011000", business=b"090005")
        ).return_codes
        == parse_h005_response(
            response(technical=b"011000", business=b"090005")
        ).return_codes
    )
    with pytest.raises(UnknownReturnCodeError):
        parse_h005_response(response(technical=b"099999"))
    with pytest.raises(UnknownReturnCodeError):
        parse_h005_response(response(business=b"099999"))
    with pytest.raises(XmlSecurityError, match="six ASCII digits"):
        parse_h005_response(response(technical=b"00000X"))
    with pytest.raises(XmlSecurityError, match="text leaf"):
        parse_h005_response(response().replace(b"[EBICS_OK] OK", b""))
    with pytest.raises(XmlSecurityError, match="bounds"):
        parse_h005_response(response().replace(b"[EBICS_OK] OK", b"x\n"))


def test_h005_common_transaction_fields_follow_the_schema_shape() -> None:
    rich = (
        response()
        .replace(
            b"<static/>",
            b"<static>"
            b"<TransactionID>0123456789abcdef0123456789ABCDEF</TransactionID>"
            b"<NumSegments>2</NumSegments></static>",
        )
        .replace(
            b"</TransactionPhase>",
            b'</TransactionPhase><SegmentNumber lastSegment="false">1</SegmentNumber>'
            b"<OrderID>A001</OrderID>",
            1,
        )
        .replace(
            b"<body>",
            b"<body><DataTransfer><OrderData>QQ==</OrderData></DataTransfer>",
        )
        .replace(
            b"</ReturnCode></body>",
            b'</ReturnCode><TimestampBankParameter authenticate="true">'
            b"2026-08-08T12:00:00Z</TimestampBankParameter></body>",
        )
    )
    parsed = parse_h005_response(rich)
    assert parsed.return_codes.technical == "000000"
    assert parsed.bank_parameter_timestamp == datetime(
        2026, 8, 8, 12, tzinfo=timezone.utc
    )
    assert parse_h005_response(response()).bank_parameter_timestamp is None

    attacks = (
        rich.replace(b"0123456789abcdef0123456789ABCDEF", b"not-a-transaction-id"),
        rich.replace(b"<NumSegments>2</NumSegments>", b"<NumSegments>0</NumSegments>"),
        rich.replace(b' lastSegment="false"', b""),
        rich.replace(b">1</SegmentNumber>", b">0</SegmentNumber>"),
        rich.replace(b"<OrderID>A001</OrderID>", b"<OrderID>bad</OrderID>"),
        rich.replace(b"<DataTransfer>", b'<DataTransfer bad="x">'),
        rich.replace(
            b'<TimestampBankParameter authenticate="true">2026-08-08T12:00:00Z',
            b'<TimestampBankParameter authenticate="true"><nested/>',
        ),
        rich.replace(b"2026-08-08T12:00:00Z", b"2026-02-30T12:00:00Z"),
        rich.replace(b"<ReturnCode>000000", b'<ReturnCode bad="x">000000'),
    )
    for attack in attacks:
        with pytest.raises(XmlSecurityError):
            parse_h005_response(attack)
