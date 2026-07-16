import pytest

from ebicsmit import (
    ProtocolError,
    UnknownReturnCodeError,
    UnsupportedProtocolVersionError,
    XmlSecurityError,
)
from ebicsmit.hev import H005_NAMESPACE, HEV_NAMESPACE, parse_hev_response


def response(
    versions: bytes = b'<VersionNumber ProtocolVersion="H005">03.00</VersionNumber>',
    return_code: bytes = b"000000",
    extra_root_attribute: bytes = b"",
) -> bytes:
    return (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<ebicsHEVResponse xmlns="http://www.ebics.org/H000" '
        b'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        b'xsi:schemaLocation="http://www.ebics.org/H000 ebics_hev.xsd"'
        + extra_root_attribute
        + b">"
        b"<SystemReturnCode><ReturnCode>"
        + return_code
        + b"</ReturnCode><ReportText>EBICS_OK</ReportText></SystemReturnCode>"
        + versions
        + b"</ebicsHEVResponse>"
    )


def test_parses_h000_and_negotiates_exact_h005() -> None:
    negotiated = parse_hev_response(response()).select_h005()
    assert negotiated.hev_namespace == HEV_NAMESPACE
    assert negotiated.request_namespace == H005_NAMESPACE
    assert negotiated.protocol_version == "H005"
    assert negotiated.version_number == "03.00"


def test_rejects_downgrade_duplicate_and_conflicting_advertisements() -> None:
    h004 = b'<VersionNumber ProtocolVersion="H004">02.50</VersionNumber>'
    with pytest.raises(UnsupportedProtocolVersionError):
        parse_hev_response(response(h004)).select_h005()
    with pytest.raises(ProtocolError, match="inconsistent"):
        parse_hev_response(response(h004 + h004))
    conflict = (
        b'<VersionNumber ProtocolVersion="H005">03.00</VersionNumber>'
        b'<VersionNumber ProtocolVersion="H005">03.01</VersionNumber>'
    )
    with pytest.raises(ProtocolError, match="inconsistent"):
        parse_hev_response(response(conflict))


def test_rejects_wrong_namespaces_shape_attributes_and_schema_location() -> None:
    payloads = (
        response().replace(b"http://www.ebics.org/H000", b"urn:wrong", 1),
        response()
        .replace(b"<VersionNumber", b"<Foreign", 1)
        .replace(b"</VersionNumber>", b"</Foreign>", 1),
        response(extra_root_attribute=b' unsafe="true"'),
        response().replace(b"H000 ebics_hev.xsd", b"H000 remote.xsd"),
    )
    for payload in payloads:
        with pytest.raises(XmlSecurityError):
            parse_hev_response(payload)


def test_hev_return_codes_fail_closed() -> None:
    with pytest.raises(ProtocolError, match="host identifier"):
        parse_hev_response(response(return_code=b"091011"))
    with pytest.raises(UnknownReturnCodeError):
        parse_hev_response(response(return_code=b"099999"))


def test_rejects_schema_invalid_mixed_character_data() -> None:
    payloads = (
        response().replace(b"><SystemReturnCode>", b">ATTACK<SystemReturnCode>"),
        response().replace(
            b"</ReturnCode><ReportText>", b"</ReturnCode>JUNK<ReportText>"
        ),
        response().replace(
            b"</SystemReturnCode><VersionNumber",
            b"</SystemReturnCode>TAIL<VersionNumber",
        ),
    )
    for payload in payloads:
        with pytest.raises(XmlSecurityError, match="mixed text"):
            parse_hev_response(payload)


def test_rejects_schema_invalid_h000_field_shapes() -> None:
    valid = response()
    payloads = (
        valid.replace(b"<SystemReturnCode>", b'<SystemReturnCode bad="1">'),
        valid.replace(b"<ReturnCode>", b'<ReturnCode bad="1">'),
        valid.replace(b"<ReportText>", b"<Unexpected>"),
        valid.replace(b"</ReportText>", b"</Unexpected>"),
        valid.replace(b"000000", b"00A000"),
        valid.replace(b"EBICS_OK", b"BAD\nREPORT"),
        valid.replace(b">03.00</VersionNumber>", b"></VersionNumber>"),
        valid.replace(b"<SystemReturnCode>", b"<VersionNumber>"),
    )
    for payload in payloads:
        with pytest.raises(XmlSecurityError):
            parse_hev_response(payload)
