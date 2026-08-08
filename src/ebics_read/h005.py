"""Strict common H005 response envelopes and fail-closed return codes."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from lxml import etree

from .errors import UnknownReturnCodeError, XmlSecurityError
from .xml import XmlLimits, parse_xml_document

H005_NAMESPACE = "urn:org:ebics:H005"
_XSI_NAMESPACE = "http://www.w3.org/2001/XMLSchema-instance"
_SCHEMA_LOCATION = f"{{{_XSI_NAMESPACE}}}schemaLocation"
_STANDARD_ROOT = f"{{{H005_NAMESPACE}}}ebicsResponse"
_KEY_MANAGEMENT_ROOT = f"{{{H005_NAMESPACE}}}ebicsKeyManagementResponse"
_TRANSACTION_ID = re.compile(r"^[0-9A-Fa-f]{32}$")
_SEGMENT_NUMBER = re.compile(r"^[1-9][0-9]{0,9}$")
_ORDER_ID = re.compile(r"^[A-Z][A-Z0-9]{3}$")
_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})?$"
)

# EBICS 3.0.2 Annex 1. Codes are contextual: 091002 has different meanings in
# technical and business fields, so the allowlists intentionally stay separate.
_TECHNICAL_RETURN_CODES = frozenset(
    {
        "000000",
        "011000",
        "011001",
        "011101",
        "031001",
        "061001",
        "061002",
        "061099",
        "061101",
        "091002",
        "091003",
        "091004",
        "091005",
        "091006",
        "091007",
        "091008",
        "091009",
        "091010",
        "091011",
        "091101",
        "091102",
        "091103",
        "091104",
        "091112",
        "091113",
        "091117",
        "091118",
        "091119",
        "091120",
        "091122",
    }
)
_BUSINESS_RETURN_CODES = frozenset(
    {
        "000000",
        "011301",
        "090003",
        "090004",
        "090005",
        "090006",
        "091001",
        "091002",
        "091105",
        "091111",
        "091114",
        "091115",
        "091116",
        "091201",
        "091202",
        "091203",
        "091204",
        "091205",
        "091206",
        "091208",
        "091209",
        "091210",
        "091211",
        "091212",
        "091213",
        "091214",
        "091215",
        "091216",
        "091217",
        "091218",
        "091219",
        "091301",
        "091302",
        "091303",
        "091304",
        "091305",
        "091306",
    }
)


@dataclass(frozen=True, slots=True)
class H005ReturnCodes:
    """Untrusted, structurally parsed response codes; authentication happens later."""

    technical: str
    business: str
    report_text: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class ParsedH005Response:
    """Untrusted common envelope preserved for later X002 verification."""

    root: etree._Element = field(repr=False)
    header: etree._Element = field(repr=False)
    body: etree._Element = field(repr=False)
    return_codes: H005ReturnCodes


def parse_h005_response(
    response_xml: bytes,
    *,
    key_management: bool = False,
    limits: XmlLimits | None = None,
) -> ParsedH005Response:
    """Parse an exact standard or key-management H005 response outer shape."""

    if type(key_management) is not bool:
        raise TypeError("key_management must be a boolean")
    root = parse_xml_document(response_xml, limits)
    expected_root = _KEY_MANAGEMENT_ROOT if key_management else _STANDARD_ROOT
    if root.tag != expected_root:
        raise XmlSecurityError("H005 response root or namespace is invalid")
    _validate_root(root)
    expected_children = (
        ["header", "body"] if key_management else ["header", "AuthSignature", "body"]
    )
    children = list(root)
    if [etree.QName(child).localname for child in children] != expected_children or any(
        etree.QName(child).namespace != H005_NAMESPACE for child in children
    ):
        raise XmlSecurityError("H005 response has an invalid outer shape")
    _require_formatting_whitespace(root)
    for child in children:
        _require_formatting_whitespace(child, tail=True)

    header = children[0]
    body = children[-1]
    _require_authentication_marker(header, "header")
    header_children = list(header)
    if [child.tag for child in header_children] != [
        f"{{{H005_NAMESPACE}}}static",
        f"{{{H005_NAMESPACE}}}mutable",
    ]:
        raise XmlSecurityError("H005 response header has an invalid shape")

    static, mutable = header_children
    if static.attrib or mutable.attrib or body.attrib:
        raise XmlSecurityError("H005 response containers contain attributes")
    _require_common_sequence(header, ("static", "mutable"))
    static_names = _h005_child_names(static)
    mutable_names = _h005_child_names(mutable, allow_extensions=True)
    valid_static: set[tuple[str, ...]]
    valid_mutable: set[tuple[str, ...]]
    if key_management:
        valid_static = {()}
        valid_mutable = {
            ("ReturnCode", "ReportText"),
            ("OrderID", "ReturnCode", "ReportText"),
        }
    else:
        valid_static = {
            (),
            ("TransactionID",),
            ("NumSegments",),
            ("TransactionID", "NumSegments"),
        }
        valid_mutable = {
            ("TransactionPhase", "ReturnCode", "ReportText"),
            ("TransactionPhase", "SegmentNumber", "ReturnCode", "ReportText"),
            ("TransactionPhase", "OrderID", "ReturnCode", "ReportText"),
            (
                "TransactionPhase",
                "SegmentNumber",
                "OrderID",
                "ReturnCode",
                "ReportText",
            ),
        }
    if static_names not in valid_static or mutable_names not in valid_mutable:
        raise XmlSecurityError("H005 response header fields have an invalid shape")
    body_names = _h005_child_names(body)
    if body_names not in {
        ("ReturnCode",),
        ("ReturnCode", "TimestampBankParameter"),
        ("DataTransfer", "ReturnCode"),
        ("DataTransfer", "ReturnCode", "TimestampBankParameter"),
    }:
        raise XmlSecurityError("H005 response body fields have an invalid shape")
    _validate_common_values(static, mutable, body)

    technical = _direct_child(mutable, "ReturnCode")
    report = _direct_child(mutable, "ReportText")
    business = _direct_child(body, "ReturnCode")
    if technical.attrib or report.attrib:
        raise XmlSecurityError("H005 technical return fields contain attributes")
    _require_authentication_marker(business, "business return code")
    timestamp = [
        child
        for child in body
        if child.tag == f"{{{H005_NAMESPACE}}}TimestampBankParameter"
    ]
    if timestamp:
        _require_authentication_marker(timestamp[0], "bank-parameter timestamp")
        value = _leaf_text(timestamp[0])
        try:
            if _TIMESTAMP.fullmatch(value) is None:
                raise ValueError
            parsed_timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
            offset = parsed_timestamp.utcoffset()
            if offset is not None and abs(offset) > timedelta(hours=14):
                raise ValueError
        except ValueError as exc:
            raise XmlSecurityError("H005 bank-parameter timestamp is invalid") from exc
    technical_code = _return_code(technical, _TECHNICAL_RETURN_CODES)
    business_code = _return_code(business, _BUSINESS_RETURN_CODES)
    report_text = _leaf_text(report)
    if len(report_text) > 256 or any(value in report_text for value in "\r\n\t"):
        raise XmlSecurityError("H005 report text violates H005 bounds")
    return ParsedH005Response(
        root,
        header,
        body,
        H005ReturnCodes(technical_code, business_code, report_text),
    )


def _validate_root(root: etree._Element) -> None:
    if root.get("Version") != "H005" or root.get("Revision") not in {None, "1"}:
        raise XmlSecurityError("H005 response version or revision is unsupported")
    if set(root.attrib) - {"Version", "Revision", _SCHEMA_LOCATION}:
        raise XmlSecurityError("H005 response root contains an unknown attribute")
    schema_location = root.get(_SCHEMA_LOCATION)
    if schema_location is not None:
        tokens = schema_location.split()
        if (
            len(tokens) != 2
            or tokens[0] != H005_NAMESPACE
            or len(tokens[1].encode("utf-8")) > 1024
        ):
            raise XmlSecurityError("H005 schemaLocation is not one bounded mapping")


def _direct_child(parent: etree._Element, local_name: str) -> etree._Element:
    tag = f"{{{H005_NAMESPACE}}}{local_name}"
    matches = [child for child in parent if child.tag == tag]
    if len(matches) != 1:
        raise XmlSecurityError(f"H005 response requires one {local_name}")
    return matches[0]


def _validate_common_values(
    static: etree._Element, mutable: etree._Element, body: etree._Element
) -> None:
    for child in static:
        value = _plain_leaf(child)
        pattern = (
            _TRANSACTION_ID
            if etree.QName(child).localname == "TransactionID"
            else _SEGMENT_NUMBER
        )
        if pattern.fullmatch(value) is None:
            raise XmlSecurityError("H005 static response field is invalid")

    phase = next(
        (
            child
            for child in mutable
            if child.tag == f"{{{H005_NAMESPACE}}}TransactionPhase"
        ),
        None,
    )
    if phase is not None and _plain_leaf(phase) not in {
        "Initialisation",
        "Transfer",
        "Receipt",
    }:
        raise XmlSecurityError("H005 transaction phase is invalid")
    segment = next(
        (
            child
            for child in mutable
            if child.tag == f"{{{H005_NAMESPACE}}}SegmentNumber"
        ),
        None,
    )
    if segment is not None:
        if set(segment.attrib) != {"lastSegment"} or segment.get("lastSegment") not in {
            "true",
            "false",
            "1",
            "0",
        }:
            raise XmlSecurityError("H005 segment marker is invalid")
        if _SEGMENT_NUMBER.fullmatch(_leaf_text(segment)) is None:
            raise XmlSecurityError("H005 segment number is invalid")
    order = next(
        (child for child in mutable if child.tag == f"{{{H005_NAMESPACE}}}OrderID"),
        None,
    )
    if order is not None and _ORDER_ID.fullmatch(_plain_leaf(order)) is None:
        raise XmlSecurityError("H005 order ID is invalid")
    transfer = next(
        (child for child in body if child.tag == f"{{{H005_NAMESPACE}}}DataTransfer"),
        None,
    )
    if transfer is not None and transfer.attrib:
        raise XmlSecurityError("H005 data-transfer container contains attributes")


def _plain_leaf(element: etree._Element) -> str:
    if element.attrib:
        raise XmlSecurityError("H005 response field contains attributes")
    return _leaf_text(element)


def _h005_child_names(
    parent: etree._Element, *, allow_extensions: bool = False
) -> tuple[str, ...]:
    _require_formatting_whitespace(parent)
    names: list[str] = []
    extension_seen = False
    for child in parent:
        _require_formatting_whitespace(child, tail=True)
        name = etree.QName(child)
        if name.namespace != H005_NAMESPACE:
            if not allow_extensions:
                raise XmlSecurityError("H005 response contains an extension here")
            extension_seen = True
        elif extension_seen:
            raise XmlSecurityError("H005 response extension fields are out of order")
        else:
            names.append(name.localname)
    return tuple(names)


def _require_common_sequence(parent: etree._Element, expected: tuple[str, ...]) -> None:
    if _h005_child_names(parent) != expected:
        raise XmlSecurityError("H005 response common fields are out of order")


def _return_code(element: etree._Element, known: frozenset[str]) -> str:
    value = _leaf_text(element)
    if len(value) != 6 or not value.isascii() or not value.isdigit():
        raise XmlSecurityError("H005 return code must contain six ASCII digits")
    if value not in known:
        raise UnknownReturnCodeError("H005 response contains an unknown return code")
    return value


def _require_authentication_marker(element: etree._Element, field_name: str) -> None:
    if set(element.attrib) != {"authenticate"} or element.get("authenticate") not in {
        "true",
        "1",
    }:
        raise XmlSecurityError(f"H005 response {field_name} must be authenticated")


def _leaf_text(element: etree._Element) -> str:
    if list(element) or element.text is None or not element.text:
        raise XmlSecurityError("H005 response field is not one non-empty text leaf")
    return element.text


def _require_formatting_whitespace(
    element: etree._Element, *, tail: bool = False
) -> None:
    value = element.tail if tail else element.text
    if value is not None and value.strip():
        raise XmlSecurityError("H005 element-only content contains mixed text")
