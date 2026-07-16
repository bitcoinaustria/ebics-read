"""Strict HEV/H000 response parsing and exact H005 negotiation."""

from __future__ import annotations

from lxml import etree

from .errors import (
    ConfigurationError,
    ProtocolError,
    UnknownReturnCodeError,
    XmlSecurityError,
)
from .models import ProtocolVersion, VersionDiscovery
from .xml import XmlLimits, parse_xml_document

HEV_NAMESPACE = "http://www.ebics.org/H000"
H005_NAMESPACE = "urn:org:ebics:H005"
_XSI_NAMESPACE = "http://www.w3.org/2001/XMLSchema-instance"
_HEV_RESPONSE = f"{{{HEV_NAMESPACE}}}ebicsHEVResponse"
_SYSTEM_RETURN_CODE = f"{{{HEV_NAMESPACE}}}SystemReturnCode"
_RETURN_CODE = f"{{{HEV_NAMESPACE}}}ReturnCode"
_REPORT_TEXT = f"{{{HEV_NAMESPACE}}}ReportText"
_VERSION_NUMBER = f"{{{HEV_NAMESPACE}}}VersionNumber"
_SCHEMA_LOCATION = f"{{{_XSI_NAMESPACE}}}schemaLocation"
_HEV_OK = "000000"
_HEV_INVALID_HOST = "091011"


def parse_hev_response(
    response_xml: bytes, limits: XmlLimits | None = None
) -> VersionDiscovery:
    """Parse one successful HEV response with an exact H000 shape."""

    root = parse_xml_document(response_xml, limits)
    if root.tag != _HEV_RESPONSE:
        raise XmlSecurityError("HEV response root or namespace is invalid")
    _validate_root_attributes(root)
    children = list(root)
    _require_formatting_whitespace(root.text)
    for child in children:
        _require_formatting_whitespace(child.tail)
    if not children or children[0].tag != _SYSTEM_RETURN_CODE:
        raise XmlSecurityError("HEV response lacks the ordered SystemReturnCode")
    return_code = _parse_system_return_code(children[0])
    if return_code == _HEV_INVALID_HOST:
        raise ProtocolError("bank rejected the configured HEV host identifier")
    if return_code != _HEV_OK:
        raise UnknownReturnCodeError("HEV returned an unsupported return code")
    versions = tuple(_parse_version(element) for element in children[1:])
    try:
        return VersionDiscovery(versions)
    except ConfigurationError as exc:
        raise ProtocolError("HEV version advertisements are inconsistent") from exc


def _validate_root_attributes(root: etree._Element) -> None:
    if set(root.attrib) - {_SCHEMA_LOCATION}:
        raise XmlSecurityError("HEV response root contains an unknown attribute")
    schema_location = root.get(_SCHEMA_LOCATION)
    if schema_location is not None:
        tokens = schema_location.split()
        if tokens != [HEV_NAMESPACE, "ebics_hev.xsd"]:
            raise XmlSecurityError("HEV schemaLocation is not the exact H000 mapping")


def _parse_system_return_code(element: etree._Element) -> str:
    if element.attrib:
        raise XmlSecurityError("HEV SystemReturnCode contains attributes")
    children = list(element)
    _require_formatting_whitespace(element.text)
    for child in children:
        _require_formatting_whitespace(child.tail)
    if [child.tag for child in children] != [_RETURN_CODE, _REPORT_TEXT]:
        raise XmlSecurityError("HEV SystemReturnCode has an invalid shape")
    if children[0].attrib or children[1].attrib:
        raise XmlSecurityError("HEV return fields contain attributes")
    return_code = _required_text(children[0])
    report_text = _required_text(children[1])
    if len(return_code) != 6 or not return_code.isascii() or not return_code.isdigit():
        raise XmlSecurityError("HEV return code must contain six ASCII digits")
    if len(report_text) > 256 or any(value in report_text for value in "\r\n\t"):
        raise XmlSecurityError("HEV report text violates H000 bounds")
    return return_code


def _parse_version(element: etree._Element) -> ProtocolVersion:
    if element.tag != _VERSION_NUMBER or list(element):
        raise XmlSecurityError("HEV response contains an unknown element")
    if set(element.attrib) != {"ProtocolVersion"}:
        raise XmlSecurityError("HEV VersionNumber attributes are invalid")
    protocol_version = element.attrib["ProtocolVersion"]
    if not isinstance(protocol_version, str):
        raise XmlSecurityError("HEV ProtocolVersion must be UTF-8 text")
    return ProtocolVersion(
        protocol_version=protocol_version,
        version_number=_required_text(element),
    )


def _required_text(element: etree._Element) -> str:
    if element.text is None:
        raise XmlSecurityError("HEV field text is missing")
    value = element.text.strip()
    if not value:
        raise XmlSecurityError("HEV field text is empty")
    return value


def _require_formatting_whitespace(value: str | None) -> None:
    if value is not None and value.strip():
        raise XmlSecurityError("HEV element-only content contains mixed text")
