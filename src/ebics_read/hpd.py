"""Strict H005 HPD bank-parameter order data."""

from __future__ import annotations

import re
from datetime import datetime, timedelta

from lxml import etree

from .errors import ConfigurationError, XmlSecurityError
from .h005 import H005_NAMESPACE
from .models import AdvertisedBankUrl, BankParameters

_XSI_NAMESPACE = "http://www.w3.org/2001/XMLSchema-instance"
_SCHEMA_LOCATION = f"{{{_XSI_NAMESPACE}}}schemaLocation"
_VERSION = {
    "Protocol": re.compile(r"H[0-9]{3}"),
    "Authentication": re.compile(r"X[0-9]{3}"),
    "Encryption": re.compile(r"E[0-9]{3}"),
    "Signature": re.compile(r"A[0-9]{3}"),
}
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})?"
)


def _parse_hpd_parameters(
    root: etree._Element,
    expected_host_id: str,
    updated_at: datetime | None = None,
) -> BankParameters:
    if root.tag != f"{{{H005_NAMESPACE}}}HPDResponseOrderData":
        raise XmlSecurityError("HPD order-data root is invalid")
    if set(root.attrib) - {_SCHEMA_LOCATION}:
        raise XmlSecurityError("HPD order-data root has an unknown attribute")
    schema_location = root.get(_SCHEMA_LOCATION)
    if schema_location is not None:
        tokens = schema_location.split()
        if (
            len(tokens) != 2
            or tokens[0] != H005_NAMESPACE
            or len(tokens[1].encode("utf-8")) > 1024
        ):
            raise XmlSecurityError("HPD schemaLocation is invalid")
    access, protocol = _exact_children(
        root, ("AccessParams", "ProtocolParams"), attributes_allowed=True
    )
    urls, institute, host_id = _parse_access(access)
    if host_id is not None and host_id != expected_host_id:
        raise XmlSecurityError("HPD HostID does not match the requested bank")
    versions, flags = _parse_protocol(protocol)
    try:
        return BankParameters(
            urls=urls,
            institute=institute,
            host_id=host_id,
            protocol_versions=versions[0],
            authentication_versions=versions[1],
            encryption_versions=versions[2],
            signature_versions=versions[3],
            recovery_supported=flags[0],
            client_data_download_supported=flags[2],
            downloadable_order_data_supported=flags[3],
            updated_at=updated_at,
        )
    except (ConfigurationError, TypeError) as exc:
        raise XmlSecurityError("HPD order data contains invalid parameters") from exc


def _parse_access(
    element: etree._Element,
) -> tuple[tuple[AdvertisedBankUrl, ...], str, str | None]:
    _container(element)
    children = _children(element)
    index = 0
    urls: list[AdvertisedBankUrl] = []
    while index < len(children) and _local(children[index]) == "URL":
        url = children[index]
        if set(url.attrib) - {"valid_from"} or list(url) or url.text is None:
            raise XmlSecurityError("HPD URL has an invalid shape")
        value = url.text
        if not 0 < len(value) <= 2048 or any(
            character.isspace() or ord(character) < 32 or ord(character) == 127
            for character in value
        ):
            raise XmlSecurityError("HPD URL is invalid")
        valid_from = _date_time(url.get("valid_from"), "URL validity")
        urls.append(AdvertisedBankUrl(value, valid_from))
        index += 1
    if not urls or index >= len(children) or _local(children[index]) != "Institute":
        raise XmlSecurityError("HPD access parameters require URL and Institute")
    institute = _leaf(children[index], "Institute")
    index += 1
    host_id = None
    if index < len(children) and _local(children[index]) == "HostID":
        host_id = _leaf(children[index], "HostID")
        index += 1
    if index != len(children) or len(urls) != len(set(urls)):
        raise XmlSecurityError("HPD access parameters are invalid or duplicated")
    return tuple(urls), institute, host_id


def _parse_protocol(
    element: etree._Element,
) -> tuple[tuple[tuple[str, ...], ...], tuple[bool, ...]]:
    all_children = _children(element)
    if not all_children:
        raise XmlSecurityError("HPD protocol parameters require Version first")
    version, *children = all_children
    if _local(version) != "Version":
        raise XmlSecurityError("HPD protocol parameters require Version first")
    version_children = _exact_children(version, tuple(_VERSION))
    versions = tuple(
        _version_list(child, _VERSION[name], name)
        for child, name in zip(version_children, _VERSION, strict=True)
    )
    names = ("Recovery", "PreValidation", "ClientDataDownload", "DownloadableOrderData")
    flags: list[bool] = []
    index = 0
    for name in names:
        if index < len(children) and _local(children[index]) == name:
            flags.append(_support_flag(children[index], name))
            index += 1
        else:
            flags.append(False)
    if index != len(children):
        raise XmlSecurityError(
            "HPD protocol parameters contain an unsupported extension"
        )
    return versions, tuple(flags)


def _version_list(
    element: etree._Element, pattern: re.Pattern[str], name: str
) -> tuple[str, ...]:
    value = _leaf(element, name)
    values = tuple(value.split())
    if (
        not values
        or value != " ".join(values)
        or any(pattern.fullmatch(item) is None for item in values)
        or len(values) != len(set(values))
    ):
        raise XmlSecurityError(f"HPD {name} versions are invalid")
    return values


def _support_flag(element: etree._Element, name: str) -> bool:
    if list(element) or (element.text is not None and element.text.strip()):
        raise XmlSecurityError(f"HPD {name} support flag is invalid")
    if set(element.attrib) - {"supported"}:
        raise XmlSecurityError(f"HPD {name} support flag has an unknown attribute")
    value = element.get("supported")
    if value is None:
        return True
    if value in {"true", "1"}:
        return True
    if value in {"false", "0"}:
        return False
    raise XmlSecurityError(f"HPD {name} support flag is invalid")


def _date_time(value: str | None, name: str) -> datetime | None:
    if value is None:
        return None
    try:
        if _TIMESTAMP.fullmatch(value) is None:
            raise ValueError
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        offset = result.utcoffset()
        if offset is not None and abs(offset) > timedelta(hours=14):
            raise ValueError
        return result
    except ValueError as exc:
        raise XmlSecurityError(f"HPD {name} is invalid") from exc


def _exact_children(
    parent: etree._Element,
    names: tuple[str, ...],
    *,
    attributes_allowed: bool = False,
) -> tuple[etree._Element, ...]:
    children = _children(parent, attributes_allowed=attributes_allowed)
    if len(children) != len(names) or any(
        child.tag != f"{{{H005_NAMESPACE}}}{name}"
        for child, name in zip(children, names, strict=True)
    ):
        raise XmlSecurityError("HPD structure or element order is invalid")
    return tuple(children)


def _children(
    parent: etree._Element, *, attributes_allowed: bool = False
) -> list[etree._Element]:
    _container(parent, attributes_allowed=attributes_allowed)
    children = list(parent)
    if any(child.tail is not None and child.tail.strip() for child in children):
        raise XmlSecurityError("HPD structure contains unexpected text")
    return children


def _container(element: etree._Element, *, attributes_allowed: bool = False) -> None:
    if (element.attrib and not attributes_allowed) or (
        element.text is not None and element.text.strip()
    ):
        raise XmlSecurityError("HPD structure contains unexpected content")


def _leaf(element: etree._Element, name: str) -> str:
    if element.attrib or list(element) or element.text is None:
        raise XmlSecurityError(f"HPD {name} has an invalid shape")
    return element.text


def _local(element: etree._Element) -> str:
    if not isinstance(element.tag, str):
        raise XmlSecurityError("HPD order data contains a comment or instruction")
    name = etree.QName(element)
    if name.namespace != H005_NAMESPACE:
        raise XmlSecurityError("HPD order data contains a foreign element")
    return name.localname
