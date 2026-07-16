"""Hardened XML trust boundary shared by future order parsers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import NoReturn

from lxml import etree

from .errors import ResponseLimitError, XmlSecurityError

_XINCLUDE_NAMESPACE = "http://www.w3.org/2001/XInclude"
_ID_LOCAL_NAMES = frozenset({"Id", "ID", "id"})
_XML_DECLARATION = re.compile(
    rb"\A(?:\xef\xbb\xbf)?<\?xml\s+[^?]*?encoding\s*=\s*(['\"])([^'\"]+)\1[^?]*\?>",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class XmlLimits:
    """Immutable parser resource limits."""

    max_input_bytes: int = 16 * 1024 * 1024
    max_depth: int = 64
    max_elements: int = 100_000
    max_text_bytes: int = 8 * 1024 * 1024
    max_total_text_bytes: int = 16 * 1024 * 1024
    max_attributes_per_element: int = 64
    max_total_attribute_bytes: int = 1024 * 1024
    max_namespaces: int = 256
    max_namespace_bytes: int = 1024
    max_total_namespace_bytes: int = 16 * 1024

    def __post_init__(self) -> None:
        values = (
            self.max_input_bytes,
            self.max_depth,
            self.max_elements,
            self.max_text_bytes,
            self.max_total_text_bytes,
            self.max_attributes_per_element,
            self.max_total_attribute_bytes,
            self.max_namespaces,
            self.max_namespace_bytes,
            self.max_total_namespace_bytes,
        )
        if not all(type(value) is int for value in values):
            raise TypeError("all XML limits must be integers")
        if min(values) <= 0:
            raise ValueError("all XML limits must be positive")


def parse_xml_document(data: bytes, limits: XmlLimits | None = None) -> etree._Element:
    """Bound-check, then parse the same bytes without changing namespace prefixes."""

    active = limits if limits is not None else XmlLimits()
    if not isinstance(data, bytes):
        raise TypeError("XML input must be bytes")
    if len(data) > active.max_input_bytes:
        raise ResponseLimitError("XML input exceeds configured byte limit")
    if b"\x00" in data:
        raise XmlSecurityError("XML input must use a single-byte UTF-8 encoding")
    try:
        data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise XmlSecurityError("XML input must be valid UTF-8") from exc
    declaration = _XML_DECLARATION.match(data)
    if declaration is not None and declaration.group(2).upper() != b"UTF-8":
        raise XmlSecurityError("XML declaration must specify UTF-8")
    if b"<!DOCTYPE" in data:
        raise XmlSecurityError("DOCTYPE declarations are forbidden")
    scanner = _BoundedXmlScanner(active)
    scan_parser = etree.XMLParser(
        target=scanner,
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        dtd_validation=False,
        recover=False,
        huge_tree=False,
        strip_cdata=False,
    )
    try:
        etree.fromstring(data, scan_parser)
    except (ResponseLimitError, XmlSecurityError):
        raise
    except (etree.XMLSyntaxError, ValueError) as exc:
        raise XmlSecurityError("invalid XML document") from exc
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        dtd_validation=False,
        recover=False,
        huge_tree=False,
        strip_cdata=False,
        remove_comments=False,
        remove_pis=False,
    )
    try:
        root = etree.fromstring(data, parser)
    except (etree.XMLSyntaxError, ValueError) as exc:
        raise XmlSecurityError("invalid XML document") from exc
    if not isinstance(root, etree._Element):
        raise XmlSecurityError("XML document has no root element")
    return root


class _BoundedXmlScanner:
    """Apply structural limits without rebuilding the namespace-sensitive tree."""

    def __init__(self, limits: XmlLimits) -> None:
        self._limits = limits
        self._depth = 0
        self._elements = 0
        self._current_text = 0
        self._total_text = 0
        self._seen_ids: set[str] = set()
        self._total_attribute_bytes = 0
        self._namespaces = 0
        self._total_namespace_bytes = 0
        self._failure: ResponseLimitError | XmlSecurityError | None = None

    def start(
        self, tag: str | bytes, attributes: dict[str | bytes, str | bytes]
    ) -> None:
        if not isinstance(tag, str):
            self._fail(XmlSecurityError("XML element names must be text"))
        self._elements += 1
        self._depth += 1
        self._current_text = 0
        if self._elements > self._limits.max_elements:
            self._fail(ResponseLimitError("XML element count exceeds configured limit"))
        if self._depth > self._limits.max_depth:
            self._fail(ResponseLimitError("XML depth exceeds configured limit"))
        if len(attributes) > self._limits.max_attributes_per_element:
            self._fail(
                ResponseLimitError("XML attribute count exceeds configured limit")
            )
        name = etree.QName(tag)
        if name.namespace == _XINCLUDE_NAMESPACE:
            self._fail(XmlSecurityError("XInclude elements are forbidden"))
        for attribute, attribute_value in attributes.items():
            if not isinstance(attribute, str) or not isinstance(attribute_value, str):
                self._fail(XmlSecurityError("XML attributes must be text"))
            self._total_attribute_bytes += len(attribute.encode("utf-8")) + len(
                attribute_value.encode("utf-8")
            )
            if self._total_attribute_bytes > self._limits.max_total_attribute_bytes:
                self._fail(
                    ResponseLimitError("XML attributes exceed configured byte limit")
                )
            if etree.QName(attribute).localname in _ID_LOCAL_NAMES:
                if attribute_value in self._seen_ids:
                    self._fail(XmlSecurityError("duplicate XML ID detected"))
                self._seen_ids.add(attribute_value)

    def data(self, data: str | bytes) -> None:
        size = len(data if isinstance(data, bytes) else data.encode("utf-8"))
        self._current_text += size
        self._total_text += size
        if self._current_text > self._limits.max_text_bytes:
            self._fail(ResponseLimitError("XML text node exceeds configured limit"))
        if self._total_text > self._limits.max_total_text_bytes:
            self._fail(ResponseLimitError("XML text exceeds configured total limit"))

    def start_ns(self, prefix: str | bytes | None, uri: str | bytes) -> None:
        if (prefix is not None and not isinstance(prefix, str)) or not isinstance(
            uri, str
        ):
            self._fail(XmlSecurityError("XML namespaces must be UTF-8 text"))
        prefix_bytes = 0 if prefix is None else len(prefix.encode("utf-8"))
        namespace_bytes = prefix_bytes + len(uri.encode("utf-8"))
        self._namespaces += 1
        self._total_namespace_bytes += namespace_bytes
        if self._namespaces > self._limits.max_namespaces:
            self._fail(
                ResponseLimitError("XML namespace count exceeds configured limit")
            )
        if namespace_bytes > self._limits.max_namespace_bytes:
            self._fail(
                ResponseLimitError("XML namespace exceeds configured byte limit")
            )
        if self._total_namespace_bytes > self._limits.max_total_namespace_bytes:
            self._fail(
                ResponseLimitError("XML namespaces exceed configured total byte limit")
            )

    def end_ns(self, prefix: str | bytes | None) -> None:
        return None

    def end(self, tag: str | bytes) -> None:
        self._depth -= 1
        self._current_text = 0

    def comment(self, text: str | bytes) -> None:
        self._fail(XmlSecurityError("comments are forbidden"))

    def pi(self, target: str | bytes, data: str | bytes | None = None) -> None:
        self._fail(XmlSecurityError("processing instructions are forbidden"))

    def close(self) -> bool:
        if self._failure is not None:
            raise self._failure
        return True

    def _fail(self, error: ResponseLimitError | XmlSecurityError) -> NoReturn:
        self._failure = error
        raise error
