"""Hardened XML trust boundary shared by future order parsers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import NoReturn

from lxml import etree

from .errors import ResponseLimitError, XmlSecurityError

_XINCLUDE_NAMESPACE = "http://www.w3.org/2001/XInclude"
_ID_LOCAL_NAMES = frozenset({"Id", "ID", "id"})


@dataclass(frozen=True, slots=True)
class XmlLimits:
    """Immutable parser resource limits."""

    max_input_bytes: int = 16 * 1024 * 1024
    max_depth: int = 64
    max_elements: int = 100_000
    max_text_bytes: int = 8 * 1024 * 1024
    max_total_text_bytes: int = 16 * 1024 * 1024

    def __post_init__(self) -> None:
        values = (
            self.max_input_bytes,
            self.max_depth,
            self.max_elements,
            self.max_text_bytes,
            self.max_total_text_bytes,
        )
        if not all(type(value) is int for value in values):
            raise TypeError("all XML limits must be integers")
        if min(values) <= 0:
            raise ValueError("all XML limits must be positive")


def parse_xml_document(data: bytes, limits: XmlLimits | None = None) -> etree._Element:
    """Parse untrusted XML without DTDs, entities, recovery, or network access."""

    active = limits if limits is not None else XmlLimits()
    if not isinstance(data, bytes):
        raise TypeError("XML input must be bytes")
    if len(data) > active.max_input_bytes:
        raise ResponseLimitError("XML input exceeds configured byte limit")
    if b"\x00" in data:
        raise XmlSecurityError("XML input must use a single-byte UTF-8 encoding")
    if b"<!DOCTYPE" in data:
        raise XmlSecurityError("DOCTYPE declarations are forbidden")
    target = _BoundedTreeBuilder(active)
    parser = etree.XMLParser(
        target=target,
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        dtd_validation=False,
        recover=False,
        huge_tree=False,
        strip_cdata=False,
    )
    try:
        root = etree.fromstring(data, parser)
    except (ResponseLimitError, XmlSecurityError):
        raise
    except (etree.XMLSyntaxError, ValueError) as exc:
        raise XmlSecurityError("invalid XML document") from exc
    if not isinstance(root, etree._Element):
        raise XmlSecurityError("XML document has no root element")
    return root


class _BoundedTreeBuilder:
    """Apply structural limits while lxml is still emitting parse events."""

    def __init__(self, limits: XmlLimits) -> None:
        self._limits = limits
        self._builder = etree.TreeBuilder()
        self._depth = 0
        self._elements = 0
        self._current_text = 0
        self._total_text = 0
        self._seen_ids: set[str] = set()
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
        name = etree.QName(tag)
        if name.namespace == _XINCLUDE_NAMESPACE:
            self._fail(XmlSecurityError("XInclude elements are forbidden"))
        for attribute, attribute_value in attributes.items():
            if not isinstance(attribute, str) or not isinstance(attribute_value, str):
                self._fail(XmlSecurityError("XML attributes must be text"))
            if etree.QName(attribute).localname in _ID_LOCAL_NAMES:
                if attribute_value in self._seen_ids:
                    self._fail(XmlSecurityError("duplicate XML ID detected"))
                self._seen_ids.add(attribute_value)
        self._builder.start(tag, attributes)

    def data(self, data: str | bytes) -> None:
        size = len(data if isinstance(data, bytes) else data.encode("utf-8"))
        self._current_text += size
        self._total_text += size
        if self._current_text > self._limits.max_text_bytes:
            self._fail(ResponseLimitError("XML text node exceeds configured limit"))
        if self._total_text > self._limits.max_total_text_bytes:
            self._fail(ResponseLimitError("XML text exceeds configured total limit"))
        self._builder.data(data)

    def end(self, tag: str | bytes) -> None:
        self._builder.end(tag)
        self._depth -= 1
        self._current_text = 0

    def comment(self, text: str | bytes) -> None:
        self._fail(XmlSecurityError("comments are forbidden"))

    def pi(self, target: str | bytes, data: str | bytes | None = None) -> None:
        self._fail(XmlSecurityError("processing instructions are forbidden"))

    def close(self) -> etree._Element:
        if self._failure is not None:
            raise self._failure
        return self._builder.close()

    def _fail(self, error: ResponseLimitError | XmlSecurityError) -> NoReturn:
        self._failure = error
        raise error
