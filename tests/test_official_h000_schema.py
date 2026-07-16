"""Opt-in validation against the unmodified, separately supplied H000 XSD."""

import os
from hashlib import sha256
from pathlib import Path

import pytest
from lxml import etree

from ebics_read import Bank
from ebics_read.transport import _PreparedTransportRequest

_H000 = "http://www.ebics.org/H000"
_OFFICIAL_H000_SHA256 = (
    "0f529a5220181ef8d99876daddafecd70a53717a2826ff13581147d769ec5056"
)


def _reviewed_schema_bytes(path: Path) -> bytes:
    schema_bytes = path.read_bytes()
    if sha256(schema_bytes).hexdigest() != _OFFICIAL_H000_SHA256:
        raise ValueError("schema does not match the reviewed official file")
    return schema_bytes


def _official_schema() -> etree.XMLSchema:
    configured = os.environ.get("EBICS_READ_H000_XSD")
    if configured is None:
        pytest.skip("set EBICS_READ_H000_XSD to a separately downloaded official XSD")
    path = Path(configured)
    if not path.is_file():
        pytest.fail("EBICS_READ_H000_XSD does not identify a file")
    try:
        schema_bytes = _reviewed_schema_bytes(path)
    except ValueError as exc:
        pytest.fail(str(exc))
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        recover=False,
        huge_tree=False,
    )
    return etree.XMLSchema(etree.fromstring(schema_bytes, parser))


@pytest.mark.schema
def test_hev_request_and_response_match_external_official_h000_xsd() -> None:
    schema = _official_schema()
    request = _PreparedTransportRequest._for_hev(
        Bank("https://bank.invalid/ebics", "HOST")
    )
    response = (
        b'<ebics:ebicsHEVResponse xmlns:ebics="http://www.ebics.org/H000">'
        b"<ebics:SystemReturnCode><ebics:ReturnCode>000000</ebics:ReturnCode>"
        b"<ebics:ReportText>EBICS_OK</ebics:ReportText></ebics:SystemReturnCode>"
        b'<ebics:VersionNumber ProtocolVersion="H005">03.00</ebics:VersionNumber>'
        b"</ebics:ebicsHEVResponse>"
    )
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)

    assert schema.validate(etree.fromstring(request.body, parser))
    assert schema.validate(etree.fromstring(response, parser))
    assert etree.QName(etree.fromstring(request.body).tag).namespace == _H000


def test_rejects_replacement_xsd_without_reviewed_digest(tmp_path: Path) -> None:
    replacement = tmp_path / "ebics_hev.xsd"
    replacement.write_bytes(b"<not-the-reviewed-schema/>")

    with pytest.raises(ValueError, match="reviewed official file"):
        _reviewed_schema_bytes(replacement)
