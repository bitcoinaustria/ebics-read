"""Opt-in compilation of the hash-pinned, separately supplied H005 schemas."""

# ruff: noqa: E501 -- reviewed SHA-256 values stay contiguous for auditability.

import base64
import os
import zlib
from hashlib import sha256
from pathlib import Path

import pytest
from lxml import etree

from ebics_read import Bank, NegotiatedProtocol, Subscriber
from ebics_read.transport import _PreparedTransportRequest

_OFFICIAL_SCHEMA_SHA256 = {
    "ebics_H005.xsd": "cf9d5d29fac0950f810c2a0018312fe476ab3415d804f5fc00cd4e3aa216136e",
    "ebics_keymgmt_request_H005.xsd": "7165cd441a0c68f6e93c384de743f97d0d768ac444d1adc6daf89d0e1edb0505",
    "ebics_keymgmt_response_H005.xsd": "9671ccf4282df1a4089f5d61a86378fa78e38d80292550a34422e15aa802ef3f",
    "ebics_orders_H005.xsd": "ce19f0e0b8cdfa05678a9e2123e09634f131107e08552e7a1371e6dbbf82e2f1",
    "ebics_request_H005.xsd": "48838ffd60275549849a7054223085154746b920e5f438cd16878fc62004d874",
    "ebics_response_H005.xsd": "19226688cd598581b37a7b32cb1df874c525aac710f68dbcc10e11b820eabd4d",
    "ebics_signature_S002.xsd": "6fcee44bdb80d656e05f11da86303bb25de2cf545203eef30dffbd6c662f8d93",
    "ebics_types_H005.xsd": "0c94813782e725b7698449f117a8f2e6e47d6560b3df83ca53a720d6f6fc4351",
    "xmldsig-core-schema.xsd": "43f97eddd32ca6df482ff1757cd55d784054fa36cb35d882ddc1e52669a37af6",
}


def _reviewed_schema_bundle(directory: Path) -> None:
    for name, expected_digest in _OFFICIAL_SCHEMA_SHA256.items():
        path = directory / name
        if (
            not path.is_file()
            or sha256(path.read_bytes()).hexdigest() != expected_digest
        ):
            raise ValueError(f"{name} does not match the reviewed official file")


def _official_schema_directory() -> Path:
    configured = os.environ.get("EBICS_READ_H005_XSD_DIR")
    if configured is None:
        pytest.skip(
            "set EBICS_READ_H005_XSD_DIR to the separately downloaded schema directory"
        )
    directory = Path(configured)
    if not directory.is_dir():
        pytest.fail("EBICS_READ_H005_XSD_DIR does not identify a directory")
    try:
        _reviewed_schema_bundle(directory)
    except ValueError as exc:
        pytest.fail(str(exc))
    return directory


@pytest.mark.schema
def test_external_official_h005_and_s002_schema_sets_compile() -> None:
    directory = _official_schema_directory()
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        recover=False,
        huge_tree=False,
    )

    assert etree.XMLSchema(etree.parse(directory / "ebics_H005.xsd", parser))
    assert etree.XMLSchema(etree.parse(directory / "ebics_signature_S002.xsd", parser))


@pytest.mark.schema
def test_generated_ini_matches_external_official_h005_and_s002_schemas() -> None:
    directory = _official_schema_directory()
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        recover=False,
        huge_tree=False,
    )
    request = _PreparedTransportRequest._for_ini(
        Bank("https://bank.invalid/ebics", "HOST"),
        Subscriber("PARTNER=1", "USER,1", "SYSTEM1"),
        NegotiatedProtocol(),
        b"synthetic-certificate",
    )
    outer = etree.fromstring(request.body, parser)
    request_schema = etree.XMLSchema(
        etree.parse(directory / "ebics_keymgmt_request_H005.xsd", parser)
    )
    request_schema.assertValid(outer)

    encoded = outer.findtext(".//{urn:org:ebics:H005}OrderData")
    assert encoded is not None
    inner = etree.fromstring(zlib.decompress(base64.b64decode(encoded)), parser)
    signature_schema = etree.XMLSchema(
        etree.parse(directory / "ebics_signature_S002.xsd", parser)
    )
    signature_schema.assertValid(inner)


def test_rejects_replacement_h005_schema_bundle(tmp_path: Path) -> None:
    for name in _OFFICIAL_SCHEMA_SHA256:
        (tmp_path / name).write_bytes(b"<not-the-reviewed-schema/>")

    with pytest.raises(ValueError, match="reviewed official file"):
        _reviewed_schema_bundle(tmp_path)
