from __future__ import annotations

from io import BytesIO
from stat import S_IFLNK
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile, ZipInfo

import pytest
from test_haa import _TRANSACTION_KEY, _fragments

from ebics_read import (
    ContainerType,
    ContentSha256,
    OperationNotImplementedError,
    ProtocolLimits,
    ResponseLimitError,
    SecurityError,
    XmlSecurityError,
)
from ebics_read.btd import _decode_btd_payload, _extract_btd_documents


def _zip(*members: tuple[str, bytes], compression: int = ZIP_STORED) -> bytes:
    output = BytesIO()
    with ZipFile(output, "w", compression) as archive:
        for name, content in members:
            archive.writestr(name, content)
    return output.getvalue()


def test_btd_decodes_one_strict_bounded_payload() -> None:
    payload = b"synthetic BTD document"

    assert (
        _decode_btd_payload(
            _fragments(order_data=payload), _TRANSACTION_KEY, ProtocolLimits()
        )
        == payload
    )
    with pytest.raises(XmlSecurityError, match="strict base64"):
        _decode_btd_payload(("!",), _TRANSACTION_KEY, ProtocolLimits())
    with pytest.raises(ResponseLimitError, match="compression-ratio"):
        _decode_btd_payload(
            _fragments(order_data=b"x" * 10_000),
            _TRANSACTION_KEY,
            ProtocolLimits(max_compression_ratio=2),
        )
    with pytest.raises(ResponseLimitError, match="encoded order data"):
        _decode_btd_payload(
            ("A" * 20, "A" * 20),
            _TRANSACTION_KEY,
            ProtocolLimits(max_compressed_bytes=1),
        )


def test_btd_none_container_is_one_document() -> None:
    payload = b"synthetic raw document"

    assert _extract_btd_documents(payload, ContainerType.NONE, ProtocolLimits()) == (
        (payload, ()),
    )


def test_btd_zip_extracts_only_bounded_content_and_hashed_names() -> None:
    payload = _zip(
        ("statements/", b""),
        ("statements/first.xml", b"first"),
        ("statements/second.xml", b"second"),
    )

    documents = _extract_btd_documents(payload, ContainerType.ZIP, ProtocolLimits())

    assert tuple(content for content, _ in documents) == (b"first", b"second")
    first = documents[0][1][0]
    assert first.index == 1
    assert first.name_sha256 == ContentSha256.from_bytes(b"statements/first.xml")
    assert first.content_sha256 == ContentSha256.from_bytes(b"first")


@pytest.mark.parametrize("name", ("../secret", "/absolute", "C:/drive", "a\\b"))
def test_btd_zip_rejects_unsafe_paths(name: str) -> None:
    with pytest.raises(SecurityError, match="path"):
        _extract_btd_documents(
            _zip((name, b"content")), ContainerType.ZIP, ProtocolLimits()
        )


def test_btd_zip_rejects_symlinks_nested_archives_and_bombs() -> None:
    output = BytesIO()
    link = ZipInfo("link")
    link.create_system = 3
    link.external_attr = (S_IFLNK | 0o777) << 16
    with ZipFile(output, "w") as archive:
        archive.writestr(link, b"target")
    with pytest.raises(SecurityError, match="symbolic"):
        _extract_btd_documents(output.getvalue(), ContainerType.ZIP, ProtocolLimits())

    nested = _zip(("inner.zip", _zip(("document", b"content"))))
    with pytest.raises(SecurityError, match="nested"):
        _extract_btd_documents(nested, ContainerType.ZIP, ProtocolLimits())

    bomb = _zip(("document", b"x" * 10_000), compression=ZIP_DEFLATED)
    with pytest.raises(ResponseLimitError, match="member"):
        _extract_btd_documents(
            bomb,
            ContainerType.ZIP,
            ProtocolLimits(max_compression_ratio=2),
        )


def test_btd_zip_validates_directory_entries_before_skipping_them() -> None:
    output = BytesIO()
    link = ZipInfo("link/")
    link.create_system = 3
    link.external_attr = (S_IFLNK | 0o777) << 16
    with ZipFile(output, "w") as archive:
        archive.writestr(link, b"")
        archive.writestr("document", b"content")
    with pytest.raises(SecurityError, match="symbolic"):
        _extract_btd_documents(
            output.getvalue(), ContainerType.ZIP, ProtocolLimits()
        )

    hidden = _zip(("hidden/", b"secret"), ("document", b"content"))
    with pytest.raises(SecurityError, match="directory entry"):
        _extract_btd_documents(hidden, ContainerType.ZIP, ProtocolLimits())

    encrypted = bytearray(_zip(("encrypted/", b""), ("document", b"content")))
    local = encrypted.index(b"PK\x03\x04")
    central = encrypted.index(b"PK\x01\x02")
    encrypted[local + 6] |= 1
    encrypted[central + 8] |= 1
    with pytest.raises(SecurityError, match="encrypted"):
        _extract_btd_documents(bytes(encrypted), ContainerType.ZIP, ProtocolLimits())


def test_btd_zip_rejects_member_count_and_unknown_container_framing() -> None:
    with pytest.raises(ResponseLimitError, match="member count"):
        _extract_btd_documents(
            _zip(("one", b"1"), ("two", b"2")),
            ContainerType.ZIP,
            ProtocolLimits(max_zip_members=1),
        )
    for container_type in (ContainerType.XML, ContainerType.SVC):
        with pytest.raises(OperationNotImplementedError, match="public specification"):
            _extract_btd_documents(b"synthetic", container_type, ProtocolLimits())
