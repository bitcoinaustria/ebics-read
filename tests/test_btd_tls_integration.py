from __future__ import annotations

import ssl
import threading
from dataclasses import dataclass, field, replace
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

from cryptography.hazmat.primitives.asymmetric import rsa
from lxml import etree
from test_btd import _descriptor
from test_haa import _response, _setup
from test_hev_integration import _write_local_tls_identity

from ebics_read import (
    Bank,
    ContainerType,
    ContentSha256,
    DeadlineControl,
    DocumentReference,
    DocumentStagingId,
    DownloadOptions,
    HttpsTransport,
    NegotiatedProtocol,
    RetrievalProvenance,
    Subscriber,
    SystemClock,
    ZipMemberIdentity,
)
from ebics_read.testing import InMemorySegmentStore

_H005 = "urn:org:ebics:H005"
_TRANSACTION_ID = "00112233445566778899AABBCCDDEEFF"


class _SyntheticBtdHandler(BaseHTTPRequestHandler):
    bank_key: ClassVar[rsa.RSAPrivateKey]
    encryption_der: ClassVar[bytes]
    fragments: ClassVar[tuple[str, ...]]
    phases: ClassVar[list[str]] = []

    def do_POST(self) -> None:
        length = int(self.headers["Content-Length"])
        root = etree.fromstring(self.rfile.read(length))
        phase = root.findtext(f".//{{{_H005}}}TransactionPhase")
        if phase is None:
            self.send_error(400)
            return
        type(self).phases.append(phase)
        if phase == "Initialisation":
            response = _response(
                self.bank_key,
                phase,
                transaction_id=_TRANSACTION_ID,
                total_segments=len(self.fragments),
                segment_number=1,
                fragment=self.fragments[0],
                encryption_der=self.encryption_der,
            )
        elif phase == "Transfer":
            segment = int(root.findtext(f".//{{{_H005}}}SegmentNumber") or "0")
            response = _response(
                self.bank_key,
                phase,
                transaction_id=_TRANSACTION_ID,
                total_segments=len(self.fragments),
                segment_number=segment,
                fragment=self.fragments[segment - 1],
            )
        elif phase == "Receipt":
            receipt = root.findtext(f".//{{{_H005}}}ReceiptCode")
            response = _response(
                self.bank_key,
                phase,
                transaction_id=_TRANSACTION_ID,
                technical="011000" if receipt == "0" else "011001",
            )
        else:
            self.send_error(400)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/xml; charset=utf-8")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format_: str, *args: object) -> None:
        return None


@dataclass
class _TlsWriter:
    sink: _TlsSink
    staging_id: DocumentStagingId
    provenance: RetrievalProvenance
    content: bytearray = field(default_factory=bytearray)

    def write(self, chunk: bytes) -> None:
        self.content.extend(chunk)

    def stage(
        self,
        content_sha256: ContentSha256,
        size_bytes: int,
        zip_members: tuple[ZipMemberIdentity, ...],
    ) -> None:
        content = bytes(self.content)
        assert ContentSha256.from_bytes(content) == content_sha256
        assert len(content) == size_bytes
        self.sink.staged[self.staging_id] = (
            content,
            self.provenance,
            content_sha256,
            size_bytes,
            zip_members,
        )

    def abort(self) -> None:
        self.content.clear()


@dataclass
class _TlsSink:
    staged: dict[
        DocumentStagingId,
        tuple[
            bytes,
            RetrievalProvenance,
            ContentSha256,
            int,
            tuple[ZipMemberIdentity, ...],
        ],
    ] = field(default_factory=dict)
    published: dict[DocumentStagingId, bytes] = field(default_factory=dict)

    def begin(
        self, staging_id: DocumentStagingId, provenance: RetrievalProvenance
    ) -> _TlsWriter:
        self.staged.pop(staging_id, None)
        return _TlsWriter(self, staging_id, provenance)

    def publish(self, staging_id: DocumentStagingId) -> DocumentReference:
        self.published[staging_id] = self.staged[staging_id][0]
        return DocumentReference("synthetic-local-tls-document")

    def discard(self, staging_id: DocumentStagingId) -> None:
        self.staged.pop(staging_id, None)


def test_complete_btd_exchange_over_verified_local_tls(
    tmp_path: Path, monkeypatch
) -> None:
    ca_path, certificate_path, key_path = _write_local_tls_identity(tmp_path)
    monkeypatch.setenv("SSL_CERT_FILE", str(ca_path))
    fixture_backend, fixture_transport, trusted = _setup(
        order_data=b"synthetic local TLS BTD document"
    )
    _SyntheticBtdHandler.bank_key = fixture_transport.bank_key
    _SyntheticBtdHandler.encryption_der = fixture_transport.encryption_der
    _SyntheticBtdHandler.fragments = fixture_transport.fragments
    _SyntheticBtdHandler.phases = []
    server = HTTPServer(("127.0.0.1", 0), _SyntheticBtdHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        system_clock = SystemClock()
        backend = replace(
            fixture_backend,
            transport=HttpsTransport(clock=system_clock),
            segment_store=InMemorySegmentStore(),
        )
        sink = _TlsSink()
        documents = backend.download(
            Bank(f"https://127.0.0.1:{server.server_port}/ebics", "HOST"),
            Subscriber("PARTNER=1", "USER,1", "SYSTEM1"),
            NegotiatedProtocol(),
            trusted,
            "synthetic-tls-btd",
            _descriptor(ContainerType.NONE),
            DownloadOptions(),
            sink,
            DeadlineControl.after(10, system_clock),
        )

        assert len(documents) == 1
        assert tuple(sink.published.values()) == (b"synthetic local TLS BTD document",)
        assert _SyntheticBtdHandler.phases == [
            "Initialisation",
            "Transfer",
            "Receipt",
        ]
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
