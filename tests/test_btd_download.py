from __future__ import annotations

from dataclasses import dataclass, field, replace
from io import BytesIO
from random import Random
from zipfile import ZIP_STORED, ZipFile

import pytest
from lxml import etree
from test_btd import _Control, _descriptor
from test_haa import _setup, _Transport

from ebics_read import (
    AmbiguousTransportError,
    Bank,
    ContainerType,
    ContentSha256,
    DeadlineControl,
    DocumentReference,
    DocumentStagingId,
    DownloadOptions,
    DownloadPhase,
    DownloadSession,
    NegotiatedProtocol,
    OperationCancelledError,
    OperationNotImplementedError,
    RetrievalProvenance,
    SecurityError,
    SessionLease,
    Subscriber,
    TransactionId,
    TransportResponse,
    ZipMemberIdentity,
)
from ebics_read.testing import InMemorySegmentStore, InMemorySessionStore
from ebics_read.transport import _PreparedTransportRequest

_H005 = "urn:org:ebics:H005"


@dataclass
class _ReceiptAwareTransport:
    inner: _Transport
    ambiguous_receipt: bool = False
    calls: int = 0
    receipt_returned: bool = False

    def exchange(
        self, request: _PreparedTransportRequest, control: object
    ) -> TransportResponse:
        self.calls += 1
        root = etree.fromstring(request.body)
        phase = root.findtext(f".//{{{_H005}}}TransactionPhase")
        if phase == "Receipt" and self.ambiguous_receipt:
            self.inner.requests.append(request)
            raise AmbiguousTransportError("synthetic ambiguous receipt")
        response = self.inner.exchange(request, control)
        if phase == "Receipt":
            self.receipt_returned = True
        return response


@dataclass
class _Writer:
    sink: _Sink
    staging_id: DocumentStagingId
    provenance: RetrievalProvenance
    content: bytearray = field(default_factory=bytearray)

    def write(self, chunk: bytes) -> None:
        self.content.extend(chunk)
        if self.sink.cancel_on_write and self.sink.cancel_control is not None:
            self.sink.cancel_on_write = False
            self.sink.cancel_control.cancel()

    def stage(
        self,
        content_sha256: ContentSha256,
        size_bytes: int,
        zip_members: tuple[ZipMemberIdentity, ...],
    ) -> None:
        if self.sink.fail_stage_once:
            self.sink.fail_stage_once = False
            raise RuntimeError("synthetic stage failure")
        content = bytes(self.content)
        assert ContentSha256.from_bytes(content) == content_sha256
        assert len(content) == size_bytes
        self.sink.stages[self.staging_id] = (
            content,
            self.provenance,
            content_sha256,
            zip_members,
        )
        if self.sink.cancel_after_stage and self.sink.cancel_control is not None:
            self.sink.cancel_after_stage = False
            self.sink.cancel_control.cancel()

    def abort(self) -> None:
        self.content.clear()


@dataclass
class _Sink:
    transport: _ReceiptAwareTransport
    fail_stage_once: bool = False
    fail_publish_once: bool = False
    cancel_control: DeadlineControl | None = None
    cancel_after_stage: bool = False
    cancel_on_write: bool = False
    stages: dict[
        DocumentStagingId,
        tuple[
            bytes,
            RetrievalProvenance,
            ContentSha256,
            tuple[ZipMemberIdentity, ...],
        ],
    ] = field(default_factory=dict)
    published: dict[DocumentStagingId, bytes] = field(default_factory=dict)

    def begin(
        self, staging_id: DocumentStagingId, provenance: RetrievalProvenance
    ) -> _Writer:
        self.stages.pop(staging_id, None)
        return _Writer(self, staging_id, provenance)

    def publish(self, staging_id: DocumentStagingId) -> DocumentReference:
        assert self.transport.receipt_returned
        if self.fail_publish_once:
            self.fail_publish_once = False
            raise RuntimeError("synthetic publish failure")
        content = self.stages[staging_id][0]
        self.published[staging_id] = content
        return DocumentReference(f"document-{len(self.published)}")

    def discard(self, staging_id: DocumentStagingId) -> None:
        self.stages.pop(staging_id, None)


@dataclass
class _CrashAfterReceiptIntentStore:
    inner: InMemorySessionStore
    crashed: bool = False

    def acquire_lease(
        self, session_id: str, owner_token: bytes, expires_at: object
    ) -> SessionLease:
        return self.inner.acquire_lease(session_id, owner_token, expires_at)  # type: ignore[arg-type]

    def load(self, lease: SessionLease) -> DownloadSession | None:
        return self.inner.load(lease)

    def compare_and_swap(
        self,
        lease: SessionLease,
        expected_revision: int | None,
        state: DownloadSession,
    ) -> bool:
        result = self.inner.compare_and_swap(lease, expected_revision, state)
        if not self.crashed and state.phase is DownloadPhase.RECEIPT_PENDING:
            self.crashed = True
            raise RuntimeError("synthetic crash after receipt intent")
        return result

    def initialize_transaction(
        self,
        lease: SessionLease,
        expected_revision: int,
        state: DownloadSession,
    ) -> bool:
        return self.inner.initialize_transaction(lease, expected_revision, state)

    def claim_transaction_id(self, transaction_id: TransactionId) -> None:
        self.inner.claim_transaction_id(transaction_id)

    def delete(self, lease: SessionLease, expected_revision: int) -> bool:
        return self.inner.delete(lease, expected_revision)

    def release_lease(self, lease: SessionLease) -> None:
        self.inner.release_lease(lease)


def _download(
    backend: object,
    trusted: object,
    sink: _Sink,
    container_type: ContainerType = ContainerType.NONE,
    control: object | None = None,
):  # type: ignore[no-untyped-def]
    return backend.download(  # type: ignore[attr-defined,no-any-return]
        Bank("https://bank.invalid/ebics", "HOST"),
        Subscriber("PARTNER=1", "USER,1", "SYSTEM1"),
        NegotiatedProtocol(),
        trusted,
        "btd-session",
        _descriptor(container_type),
        DownloadOptions(),
        sink,
        _Control() if control is None else control,
    )


def _prepared_backend(order_data: bytes):  # type: ignore[no-untyped-def]
    backend, transport, trusted = _setup(order_data=order_data)
    aware = _ReceiptAwareTransport(transport)
    spool = InMemorySegmentStore()
    return (
        replace(backend, transport=aware, segment_store=spool),
        aware,
        trusted,
        spool,
    )


def test_btd_download_stages_receipts_publishes_and_resumes_complete() -> None:
    backend, transport, trusted, spool = _prepared_backend(b"synthetic document")
    sink = _Sink(transport)

    documents = _download(backend, trusted, sink)

    assert len(documents) == 1
    assert tuple(sink.published.values()) == (b"synthetic document",)
    phases = [
        etree.fromstring(request.body).findtext(f".//{{{_H005}}}TransactionPhase")
        for request in transport.inner.requests
    ]
    assert phases == ["Initialisation", "Transfer", "Receipt"]
    assert (
        etree.fromstring(transport.inner.requests[-1].body).findtext(
            f".//{{{_H005}}}ReceiptCode"
        )
        == "0"
    )
    assert _download(backend, trusted, sink) == documents
    assert transport.calls == 3
    lease = SessionLease("btd-session", b"0123456789abcdef", _Control.deadline)
    assert spool.list_segments(lease) == ()


def test_btd_download_extracts_zip_members_as_separate_documents() -> None:
    output = BytesIO()
    with ZipFile(output, "w", ZIP_STORED) as archive:
        archive.writestr("first.xml", b"first")
        archive.writestr("second.xml", b"second")
    backend, transport, trusted, _ = _prepared_backend(output.getvalue())
    sink = _Sink(transport)

    documents = _download(backend, trusted, sink, ContainerType.ZIP)

    assert tuple(sink.published.values()) == (b"first", b"second")
    assert [document.zip_members[0].index for document in documents] == [0, 1]


def test_btd_processing_failure_sends_negative_receipt_without_publication() -> None:
    backend, transport, trusted, spool = _prepared_backend(b"")
    sink = _Sink(transport)

    with pytest.raises(SecurityError, match="payload is empty"):
        _download(backend, trusted, sink)

    assert not sink.published
    receipt = etree.fromstring(transport.inner.requests[-1].body)
    assert receipt.findtext(f".//{{{_H005}}}ReceiptCode") == "1"
    lease = SessionLease("btd-session", b"0123456789abcdef", _Control.deadline)
    assert spool.list_segments(lease) == ()


def test_btd_publish_failure_resumes_without_repeating_receipt() -> None:
    backend, transport, trusted, _ = _prepared_backend(b"synthetic document")
    sink = _Sink(transport, fail_publish_once=True)

    with pytest.raises(RuntimeError, match="publish failure"):
        _download(backend, trusted, sink)
    calls = transport.calls

    assert len(_download(backend, trusted, sink)) == 1
    assert transport.calls == calls


def test_btd_receipt_ambiguity_is_durable_and_never_retried() -> None:
    backend, transport, trusted, _ = _prepared_backend(b"synthetic document")
    transport.ambiguous_receipt = True
    sink = _Sink(transport)

    with pytest.raises(AmbiguousTransportError):
        _download(backend, trusted, sink)
    calls = transport.calls
    with pytest.raises(AmbiguousTransportError):
        _download(backend, trusted, sink)

    assert transport.calls == calls
    assert not sink.published


def test_btd_crash_after_receipt_intent_becomes_ambiguous_without_send() -> None:
    backend, transport, trusted, _ = _prepared_backend(b"synthetic document")
    backend = replace(
        backend,
        session_store=_CrashAfterReceiptIntentStore(InMemorySessionStore()),
    )
    sink = _Sink(transport)

    with pytest.raises(RuntimeError, match="receipt intent"):
        _download(backend, trusted, sink)
    calls = transport.calls
    with pytest.raises(AmbiguousTransportError):
        _download(backend, trusted, sink)

    assert transport.calls == calls == 2
    assert not sink.published


def test_btd_cancellation_before_receipt_keeps_staged_state_resumable() -> None:
    backend, transport, trusted, _ = _prepared_backend(b"synthetic document")
    control = DeadlineControl(_Control.deadline)
    sink = _Sink(transport, cancel_control=control, cancel_after_stage=True)

    with pytest.raises(OperationCancelledError):
        _download(backend, trusted, sink, control=control)
    assert transport.calls == 2

    documents = _download(
        backend, trusted, sink, control=DeadlineControl(_Control.deadline)
    )
    assert len(documents) == 1
    assert transport.calls == 3


def test_btd_mid_staging_cancellation_sends_no_negative_receipt() -> None:
    payload = Random(0).randbytes(70_000)
    backend, transport, trusted, _ = _prepared_backend(payload)
    control = DeadlineControl(_Control.deadline)
    sink = _Sink(transport, cancel_control=control, cancel_on_write=True)

    with pytest.raises(OperationCancelledError):
        _download(backend, trusted, sink, control=control)
    assert transport.calls == 2
    assert not sink.stages

    documents = _download(
        backend, trusted, sink, control=DeadlineControl(_Control.deadline)
    )
    assert len(documents) == 1
    assert transport.calls == 3


def test_btd_sink_stage_failure_completes_negative_receipt() -> None:
    backend, transport, trusted, _ = _prepared_backend(b"synthetic document")
    sink = _Sink(transport, fail_stage_once=True)

    with pytest.raises(RuntimeError, match="stage failure"):
        _download(backend, trusted, sink)

    assert not sink.stages
    assert not sink.published
    receipt = etree.fromstring(transport.inner.requests[-1].body)
    assert receipt.findtext(f".//{{{_H005}}}ReceiptCode") == "1"


def test_btd_unknown_container_framing_fails_before_network_io() -> None:
    backend, transport, trusted, _ = _prepared_backend(b"synthetic document")
    sink = _Sink(transport)

    with pytest.raises(OperationNotImplementedError, match="public specification"):
        _download(backend, trusted, sink, ContainerType.XML)

    assert transport.calls == 0
