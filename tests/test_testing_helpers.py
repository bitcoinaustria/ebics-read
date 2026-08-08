from datetime import datetime, timezone

import pytest

from ebics_read import (
    BtfDescriptor,
    ContainerType,
    ContentSha256,
    DocumentReference,
    DocumentStagingId,
    DownloadedDocument,
    DownloadPhase,
    DownloadRequestIdentity,
    DownloadSession,
    NegotiatedProtocol,
    ProtocolLimits,
    ReplayError,
    RetrievalProvenance,
    SessionConflictError,
    StagedDocument,
    TransactionId,
)
from ebics_read.testing import (
    DeterministicNonceSource,
    FixedClock,
    InMemorySegmentStore,
    InMemorySessionStore,
)

_TRANSACTION_ID = TransactionId("0123456789ABCDEF0123456789ABCDEF")
_OTHER_TRANSACTION_ID = TransactionId("FEDCBA9876543210FEDCBA9876543210")
_REQUEST_IDENTITY = DownloadRequestIdentity("C" * 64)
_OTHER_REQUEST_IDENTITY = DownloadRequestIdentity("D" * 64)


def _document_pair() -> tuple[StagedDocument, DownloadedDocument]:
    descriptor = BtfDescriptor(
        "EOP", "camt.053", "08", "001", "XML", "STM", ContainerType.NONE
    )
    provenance = RetrievalProvenance(
        descriptor,
        NegotiatedProtocol(),
        datetime(2026, 8, 8, tzinfo=timezone.utc),
        ContentSha256.from_bytes(bytes.fromhex(_TRANSACTION_ID.value)),
        1,
        "HOST",
    )
    staging_id = DocumentStagingId.derive(_REQUEST_IDENTITY, _TRANSACTION_ID, 1)
    metadata = {
        "staging_id": staging_id,
        "provenance": provenance,
        "content_sha256": ContentSha256.from_bytes(b"document"),
        "size_bytes": 8,
    }
    return (
        StagedDocument(**metadata),
        DownloadedDocument(**metadata, sink_reference=DocumentReference("document-1")),
    )


def test_fixed_clock_requires_aware_time() -> None:
    aware = datetime(2026, 7, 15, tzinfo=timezone.utc)
    assert FixedClock(aware).now() == aware
    with pytest.raises(ValueError):
        FixedClock(datetime(2026, 7, 15)).now()  # noqa: DTZ001 - intentional


def test_deterministic_nonce_source_is_explicitly_predictable() -> None:
    source = DeterministicNonceSource(b"ab")
    assert source.random_bytes(3) == b"aba"
    assert source.random_bytes(3) == b"bab"
    with pytest.raises(ValueError):
        source.random_bytes(0)


def test_in_memory_session_store_replaces_immutable_state() -> None:
    store = InMemorySessionStore()
    lease = store.acquire_lease(
        "session", b"0123456789abcdef", datetime(2026, 7, 16, tzinfo=timezone.utc)
    )
    initial = DownloadSession.start(
        "session", _REQUEST_IDENTITY, ProtocolLimits(max_segments=1)
    )
    assert store.compare_and_swap(lease, None, initial)
    assert store.load(lease) == initial

    advanced = initial.initialize(transaction_id=_TRANSACTION_ID, total_segments=1)
    with pytest.raises(SessionConflictError, match="cannot change"):
        store.compare_and_swap(lease, initial.revision, advanced)
    assert not store.initialize_transaction(lease, 99, advanced)
    forged_limits = DownloadSession.restore(
        session_id="session",
        request_identity=_REQUEST_IDENTITY,
        phase=advanced.phase,
        transaction_id=_TRANSACTION_ID,
        next_segment=1,
        total_segments=1,
        max_segments=2,
        revision=1,
    )
    with pytest.raises(SessionConflictError, match="exact initialization"):
        store.initialize_transaction(lease, initial.revision, forged_limits)
    assert store.initialize_transaction(lease, initial.revision, advanced)
    assert store.load(lease) == advanced
    swapped_transaction = DownloadSession.restore(
        session_id="session",
        request_identity=_REQUEST_IDENTITY,
        phase=advanced.phase,
        transaction_id=_OTHER_TRANSACTION_ID,
        next_segment=1,
        total_segments=1,
        max_segments=1,
        revision=2,
    )
    with pytest.raises(SessionConflictError, match="cannot change"):
        store.compare_and_swap(lease, advanced.revision, swapped_transaction)
    swapped_request = DownloadSession.restore(
        session_id="session",
        request_identity=_OTHER_REQUEST_IDENTITY,
        phase=advanced.phase,
        transaction_id=_TRANSACTION_ID,
        next_segment=1,
        total_segments=1,
        max_segments=1,
        revision=2,
    )
    with pytest.raises(SessionConflictError, match="request identity"):
        store.compare_and_swap(lease, advanced.revision, swapped_request)

    forged_jump = DownloadSession.restore(
        session_id="session",
        request_identity=_REQUEST_IDENTITY,
        phase=DownloadPhase.SIGNATURES_AND_DIGESTS_VERIFIED,
        transaction_id=_TRANSACTION_ID,
        next_segment=2,
        total_segments=1,
        max_segments=1,
        revision=2,
    )
    with pytest.raises(SessionConflictError, match="exact next"):
        store.compare_and_swap(lease, advanced.revision, forged_jump)

    staged, published = _document_pair()
    current = advanced
    transitions = (
        lambda state: state.record_segment(1),
        lambda state: state.mark_signatures_and_digests_verified(),
        lambda state: state.mark_decrypted(),
        lambda state: state.mark_container_verified(),
        lambda state: state.mark_documents_staged((staged,)),
        lambda state: state.mark_positive_receipt_pending(),
        lambda state: state.mark_receipt_ambiguous(),
        lambda state: state.mark_receipt_response_verified(),
        lambda state: state.mark_documents_published((published,)),
        lambda state: state.finish(),
    )
    for transition in transitions:
        next_state = transition(current)
        assert store.compare_and_swap(lease, current.revision, next_state)
        current = next_state
    assert store.delete(lease, current.revision)
    assert store.load(lease) is None
    store.release_lease(lease)
    with pytest.raises(SessionConflictError):
        store.load(lease)

    replay_lease = store.acquire_lease(
        "other-session",
        b"fedcba9876543210",
        datetime(2026, 7, 16, tzinfo=timezone.utc),
    )
    replay_initial = DownloadSession.start(
        "other-session", _REQUEST_IDENTITY, ProtocolLimits(max_segments=1)
    )
    assert store.compare_and_swap(replay_lease, None, replay_initial)
    replayed = replay_initial.initialize(
        transaction_id=_TRANSACTION_ID, total_segments=1
    )
    with pytest.raises(ReplayError):
        store.initialize_transaction(replay_lease, replay_initial.revision, replayed)


def test_in_memory_segment_store_recovers_number_reference_index() -> None:
    lease = InMemorySessionStore().acquire_lease(
        "session", b"0123456789abcdef", datetime(2026, 7, 16, tzinfo=timezone.utc)
    )
    store = InMemorySegmentStore()
    first = store.put_segment(lease, 1, (b"cipher", b"text-1"))
    second = store.put_segment(lease, 2, (b"ciphertext-2",))
    assert store.list_segments(lease) == ((1, first), (2, second))
    assert b"".join(store.iter_segment(lease, first)) == b"ciphertext-1"
    store.discard(lease)
    assert store.list_segments(lease) == ()
