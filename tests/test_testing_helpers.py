from datetime import datetime, timezone

import pytest

from ebics_read import DownloadSession, ProtocolLimits, SessionConflictError
from ebics_read.testing import (
    DeterministicNonceSource,
    FixedClock,
    InMemorySegmentStore,
    InMemorySessionStore,
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
    initial = DownloadSession.start("session", ProtocolLimits(max_segments=1))
    assert store.compare_and_swap(lease, None, initial)
    assert store.load(lease) == initial

    advanced = initial.initialize(transaction_id="transaction", total_segments=1)
    assert not store.compare_and_swap(lease, 99, advanced)
    assert store.compare_and_swap(lease, initial.revision, advanced)
    assert store.load(lease) == advanced
    assert store.delete(lease, advanced.revision)
    assert store.load(lease) is None
    store.release_lease(lease)
    with pytest.raises(SessionConflictError):
        store.load(lease)


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
