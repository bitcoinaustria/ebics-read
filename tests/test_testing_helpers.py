from datetime import datetime, timezone

import pytest

from ebicsmit import DownloadSession
from ebicsmit.testing import (
    DeterministicNonceSource,
    FixedClock,
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
    initial = DownloadSession.start("session")
    store.save(initial)
    assert store.load("session") == initial

    advanced = initial.initialize(transaction_id="transaction", total_segments=1)
    store.save(advanced)
    assert store.load("session") == advanced
    store.delete("session")
    assert store.load("session") is None
