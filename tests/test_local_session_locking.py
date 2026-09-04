from __future__ import annotations

import multiprocessing
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ebics_read import SessionConflictError, SessionLease

sys.path.insert(0, str(Path(__file__).parents[1] / "examples"))
from local_provider import FileSessionStore


def _acquire_in_process(directory: str, ready: object, finish: object) -> None:
    store = FileSessionStore(Path(directory))
    store.acquire_lease(
        "session", b"a" * 32, datetime.now(timezone.utc) + timedelta(minutes=2)
    )
    ready.set()  # type: ignore[attr-defined]
    finish.wait(20)  # type: ignore[attr-defined]
    # Intentionally exit without release: the OS, not metadata expiry, unlocks.


def test_kernel_lock_survives_metadata_expiry_and_releases_after_process_exit(
    tmp_path: Path,
) -> None:
    context = multiprocessing.get_context("spawn")
    ready, finish = context.Event(), context.Event()
    process = context.Process(
        target=_acquire_in_process, args=(str(tmp_path), ready, finish)
    )
    process.start()
    try:
        assert ready.wait(10)
        # Persisted lease JSON is informational; corrupt/stale metadata must not
        # permit stealing a running worker's kernel lock.
        for path in (tmp_path / "leases").iterdir():
            path.write_text("{}", encoding="utf-8")
        store = FileSessionStore(tmp_path)
        with pytest.raises(SessionConflictError, match="another worker"):
            store.acquire_lease(
                "session", b"b" * 32, datetime.now(timezone.utc) + timedelta(minutes=1)
            )
    finally:
        finish.set()
        process.join(10)
        if process.is_alive():
            process.terminate()
            process.join(5)
    assert process.exitcode == 0
    recovered = FileSessionStore(tmp_path)
    lease = recovered.acquire_lease(
        "session", b"b" * 32, datetime.now(timezone.utc) + timedelta(minutes=1)
    )
    assert recovered.load(lease) is None
    recovered.release_lease(lease)
    assert list((tmp_path / "leases").iterdir()) == []
    assert len(list((tmp_path / "locks").iterdir())) == 1


def test_separate_adapters_cannot_reuse_the_same_owner_token(tmp_path: Path) -> None:
    first, second = FileSessionStore(tmp_path), FileSessionStore(tmp_path)
    expires = datetime.now(timezone.utc) + timedelta(minutes=1)
    lease = first.acquire_lease("session", b"a" * 32, expires)
    try:
        with pytest.raises(SessionConflictError, match="another worker"):
            second.acquire_lease("session", b"a" * 32, expires)
        with pytest.raises(SessionConflictError, match="not current"):
            second.load(lease)
        assert first.acquire_lease("session", b"a" * 32, expires) == lease
    finally:
        first.release_lease(lease)


def test_expired_lease_cannot_load_or_extend_but_can_release(tmp_path: Path) -> None:
    store = FileSessionStore(tmp_path)
    lease = store.acquire_lease(
        "session", b"a" * 32, datetime.now(timezone.utc) + timedelta(minutes=1)
    )
    # Model passage of time without sleeping or relying on timing thresholds.
    expired = SessionLease(
        lease.session_id, lease.owner_token, datetime.now(timezone.utc) - timedelta(1)
    )
    held = store._held[lease.session_id]
    store._held[lease.session_id] = (expired, held[1])
    try:
        with pytest.raises(SessionConflictError, match="expired"):
            store.load(expired)
        with pytest.raises(SessionConflictError, match="another worker"):
            store.acquire_lease(
                "session", b"a" * 32, datetime.now(timezone.utc) + timedelta(minutes=2)
            )
        with pytest.raises(SessionConflictError, match="expired"):
            store.acquire_lease("other-session", b"b" * 32, expired.expires_at)
    finally:
        store.release_lease(expired)


def test_compare_and_swap_is_atomic_between_threads_sharing_one_lease(
    tmp_path: Path,
) -> None:
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from time import sleep

    from ebics_read import DownloadRequestIdentity, DownloadSession, ProtocolLimits

    class SlowReadStore(FileSessionStore):
        def _load(self, lease: SessionLease) -> DownloadSession | None:
            current = super()._load(lease)
            # Widen the vulnerable read/write gap so competing calls observe
            # the same revision if only the individual file writes are atomic.
            sleep(0.02)
            return current

    store = SlowReadStore(tmp_path)
    lease = store.acquire_lease(
        "session", b"a" * 32, datetime.now(timezone.utc) + timedelta(minutes=1)
    )
    state = DownloadSession.start(
        "session", DownloadRequestIdentity("A" * 64), ProtocolLimits()
    )
    ready = Barrier(4)

    def save() -> bool:
        ready.wait(timeout=5)
        return store.compare_and_swap(lease, None, state)

    try:
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = [
                future.result() for future in [executor.submit(save) for _ in range(4)]
            ]
        assert results.count(True) == 1
        assert store.load(lease) == state
    finally:
        store.release_lease(lease)
