from datetime import datetime, timezone

import pytest

from ebics_read import (
    ConfigurationError,
    DeadlineControl,
    OperationCancelledError,
    SecureNonceSource,
    SystemClock,
)
from ebics_read.testing import FixedClock


def test_system_clock_and_secure_nonce_source_are_safe_defaults() -> None:
    now = SystemClock().now()
    assert now.tzinfo is not None and now.utcoffset() is not None

    source = SecureNonceSource()
    first = source.random_bytes(32)
    second = source.random_bytes(32)
    assert len(first) == len(second) == 32
    assert first != second
    with pytest.raises((TypeError, ValueError)):
        source.random_bytes(0)


def test_deadline_control_supports_relative_deadlines_and_cancellation() -> None:
    now = datetime(2026, 7, 15, tzinfo=timezone.utc)
    control = DeadlineControl.after(5, FixedClock(now))
    assert (control.deadline - now).total_seconds() == 5
    control.raise_if_cancelled()

    control.cancel()
    with pytest.raises(OperationCancelledError):
        control.raise_if_cancelled()

    with pytest.raises(ConfigurationError):
        DeadlineControl(now.replace(tzinfo=None))
    with pytest.raises(ValueError):
        DeadlineControl.after(float("inf"), FixedClock(now))
