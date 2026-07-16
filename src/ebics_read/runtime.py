"""Safe production defaults for time, randomness, deadlines, and cancellation."""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from math import isfinite
from threading import Event

from .errors import ConfigurationError, OperationCancelledError
from .interfaces import Clock


@dataclass(frozen=True, slots=True)
class SystemClock:
    """UTC-aware system clock."""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class SecureNonceSource:
    """Operating-system CSPRNG-backed nonce source."""

    def random_bytes(self, length: int) -> bytes:
        if type(length) is not int:
            raise TypeError("nonce length must be an integer")
        if length <= 0:
            raise ValueError("nonce length must be positive")
        return secrets.token_bytes(length)


@dataclass(frozen=True, slots=True)
class DeadlineControl:
    """Thread-safe absolute deadline with explicit cooperative cancellation."""

    deadline: datetime
    _cancelled: Event = field(
        default_factory=Event, init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        if not isinstance(self.deadline, datetime):
            raise TypeError("deadline must be a datetime")
        if self.deadline.tzinfo is None or self.deadline.utcoffset() is None:
            raise ConfigurationError("deadline must be timezone-aware")

    @classmethod
    def after(
        cls, timeout_seconds: float, clock: Clock | None = None
    ) -> DeadlineControl:
        """Create a deadline relative to an injected or system clock."""

        if isinstance(timeout_seconds, bool) or not isinstance(
            timeout_seconds, (int, float)
        ):
            raise TypeError("timeout_seconds must be a finite number")
        if not isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be finite and positive")
        active_clock = clock if clock is not None else SystemClock()
        now = active_clock.now()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ConfigurationError("clock must return a timezone-aware instant")
        return cls(now + timedelta(seconds=float(timeout_seconds)))

    def cancel(self) -> None:
        """Request cancellation; blocking I/O observes it at its next check."""

        self._cancelled.set()

    def raise_if_cancelled(self) -> None:
        if self._cancelled.is_set():
            raise OperationCancelledError("operation was cancelled")
