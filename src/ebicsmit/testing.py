"""Synthetic deterministic helpers. Never use these with production secrets."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .errors import BankKeyNotTrustedError
from .models import (
    Bank,
    BankKeyFingerprints,
    DownloadSession,
    TrustedBankKeys,
    UntrustedBankKeys,
)


def _bank_key(bank: Bank) -> tuple[str, str]:
    return (bank.endpoint, bank.host_id)


@dataclass(slots=True)
class InMemoryBankKeyTrustStore:
    """Test-only pin store; production persistence belongs to the host."""

    _trusted: dict[tuple[str, str], TrustedBankKeys] = field(
        default_factory=dict, init=False, repr=False
    )

    def accept(
        self,
        bank: Bank,
        candidate: UntrustedBankKeys,
        expected: BankKeyFingerprints,
    ) -> TrustedBankKeys:
        trusted = TrustedBankKeys.accept_out_of_band(candidate, expected)
        self._trusted[_bank_key(bank)] = trusted
        return trusted

    def require_trusted(self, bank: Bank) -> TrustedBankKeys:
        try:
            return self._trusted[_bank_key(bank)]
        except KeyError as exc:
            raise BankKeyNotTrustedError(
                "bank keys require explicit out-of-band acceptance"
            ) from exc


@dataclass(frozen=True, slots=True)
class FixedClock:
    """Test-only deterministic clock."""

    value: datetime

    def now(self) -> datetime:
        if self.value.tzinfo is None or self.value.utcoffset() is None:
            raise ValueError("fixed clock value must be timezone-aware")
        return self.value


@dataclass(slots=True)
class DeterministicNonceSource:
    """Test-only byte stream; predictable and never suitable for production."""

    seed: bytes = field(repr=False)
    _offset: int = field(default=0, init=False, repr=False)

    def random_bytes(self, length: int) -> bytes:
        if length <= 0:
            raise ValueError("length must be positive")
        if not self.seed:
            raise ValueError("deterministic seed must not be empty")
        result = bytes(
            self.seed[(self._offset + index) % len(self.seed)]
            for index in range(length)
        )
        self._offset += length
        return result


@dataclass(slots=True)
class InMemorySessionStore:
    """Test-only non-secret session store."""

    _states: dict[str, DownloadSession] = field(
        default_factory=dict, init=False, repr=False
    )

    def load(self, session_id: str) -> DownloadSession | None:
        return self._states.get(session_id)

    def save(self, state: DownloadSession) -> None:
        self._states[state.session_id] = state

    def delete(self, session_id: str) -> None:
        self._states.pop(session_id, None)
