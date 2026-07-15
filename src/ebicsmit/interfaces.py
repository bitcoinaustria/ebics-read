"""Injected boundaries for keys, trust, state, time, and randomness."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Protocol

from .models import (
    Bank,
    BankKeyFingerprints,
    DownloadSession,
    TrustedBankKeys,
    UntrustedBankKeys,
)


class KeyPurpose(str, Enum):
    """The three independent EBICS subscriber key roles."""

    SIGNATURE = "signature"
    AUTHENTICATION = "authentication"
    ENCRYPTION = "encryption"


class KeyProvider(Protocol):
    """Caller-controlled private-key boundary with fixed EBICS operations."""

    def certificate_der(self, purpose: KeyPurpose) -> bytes:
        """Return the H005 X.509 certificate for one subscriber key role."""

    def sign_a006(self, message: bytes) -> bytes:
        """Produce the exact EBICS A006 signature for order data."""

    def sign_x002(self, canonical_signed_info: bytes) -> bytes:
        """Produce the exact EBICS X002 AuthSignature value."""

    def decrypt_e002_transaction_key(self, wrapped_key: bytes) -> bytes:
        """Unwrap an E002 transaction key using normative RSA PKCS#1 v1.5."""


class BankKeyTrustStore(Protocol):
    """Explicit out-of-band bank-key pinning boundary."""

    def accept(
        self,
        bank: Bank,
        candidate: UntrustedBankKeys,
        expected: BankKeyFingerprints,
    ) -> TrustedBankKeys:
        """Accept only when caller-supplied OOB fingerprints match the candidate."""

    def require_trusted(self, bank: Bank) -> TrustedBankKeys:
        """Return pinned keys or fail closed."""


class Clock(Protocol):
    """UTC-aware time source."""

    def now(self) -> datetime:
        """Return the current timezone-aware instant."""


class NonceSource(Protocol):
    """CSPRNG boundary; production implementations must be unpredictable."""

    def random_bytes(self, length: int) -> bytes:
        """Return exactly ``length`` fresh random bytes."""


class SessionStore(Protocol):
    """Caller-controlled storage for non-secret resumable transaction state."""

    def load(self, session_id: str) -> DownloadSession | None:
        """Load state without logging its identifiers."""

    def save(self, state: DownloadSession) -> None:
        """Atomically replace one immutable state value."""

    def delete(self, session_id: str) -> None:
        """Remove completed or invalidated state."""
