"""Injected boundaries for keys, trust, state, time, and randomness."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from datetime import datetime
from enum import Enum
from typing import Protocol

from .models import (
    AcceptedBankKeyIdentity,
    Bank,
    ContentSha256,
    DownloadedDocument,
    DownloadSession,
    RetrievalProvenance,
    SegmentReference,
    SessionLease,
    TrustedBankKeys,
    UntrustedBankKeys,
    ZipMemberIdentity,
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
        expected: AcceptedBankKeyIdentity,
    ) -> TrustedBankKeys:
        """Accept only when caller-supplied OOB EBICS digests match the candidate."""

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
    """Atomic caller storage for sensitive resumable transaction metadata."""

    def acquire_lease(
        self, session_id: str, owner_token: bytes, expires_at: datetime
    ) -> SessionLease:
        """Acquire exclusive ownership or fail if another live worker holds it."""

    def load(self, lease: SessionLease) -> DownloadSession | None:
        """Load state only for the current lease owner."""

    def compare_and_swap(
        self,
        lease: SessionLease,
        expected_revision: int | None,
        state: DownloadSession,
    ) -> bool:
        """Atomically store only when ownership and revision still match."""

    def delete(self, lease: SessionLease, expected_revision: int) -> bool:
        """Atomically remove completed or invalidated state."""

    def release_lease(self, lease: SessionLease) -> None:
        """Release ownership without exposing its token."""


class SegmentStore(Protocol):
    """Caller-controlled encrypted or equivalently protected ciphertext spool."""

    def put_segment(
        self,
        lease: SessionLease,
        segment_number: int,
        chunks: Iterable[bytes],
    ) -> SegmentReference:
        """Atomically store one bounded ciphertext segment from streamed chunks."""

    def iter_segment(
        self, lease: SessionLease, reference: SegmentReference
    ) -> Iterator[bytes]:
        """Stream one stored segment without materializing the transaction."""

    def list_segments(
        self, lease: SessionLease
    ) -> tuple[tuple[int, SegmentReference], ...]:
        """Recover the ordered number/reference index after process restart."""

    def discard(self, lease: SessionLease) -> None:
        """Remove every partial segment for a terminal transaction."""


class DocumentWriter(Protocol):
    """One atomic sink transaction; partial output is never a document."""

    def write(self, chunk: bytes) -> None:
        """Append one bounded verified plaintext chunk."""

    def commit(
        self,
        content_sha256: ContentSha256,
        size_bytes: int,
        zip_members: tuple[ZipMemberIdentity, ...],
    ) -> DownloadedDocument:
        """Atomically publish the document and return its small result record."""

    def abort(self) -> None:
        """Discard partial plaintext."""


class DocumentSink(Protocol):
    """Caller-controlled destination for streaming verified plaintext."""

    def begin(self, provenance: RetrievalProvenance) -> DocumentWriter:
        """Start an unpublished atomic document transaction."""


class OperationControl(Protocol):
    """Caller-owned whole-operation deadline and cancellation boundary."""

    @property
    def deadline(self) -> datetime:
        """Return the absolute timezone-aware deadline."""

    def raise_if_cancelled(self) -> None:
        """Raise a caller-selected cancellation exception when requested."""


class BankCertificateProfile(Protocol):
    """Strict profile validation kept separate from OOB key acceptance."""

    def validate_pair(
        self,
        authentication_certificate_der: bytes,
        encryption_certificate_der: bytes,
        now: datetime,
    ) -> UntrustedBankKeys:
        """Return unusable candidates only after DER and profile validation."""
