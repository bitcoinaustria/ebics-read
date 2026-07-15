"""Synthetic deterministic helpers. Never use these with production secrets."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .certificates import SelfSignedH005BankCertificateProfile
from .errors import BankKeyNotTrustedError, SessionConflictError
from .models import (
    AcceptedBankKeyIdentity,
    Bank,
    BankKeyRole,
    DownloadSession,
    SegmentReference,
    SessionLease,
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
        expected: AcceptedBankKeyIdentity,
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
    """Test-only CAS store; transaction metadata remains sensitive."""

    _states: dict[str, DownloadSession] = field(
        default_factory=dict, init=False, repr=False
    )
    _leases: dict[str, SessionLease] = field(
        default_factory=dict, init=False, repr=False
    )

    def acquire_lease(
        self, session_id: str, owner_token: bytes, expires_at: datetime
    ) -> SessionLease:
        lease = SessionLease(session_id, owner_token, expires_at)
        existing = self._leases.get(session_id)
        if existing is not None and existing.owner_token != lease.owner_token:
            raise SessionConflictError("synthetic session already has an owner")
        self._leases[session_id] = lease
        return lease

    def load(self, lease: SessionLease) -> DownloadSession | None:
        self._require_lease(lease)
        return self._states.get(lease.session_id)

    def compare_and_swap(
        self,
        lease: SessionLease,
        expected_revision: int | None,
        state: DownloadSession,
    ) -> bool:
        self._require_lease(lease)
        if state.session_id != lease.session_id:
            raise SessionConflictError("state belongs to another session")
        current = self._states.get(lease.session_id)
        current_revision = None if current is None else current.revision
        if current_revision != expected_revision:
            return False
        required_revision = 0 if current is None else current.revision + 1
        if state.revision != required_revision:
            raise SessionConflictError("state revision does not advance exactly once")
        self._states[lease.session_id] = state
        return True

    def delete(self, lease: SessionLease, expected_revision: int) -> bool:
        self._require_lease(lease)
        current = self._states.get(lease.session_id)
        if current is None or current.revision != expected_revision:
            return False
        del self._states[lease.session_id]
        return True

    def release_lease(self, lease: SessionLease) -> None:
        self._require_lease(lease)
        del self._leases[lease.session_id]

    def _require_lease(self, lease: SessionLease) -> None:
        if self._leases.get(lease.session_id) != lease:
            raise SessionConflictError("synthetic session lease is not current")


@dataclass(slots=True)
class InMemorySegmentStore:
    """Test-only recoverable ciphertext spool; never production protection."""

    _segments: dict[str, dict[int, tuple[SegmentReference, bytes]]] = field(
        default_factory=dict, init=False, repr=False
    )

    def put_segment(
        self,
        lease: SessionLease,
        segment_number: int,
        chunks: Iterable[bytes],
    ) -> SegmentReference:
        if type(segment_number) is not int or segment_number <= 0:
            raise SessionConflictError("segment number must be positive")
        transaction = self._segments.setdefault(lease.session_id, {})
        if segment_number in transaction:
            raise SessionConflictError("synthetic segment already exists")
        content = b"".join(bytes(chunk) for chunk in chunks)
        reference = SegmentReference(f"segment-{segment_number}")
        transaction[segment_number] = (reference, content)
        return reference

    def iter_segment(
        self, lease: SessionLease, reference: SegmentReference
    ) -> Iterator[bytes]:
        for stored_reference, content in self._segments.get(
            lease.session_id, {}
        ).values():
            if stored_reference == reference:
                yield content
                return
        raise SessionConflictError("synthetic segment reference is unknown")

    def list_segments(
        self, lease: SessionLease
    ) -> tuple[tuple[int, SegmentReference], ...]:
        transaction = self._segments.get(lease.session_id, {})
        return tuple((number, transaction[number][0]) for number in sorted(transaction))

    def discard(self, lease: SessionLease) -> None:
        self._segments.pop(lease.session_id, None)


def generate_synthetic_bank_keys(now: datetime) -> UntrustedBankKeys:
    """Generate test-only valid bank certificates; never production credentials."""

    authentication = _synthetic_certificate(BankKeyRole.AUTHENTICATION, now)
    encryption = _synthetic_certificate(BankKeyRole.ENCRYPTION, now)
    return SelfSignedH005BankCertificateProfile().validate_pair(
        authentication, encryption, now
    )


def synthetic_out_of_band_identity(
    candidate: UntrustedBankKeys,
) -> AcceptedBankKeyIdentity:
    """Simulate an independent OOB transcription for synthetic tests only."""

    return AcceptedBankKeyIdentity.from_out_of_band(
        candidate.authentication.ebics_public_key_digest.sha256_hex,
        candidate.encryption.ebics_public_key_digest.sha256_hex,
    )


def _synthetic_certificate(role: BankKeyRole, now: datetime) -> bytes:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("synthetic certificate time must be aware")
    private_key = rsa.generate_private_key(public_exponent=65_537, key_size=2048)
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, f"Synthetic {role.value}")]
    )
    key_usage = x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=role is BankKeyRole.ENCRYPTION,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                private_key.public_key()
            ),
            critical=False,
        )
        .add_extension(key_usage, critical=True)
        .sign(private_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)
