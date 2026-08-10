"""Reference filesystem adapters for the six caller-supplied EBICS Read seams.

EBICS Read deliberately ships no keyring, database, or document store: those are
application choices and it refuses to make them for you. That leaves six
protocols a caller must implement before a real download can run. This file is a
complete, working, deliberately small implementation of all six, meant to be
read and copied rather than imported.

It is an example, not a supported module. It is not part of the distribution and
carries no compatibility promise.

Confidentiality here is filesystem permissions only: the state directory is
created ``0o700`` and every file ``0o600``. That is enough for a single-user host
and not enough for a shared one.

    # ponytail: plaintext spool and unencrypted private keys under 0700.
    # Wrap put_segment/iter_segment and the key loader in an AEAD or a KMS/HSM
    # client if the host is shared or the disk is not already encrypted.

Usage is documented in examples/README.md.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from tempfile import NamedTemporaryFile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from ebics_read import (
    AcceptedBankKeyIdentity,
    Bank,
    BankCertificateProfile,
    BankKeyNotTrustedError,
    ContentSha256,
    DocumentReference,
    DocumentStagingId,
    DownloadPhase,
    DownloadSession,
    KeyPurpose,
    ReplayError,
    RetrievalProvenance,
    SegmentReference,
    SelfSignedH005BankCertificateProfile,
    SessionConflictError,
    SessionLease,
    TransactionId,
    TrustedBankKeys,
    UntrustedBankKeys,
    ZipMemberIdentity,
)

_FILE_MODE = 0o600
_DIRECTORY_MODE = 0o700
_CHUNK_BYTES = 64 * 1024


def _directory(path: Path) -> Path:
    path.mkdir(mode=_DIRECTORY_MODE, parents=True, exist_ok=True)
    return path


def _write_atomically(path: Path, content: bytes) -> None:
    """Replace ``path`` with ``content`` or leave the previous bytes intact."""

    with NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(content)
        handle.flush()
        # Durability before the rename, so a crash never exposes a torn file.
        os.fsync(handle.fileno())
    temporary.chmod(_FILE_MODE)
    temporary.replace(path)


def _key(value: str) -> str:
    """Derive a safe filename from caller-supplied text."""

    return sha256(value.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Subscriber keys
# --------------------------------------------------------------------------- #


def generate_subscriber_keys(directory: Path, *, key_size: int = 2048) -> None:
    """Create the three independent EBICS subscriber keys and certificates.

    EBICS requires three separate key pairs: A006 signature, X002
    authentication, and E002 encryption. Reusing one key across roles is a
    protocol violation. Banks accept self-signed certificates for these roles;
    the initialization letter is what binds them to you.

    EBICS Read enforces the full self-signed subscriber profile, so a
    certificate that omits any of the following is rejected before transport:

    * X.509 v3, self-signed, RSA with SHA-256, ``rsaEncryption`` SPKI;
    * RSA 2048 to 4096 bits for signature keys, 2048 to 16384 for transport;
    * a serial no wider than 160 bits (280 for encryption);
    * validity no longer than five years;
    * a common name, at least on the encryption certificate;
    * both SubjectKeyIdentifier and AuthorityKeyIdentifier, with the authority
      key identifier equal to the subject key identifier digest;
    * ``KeyUsage`` matching the role, and no CA basic constraints.
    """

    target = _directory(directory)
    for purpose in KeyPurpose:
        private_key = rsa.generate_private_key(
            public_exponent=65_537, key_size=key_size
        )
        name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, f"EBICS {purpose.value}")]
        )
        now = datetime.now(timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365 * 2))
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    private_key.public_key()
                ),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=purpose is not KeyPurpose.ENCRYPTION,
                    content_commitment=False,
                    key_encipherment=purpose is KeyPurpose.ENCRYPTION,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(private_key, hashes.SHA256())
        )
        _write_atomically(
            target / f"{purpose.value}.key.pem",
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        _write_atomically(
            target / f"{purpose.value}.cert.der",
            certificate.public_bytes(serialization.Encoding.DER),
        )


class FileKeyProvider:
    """Loads the three subscriber keys and performs only the two EBICS operations."""

    def __init__(self, directory: Path) -> None:
        self._directory = directory

    def certificate_der(self, purpose: KeyPurpose) -> bytes:
        return (self._directory / f"{purpose.value}.cert.der").read_bytes()

    def sign_x002(self, canonical_signed_info: bytes) -> bytes:
        # EBICS Read builds and self-verifies SignedInfo; this is raw RSA only.
        return self._private_key(KeyPurpose.AUTHENTICATION).sign(
            canonical_signed_info, padding.PKCS1v15(), hashes.SHA256()
        )

    def decrypt_e002_transaction_key(self, wrapped_key: bytes) -> bytes:
        return self._private_key(KeyPurpose.ENCRYPTION).decrypt(
            wrapped_key, padding.PKCS1v15()
        )

    def _private_key(self, purpose: KeyPurpose) -> rsa.RSAPrivateKey:
        key = serialization.load_pem_private_key(
            (self._directory / f"{purpose.value}.key.pem").read_bytes(), password=None
        )
        if not isinstance(key, rsa.RSAPrivateKey):
            raise TypeError(f"{purpose.value} key is not RSA")
        return key


# --------------------------------------------------------------------------- #
# Bank key trust
# --------------------------------------------------------------------------- #


class FileBankKeyTrustStore:
    """Pins bank keys only against digests the operator transcribed out of band.

    Both the certificates and the operator-supplied digests are stored. On every
    load the certificates are re-validated and re-compared against those stored
    digests, so swapping the certificate file alone cannot promote a new key to
    trusted. The digests themselves are the trust root: protect this directory.
    """

    def __init__(
        self,
        directory: Path,
        profile: BankCertificateProfile | None = None,
    ) -> None:
        self._directory = _directory(directory)
        self._profile = (
            SelfSignedH005BankCertificateProfile() if profile is None else profile
        )

    def accept(
        self,
        bank: Bank,
        candidate: UntrustedBankKeys,
        expected: AcceptedBankKeyIdentity,
    ) -> TrustedBankKeys:
        trusted = TrustedBankKeys.accept_out_of_band(candidate, expected)
        _write_atomically(
            self._path(bank),
            json.dumps(
                {
                    "authentication_certificate": (
                        trusted.authentication.certificate_der.hex()
                    ),
                    "encryption_certificate": trusted.encryption.certificate_der.hex(),
                    "authentication_digest": expected.authentication.sha256_hex,
                    "encryption_digest": expected.encryption.sha256_hex,
                }
            ).encode("utf-8"),
        )
        return trusted

    def require_trusted(self, bank: Bank) -> TrustedBankKeys:
        path = self._path(bank)
        if not path.exists():
            raise BankKeyNotTrustedError(
                "no pinned bank keys; run HPB and accept the out-of-band digests"
            )
        stored = json.loads(path.read_text("utf-8"))
        candidate = self._profile.validate_pair(
            bytes.fromhex(stored["authentication_certificate"]),
            bytes.fromhex(stored["encryption_certificate"]),
            datetime.now(timezone.utc),
        )
        # Compare against the recorded operator digests, never against digests
        # re-derived from the same file.
        return TrustedBankKeys.accept_out_of_band(
            candidate,
            AcceptedBankKeyIdentity.from_out_of_band(
                stored["authentication_digest"], stored["encryption_digest"]
            ),
        )

    def _path(self, bank: Bank) -> Path:
        return self._directory / f"{_key(bank.host_id)}.json"


# --------------------------------------------------------------------------- #
# Resumable session state
# --------------------------------------------------------------------------- #


class FileSessionStore:
    """Lease-guarded, compare-and-swap session state with durable replay claims."""

    def __init__(self, directory: Path) -> None:
        root = _directory(directory)
        self._states = _directory(root / "states")
        self._leases = _directory(root / "leases")
        self._claims = _directory(root / "claims")

    # -- leases ------------------------------------------------------------- #

    def acquire_lease(
        self, session_id: str, owner_token: bytes, expires_at: datetime
    ) -> SessionLease:
        lease = SessionLease(session_id, owner_token, expires_at)
        path = self._leases / _key(session_id)
        digest = sha256(lease.owner_token).hexdigest()
        while True:
            try:
                with path.open("x", encoding="utf-8") as handle:
                    handle.write(
                        json.dumps(
                            {"owner": digest, "expires_at": expires_at.isoformat()}
                        )
                    )
                path.chmod(_FILE_MODE)
                return lease
            except FileExistsError:
                held = json.loads(path.read_text("utf-8"))
                if held["owner"] == digest:
                    return lease
                if datetime.fromisoformat(held["expires_at"]) > datetime.now(
                    timezone.utc
                ):
                    raise SessionConflictError(
                        "another worker holds this download session"
                    ) from None
                # The holder's deadline passed, so its work can no longer
                # progress; break the lease and retry.
                path.unlink(missing_ok=True)

    def release_lease(self, lease: SessionLease) -> None:
        self._require_lease(lease)
        (self._leases / _key(lease.session_id)).unlink(missing_ok=True)

    def _require_lease(self, lease: SessionLease) -> None:
        path = self._leases / _key(lease.session_id)
        if not path.exists():
            raise SessionConflictError("download session lease is not current")
        held = json.loads(path.read_text("utf-8"))
        if held["owner"] != sha256(lease.owner_token).hexdigest():
            raise SessionConflictError("download session lease is not current")

    # -- state -------------------------------------------------------------- #

    def load(self, lease: SessionLease) -> DownloadSession | None:
        self._require_lease(lease)
        return self._load(lease)

    def compare_and_swap(
        self,
        lease: SessionLease,
        expected_revision: int | None,
        state: DownloadSession,
    ) -> bool:
        self._require_lease(lease)
        if state.session_id != lease.session_id:
            raise SessionConflictError("state belongs to another session")
        current = self._load(lease)
        if current is not None and state.request_identity != current.request_identity:
            raise SessionConflictError(
                "generic state update cannot change the download request identity"
            )
        if state.transaction_id != (
            None if current is None else current.transaction_id
        ):
            raise SessionConflictError(
                "generic state update cannot change the bank transaction ID"
            )
        if (None if current is None else current.revision) != expected_revision:
            return False
        if state.revision != (0 if current is None else current.revision + 1):
            raise SessionConflictError("state revision does not advance exactly once")
        if current is None:
            if state.phase is not DownloadPhase.NEW:
                raise SessionConflictError("first persisted state must be new")
        elif not state.is_exact_successor_of(current):
            raise SessionConflictError("state is not the exact next transition")
        self._store(lease, state)
        return True

    def initialize_transaction(
        self,
        lease: SessionLease,
        expected_revision: int,
        state: DownloadSession,
    ) -> bool:
        self._require_lease(lease)
        if (
            state.session_id != lease.session_id
            or state.phase is not DownloadPhase.INITIALIZED
            or state.transaction_id is None
            or state.total_segments is None
        ):
            raise SessionConflictError("state is not a transaction initialization")
        current = self._load(lease)
        if current is None or current.revision != expected_revision:
            return False
        if state != current.initialize(
            transaction_id=state.transaction_id,
            total_segments=state.total_segments,
        ):
            raise SessionConflictError(
                "state is not the exact initialization transition"
            )
        # Claim first: a crash between the claim and the write must still reject
        # a replay of this transaction ID.
        self.claim_transaction_id(state.transaction_id)
        self._store(lease, state)
        return True

    def claim_transaction_id(self, transaction_id: TransactionId) -> None:
        if not isinstance(transaction_id, TransactionId):
            raise TypeError("transaction_id must be a TransactionId")
        path = self._claims / _key(transaction_id.value)
        try:
            path.touch(mode=_FILE_MODE, exist_ok=False)
        except FileExistsError:
            raise ReplayError("bank transaction ID was already claimed") from None

    def delete(self, lease: SessionLease, expected_revision: int) -> bool:
        self._require_lease(lease)
        current = self._load(lease)
        if current is None or current.revision != expected_revision:
            return False
        # The claim in self._claims deliberately outlives the state.
        (self._states / _key(lease.session_id)).unlink(missing_ok=True)
        return True

    def _load(self, lease: SessionLease) -> DownloadSession | None:
        path = self._states / _key(lease.session_id)
        if not path.exists():
            return None
        return DownloadSession.from_mapping(json.loads(path.read_text("utf-8")))

    def _store(self, lease: SessionLease, state: DownloadSession) -> None:
        _write_atomically(
            self._states / _key(lease.session_id),
            json.dumps(state.to_mapping()).encode("utf-8"),
        )


# --------------------------------------------------------------------------- #
# Segment spool
# --------------------------------------------------------------------------- #


class FileSegmentStore:
    """Append-only spool of encrypted bank responses for one transaction."""

    def __init__(self, directory: Path) -> None:
        self._directory = _directory(directory)

    def put_segment(
        self,
        lease: SessionLease,
        segment_number: int,
        chunks: Iterable[bytes],
    ) -> SegmentReference:
        if type(segment_number) is not int or segment_number <= 0:
            raise SessionConflictError("segment number must be positive")
        path = self._segment(lease, segment_number)
        if path.exists():
            raise SessionConflictError("segment already exists")
        _directory(path.parent)
        _write_atomically(path, b"".join(bytes(chunk) for chunk in chunks))
        return SegmentReference(f"segment-{segment_number}")

    def iter_segment(
        self, lease: SessionLease, reference: SegmentReference
    ) -> Iterator[bytes]:
        for number, stored in self.list_segments(lease):
            if stored == reference:
                with self._segment(lease, number).open("rb") as handle:
                    while chunk := handle.read(_CHUNK_BYTES):
                        yield chunk
                return
        raise SessionConflictError("segment reference is unknown")

    def list_segments(
        self, lease: SessionLease
    ) -> tuple[tuple[int, SegmentReference], ...]:
        directory = self._directory / _key(lease.session_id)
        if not directory.exists():
            return ()
        numbers = sorted(int(path.name) for path in directory.iterdir())
        return tuple(
            (number, SegmentReference(f"segment-{number}")) for number in numbers
        )

    def discard(self, lease: SessionLease) -> None:
        directory = self._directory / _key(lease.session_id)
        if not directory.exists():
            return
        for path in directory.iterdir():
            path.unlink(missing_ok=True)
        directory.rmdir()

    def _segment(self, lease: SessionLease, number: int) -> Path:
        return self._directory / _key(lease.session_id) / str(number)


# --------------------------------------------------------------------------- #
# Document delivery
# --------------------------------------------------------------------------- #


class FileDocumentWriter:
    """One restartable staging write; partial output never becomes a document."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._digest = sha256()
        self._size = 0
        self._handle = path.open("wb")
        path.chmod(_FILE_MODE)

    def write(self, chunk: bytes) -> None:
        self._handle.write(chunk)
        self._digest.update(chunk)
        self._size += len(chunk)

    def stage(
        self,
        content_sha256: ContentSha256,
        size_bytes: int,
        zip_members: tuple[ZipMemberIdentity, ...],
    ) -> None:
        self._handle.close()
        # Independently re-check what was actually written to this disk.
        if self._size != size_bytes or (
            self._digest.hexdigest().upper() != content_sha256.sha256_hex
        ):
            self._path.unlink(missing_ok=True)
            raise SessionConflictError("staged document does not match its identity")

    def abort(self) -> None:
        self._handle.close()
        self._path.unlink(missing_ok=True)


class FileDocumentSink:
    """Stages plaintext unpublished, then publishes with an atomic rename."""

    def __init__(self, staging: Path, published: Path) -> None:
        self._staging = _directory(staging)
        self._published = _directory(published)

    def begin(
        self, staging_id: DocumentStagingId, provenance: RetrievalProvenance
    ) -> FileDocumentWriter:
        return FileDocumentWriter(self._stage_path(staging_id))

    def publish(self, staging_id: DocumentStagingId) -> DocumentReference:
        name = f"{staging_id.sha256_hex}.bin"
        target = self._published / name
        stage = self._stage_path(staging_id)
        if stage.exists():
            stage.replace(target)
        elif not target.exists():
            raise SessionConflictError("no staged document to publish")
        # Idempotent: a repeated publish of an already-renamed stage is a no-op.
        return DocumentReference(name)

    def discard(self, staging_id: DocumentStagingId) -> None:
        self._stage_path(staging_id).unlink(missing_ok=True)

    def _stage_path(self, staging_id: DocumentStagingId) -> Path:
        return self._staging / f"{staging_id.sha256_hex}.part"
