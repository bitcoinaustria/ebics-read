"""Proves examples/local_provider.py really satisfies all six caller seams.

Unlike the in-memory helpers in ``ebics_read.testing``, these adapters persist to
disk, so this is also the only test that reconstructs session state across
process-like boundaries and that unwraps a genuinely RSA-encrypted E002
transaction key.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from test_btd import _descriptor
from test_haa import _TRANSACTION_KEY, _certificate, _fragments, _Transport

from ebics_read import (
    Bank,
    BankKeyMismatchError,
    BankKeyNotTrustedError,
    ContainerType,
    ContentSha256,
    DeadlineControl,
    DocumentReference,
    DocumentStagingId,
    DownloadRequestIdentity,
    EbicsBackend,
    KeyPurpose,
    NegotiatedProtocol,
    ProtocolLimits,
    ReadOnlyClient,
    ReplayError,
    RetrievalProvenance,
    SecureNonceSource,
    SelfSignedH005BankCertificateProfile,
    Subscriber,
    SystemClock,
    TransactionId,
)
from ebics_read.models import BankKeyRole
from ebics_read.testing import synthetic_out_of_band_identity

sys.path.insert(0, str(Path(__file__).parents[1] / "examples"))

from local_provider import (
    FileBankKeyTrustStore,
    FileDocumentSink,
    FileKeyProvider,
    FileSegmentStore,
    FileSessionStore,
    generate_subscriber_keys,
)

_DOCUMENT = b"synthetic camt.053 document delivered through file-backed adapters"
_BANK = Bank("https://bank.invalid/ebics", "HOST")
_SUBSCRIBER = Subscriber("PARTNER=1", "USER,1", "SYSTEM1")


@dataclass(frozen=True)
class _Deployment:
    """One host: its state directory plus the bank identity it has pinned."""

    root: Path
    bank_key: rsa.RSAPrivateKey
    authentication_der: bytes
    encryption_der: bytes

    def wired(self) -> tuple[ReadOnlyClient, _Transport, FileDocumentSink]:
        """Build fresh adapters over the same directories, as a restart does."""

        provider = FileKeyProvider(self.root / "keys")
        subscriber_encryption_der = provider.certificate_der(KeyPurpose.ENCRYPTION)
        # A real PKCS#1 v1.5 wrap, so FileKeyProvider must genuinely decrypt it.
        encryption_key = x509.load_der_x509_certificate(
            subscriber_encryption_der
        ).public_key()
        wrapped_key = encryption_key.encrypt(  # type: ignore[union-attr]
            _TRANSACTION_KEY, padding.PKCS1v15()
        )
        transport = _Transport(
            self.bank_key,
            subscriber_encryption_der,
            _fragments(order_data=_DOCUMENT),
            wrapped_key=wrapped_key,
        )
        backend = EbicsBackend(
            transport,  # type: ignore[arg-type]
            key_provider=provider,
            clock=SystemClock(),
            nonce_source=SecureNonceSource(),
            session_store=FileSessionStore(self.root / "sessions"),
            segment_store=FileSegmentStore(self.root / "spool"),
            protocol_limits=ProtocolLimits(),
        )
        client = ReadOnlyClient(
            _BANK, _SUBSCRIBER, backend, FileBankKeyTrustStore(self.root / "trust")
        )
        return (
            client,
            transport,
            FileDocumentSink(self.root / "staging", self.root / "documents"),
        )


@pytest.fixture
def prepared(tmp_path: Path) -> _Deployment:
    """Generated subscriber keys plus bank keys pinned out of band, post-HPB."""

    generate_subscriber_keys(tmp_path / "keys")
    bank_key, authentication_der = _certificate(BankKeyRole.AUTHENTICATION)
    _, encryption_der = _certificate(BankKeyRole.ENCRYPTION)
    deployment = _Deployment(tmp_path, bank_key, authentication_der, encryption_der)
    candidate = SelfSignedH005BankCertificateProfile().validate_pair(
        authentication_der, encryption_der, datetime.now(timezone.utc)
    )
    client, _, _ = deployment.wired()
    client.accept_bank_keys(candidate, synthetic_out_of_band_identity(candidate))
    return deployment


def test_file_adapters_complete_a_download_and_publish_to_disk(
    prepared: _Deployment,
) -> None:
    client, transport, sink = prepared.wired()

    documents = client.download(
        "local-session",
        _descriptor(ContainerType.NONE),
        sink,
        DeadlineControl.after(30, SystemClock()),
        protocol=NegotiatedProtocol(),
    )

    assert len(documents) == 1
    assert documents[0].content_sha256 == ContentSha256.from_bytes(_DOCUMENT)
    published = prepared.root / "documents" / documents[0].sink_reference.value
    assert published.read_bytes() == _DOCUMENT
    # Nothing is left staged, spooled or leased once the transaction completes.
    assert list((prepared.root / "staging").iterdir()) == []
    assert list((prepared.root / "spool").iterdir()) == []
    assert list((prepared.root / "sessions" / "leases").iterdir()) == []
    assert len(transport.requests) == 3


def test_completed_session_state_is_read_back_from_disk_after_a_restart(
    prepared: _Deployment,
) -> None:
    client, transport, sink = prepared.wired()
    documents = client.download(
        "local-session",
        _descriptor(ContainerType.NONE),
        sink,
        DeadlineControl.after(30, SystemClock()),
        protocol=NegotiatedProtocol(),
    )
    assert len(transport.requests) == 3

    # Entirely new adapter and backend objects over the same directories.
    restarted, restarted_transport, restarted_sink = prepared.wired()
    repeated = restarted.download(
        "local-session",
        _descriptor(ContainerType.NONE),
        restarted_sink,
        DeadlineControl.after(30, SystemClock()),
        protocol=NegotiatedProtocol(),
    )

    assert repeated == documents
    # The completed state came off disk; the bank was never contacted again.
    assert restarted_transport.requests == []


def test_file_session_store_rejects_a_concurrent_worker(
    prepared: _Deployment,
) -> None:
    store = FileSessionStore(prepared.root / "sessions")
    deadline = DeadlineControl.after(30, SystemClock()).deadline
    store.acquire_lease("local-session", b"\x01" * 32, deadline)

    with pytest.raises(Exception, match="another worker"):
        store.acquire_lease("local-session", b"\x02" * 32, deadline)

    # The same owner re-acquires idempotently, as a retry in one process would.
    assert store.acquire_lease("local-session", b"\x01" * 32, deadline)


def test_file_session_store_claims_transaction_ids_durably(
    prepared: _Deployment,
) -> None:
    transaction_id = TransactionId("0123456789ABCDEF0123456789ABCDEF")
    sessions = prepared.root / "sessions"
    FileSessionStore(sessions).claim_transaction_id(transaction_id)

    # A fresh store instance must still reject the replay.
    with pytest.raises(ReplayError, match="already claimed"):
        FileSessionStore(sessions).claim_transaction_id(transaction_id)


def test_file_trust_store_fails_closed_before_pinning_and_on_a_swapped_certificate(
    tmp_path: Path,
) -> None:
    store = FileBankKeyTrustStore(tmp_path / "trust")

    with pytest.raises(BankKeyNotTrustedError, match="out-of-band"):
        store.require_trusted(_BANK)

    _, bank_authentication = _certificate(BankKeyRole.AUTHENTICATION)
    _, bank_encryption = _certificate(BankKeyRole.ENCRYPTION)
    candidate = SelfSignedH005BankCertificateProfile().validate_pair(
        bank_authentication, bank_encryption, datetime.now(timezone.utc)
    )
    store.accept(_BANK, candidate, synthetic_out_of_band_identity(candidate))
    assert store.require_trusted(_BANK).authentication.certificate_der == (
        bank_authentication
    )

    # Swapping the stored certificate without its recorded digest must not pin.
    _, other_authentication = _certificate(BankKeyRole.AUTHENTICATION)
    path = next((tmp_path / "trust").iterdir())
    tampered = path.read_text("utf-8").replace(
        bank_authentication.hex(), other_authentication.hex()
    )
    path.write_text(tampered, encoding="utf-8")
    with pytest.raises(BankKeyMismatchError, match="do not match OOB"):
        store.require_trusted(_BANK)


def test_file_document_sink_never_publishes_a_mismatched_stage(tmp_path: Path) -> None:
    sink = FileDocumentSink(tmp_path / "staging", tmp_path / "documents")
    staging_id, provenance = _staging_identity()

    writer = sink.begin(staging_id, provenance)
    writer.write(b"partial")
    with pytest.raises(Exception, match="does not match its identity"):
        writer.stage(ContentSha256.from_bytes(b"different"), 7, ())
    # A failed stage leaves nothing to publish.
    with pytest.raises(Exception, match="no staged document"):
        sink.publish(staging_id)


def _staging_identity() -> tuple[DocumentStagingId, RetrievalProvenance]:
    request_identity = DownloadRequestIdentity("C" * 64)
    transaction_id = TransactionId("0123456789ABCDEF0123456789ABCDEF")
    provenance = RetrievalProvenance(
        _descriptor(ContainerType.NONE),
        NegotiatedProtocol(),
        datetime.now(timezone.utc),
        ContentSha256.from_bytes(bytes.fromhex(transaction_id.value)),
        1,
        "HOST",
    )
    return (
        DocumentStagingId.derive(request_identity, transaction_id, 1),
        provenance,
    )


def test_file_segment_store_streams_back_what_it_spooled(
    prepared: _Deployment,
) -> None:
    store = FileSegmentStore(prepared.root / "spool")
    lease = FileSessionStore(prepared.root / "sessions").acquire_lease(
        "spool-session", b"\x03" * 32, DeadlineControl.after(30, SystemClock()).deadline
    )

    first = store.put_segment(lease, 1, [b"alpha", b"beta"])
    second = store.put_segment(lease, 2, [b"gamma"])

    assert store.list_segments(lease) == ((1, first), (2, second))
    assert b"".join(store.iter_segment(lease, first)) == b"alphabeta"
    assert b"".join(store.iter_segment(lease, second)) == b"gamma"
    with pytest.raises(Exception, match="already exists"):
        store.put_segment(lease, 1, [b"again"])

    store.discard(lease)
    assert store.list_segments(lease) == ()


def test_generated_subscriber_keys_are_three_distinct_roles(tmp_path: Path) -> None:
    generate_subscriber_keys(tmp_path / "keys")
    provider = FileKeyProvider(tmp_path / "keys")

    certificates = {
        purpose: provider.certificate_der(purpose) for purpose in KeyPurpose
    }
    assert len(set(certificates.values())) == 3
    for purpose, der in certificates.items():
        certificate = x509.load_der_x509_certificate(der)
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        assert usage.key_encipherment is (purpose is KeyPurpose.ENCRYPTION)
        assert usage.digital_signature is (purpose is not KeyPurpose.ENCRYPTION)
    # Private key files must not be group- or world-readable.
    for path in (tmp_path / "keys").glob("*.key.pem"):
        assert path.stat().st_mode & 0o077 == 0

    signed = b"synthetic canonical SignedInfo"
    public_key = x509.load_der_x509_certificate(
        certificates[KeyPurpose.AUTHENTICATION]
    ).public_key()
    # Raises InvalidSignature if the provider signed with the wrong key or scheme.
    public_key.verify(  # type: ignore[union-attr]
        provider.sign_x002(signed), signed, padding.PKCS1v15(), hashes.SHA256()
    )


def test_reference_adapters_stay_outside_the_distribution() -> None:
    import ebics_read

    assert not hasattr(ebics_read, "FileSessionStore")
    assert "local_provider" not in dir(ebics_read)


class _FailOncePublishSink(FileDocumentSink):
    """A sink that dies exactly once, standing in for a crash before publication."""

    def __init__(self, staging: Path, published: Path) -> None:
        super().__init__(staging, published)
        self.failed = False

    def publish(self, staging_id: DocumentStagingId) -> DocumentReference:
        if not self.failed:
            self.failed = True
            raise RuntimeError("synthetic crash before publication")
        return super().publish(staging_id)


def test_interrupted_publication_resumes_from_disk_without_repeating_the_receipt(
    prepared: _Deployment,
) -> None:
    client, transport, _ = prepared.wired()
    crashing = _FailOncePublishSink(
        prepared.root / "staging", prepared.root / "documents"
    )
    control = DeadlineControl.after(30, SystemClock())

    with pytest.raises(RuntimeError, match="synthetic crash"):
        client.download(
            "local-session",
            _descriptor(ContainerType.NONE),
            crashing,
            control,
            protocol=NegotiatedProtocol(),
        )
    # Initialisation, Transfer and the positive Receipt were all already sent.
    assert len(transport.requests) == 3
    assert list((prepared.root / "documents").iterdir()) == []

    # A wholly new process: fresh stores, fresh backend, same directories.
    restarted, restarted_transport, restarted_sink = prepared.wired()
    documents = restarted.download(
        "local-session",
        _descriptor(ContainerType.NONE),
        restarted_sink,
        DeadlineControl.after(30, SystemClock()),
        protocol=NegotiatedProtocol(),
    )

    assert len(documents) == 1
    published = prepared.root / "documents" / documents[0].sink_reference.value
    assert published.read_bytes() == _DOCUMENT
    # The receipt is never re-sent: the bank would reject a second one.
    assert restarted_transport.requests == []
    assert list((prepared.root / "sessions" / "leases").iterdir()) == []
