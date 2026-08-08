"""Immutable, typed values accepted or returned by the public API."""

from __future__ import annotations

import hmac
import re
from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum
from hashlib import sha256
from urllib.parse import urlsplit

from .errors import (
    BankKeyMismatchError,
    ConfigurationError,
    UnsupportedProtocolVersionError,
)
from .orders import DISCOVERY_ORDERS, OrderType

_PROTOCOL_FIELD_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,63}$")
_H005_SUBSCRIBER_ID = re.compile(r"^[A-Za-z0-9,=]{1,35}$")
_IBAN = re.compile(r"^[A-Z]{2}[0-9A-Z]{13,32}$")
_CURRENCY = re.compile(r"^[A-Z]{3}$")
_SHA256_HEX = re.compile(r"^[0-9A-F]{64}$")
_PROTOCOL_VERSION = re.compile(r"^H[0-9]{3}$")
_VERSION_NUMBER = re.compile(r"^[0-9]{2}\.[0-9]{2}$")
_AUTHENTICATION_VERSION = re.compile(r"^X[0-9]{3}$")
_ENCRYPTION_VERSION = re.compile(r"^E[0-9]{3}$")
_SIGNATURE_VERSION = re.compile(r"^A[0-9]{3}$")
_BTF_SERVICE_NAME = re.compile(r"^[A-Z0-9]{3}$")
_BTF_MESSAGE_NAME = re.compile(r"^[a-z.0-9]{1,10}$")
_BTF_SCOPE = re.compile(r"^[A-Z0-9]{2,3}$")
_BTF_SERVICE_OPTION = re.compile(r"^[A-Z0-9]{3,10}$")
_BTF_NUMBER = re.compile(r"^[0-9]{2,3}$")
_BTF_FORMAT = re.compile(r"^[A-Z0-9]{1,4}$")
_TRUST_CREATION_TOKEN = object()
_OOB_IDENTITY_TOKEN = object()
_SESSION_CREATION_TOKEN = object()
_CERTIFICATE_VALIDATION_TOKEN = object()


def _require_token(name: str, value: str, *, optional: bool = False) -> str:
    if optional and value == "":
        return value
    if not isinstance(value, str) or _PROTOCOL_FIELD_PATTERN.fullmatch(value) is None:
        raise ConfigurationError(f"{name} must be a bounded protocol token")
    return value


def _require_identifier(name: str, value: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ConfigurationError(f"{name} must be a bounded identifier")
    return value


def _require_xml_token(name: str, value: str, max_length: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > max_length
        or value != " ".join(value.split())
    ):
        raise ConfigurationError(f"{name} must be a bounded XML token")
    return value


@dataclass(frozen=True, slots=True)
class Bank:
    """A caller-supplied bank endpoint and EBICS host identifier."""

    endpoint: str = field(repr=False)
    host_id: str = field(repr=False)
    institution_name: str | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        parts = urlsplit(self.endpoint)
        if (
            parts.scheme != "https"
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
        ):
            raise ConfigurationError(
                "bank endpoint must be HTTPS without credentials, query, or fragment"
            )
        _require_identifier("host_id", self.host_id)
        if len(self.host_id) > 35:
            raise ConfigurationError("host_id exceeds the H005 limit")
        if self.institution_name is not None:
            _require_xml_token("institution_name", self.institution_name, 128)


@dataclass(frozen=True, slots=True)
class Subscriber:
    """Bank-issued participant identifiers; deliberately hidden from repr."""

    partner_id: str = field(repr=False)
    user_id: str = field(repr=False)
    system_id: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        for name, value, optional in (
            ("partner_id", self.partner_id, False),
            ("user_id", self.user_id, False),
            ("system_id", self.system_id, True),
        ):
            if optional and value is None:
                continue
            if (
                not isinstance(value, str)
                or _H005_SUBSCRIBER_ID.fullmatch(value) is None
            ):
                raise ConfigurationError(
                    f"{name} must match the H005 subscriber identifier profile"
                )


class ContainerType(str, Enum):
    """Container handling requested for a BTF download."""

    NONE = "NONE"
    ZIP = "ZIP"


@dataclass(frozen=True, slots=True)
class BtfDescriptor:
    """Complete caller-supplied BTF service descriptor for BTD."""

    service_name: str
    message_name: str
    message_version: str | None
    variant: str | None
    format: str | None
    service_option: str | None
    container_type: ContainerType
    scope: str | None = None

    def __post_init__(self) -> None:
        values = (
            ("service_name", self.service_name, _BTF_SERVICE_NAME),
            ("message_name", self.message_name, _BTF_MESSAGE_NAME),
            ("message_version", self.message_version, _BTF_NUMBER),
            ("variant", self.variant, _BTF_NUMBER),
            ("format", self.format, _BTF_FORMAT),
            ("service_option", self.service_option, _BTF_SERVICE_OPTION),
            ("scope", self.scope, _BTF_SCOPE),
        )
        for name, value, pattern in values:
            if value is not None and (
                not isinstance(value, str) or pattern.fullmatch(value) is None
            ):
                raise ConfigurationError(f"{name} is not a valid H005 BTF value")
        if not isinstance(self.container_type, ContainerType):
            raise TypeError("container_type must be a ContainerType")


@dataclass(frozen=True, slots=True)
class DateRange:
    """Inclusive caller-requested booking date range."""

    start: date
    end: date

    def __post_init__(self) -> None:
        if not isinstance(self.start, date) or not isinstance(self.end, date):
            raise TypeError("start and end must be dates")
        if self.start > self.end:
            raise ConfigurationError("date range start must not follow end")


@dataclass(frozen=True, slots=True)
class AccountSelector:
    """Optional, typed account restriction; actual bank support is discoverable."""

    iban: str | None = field(default=None, repr=False)
    account_id: str | None = field(default=None, repr=False)
    currency: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if (self.iban is None) == (self.account_id is None):
            raise ConfigurationError("provide exactly one of iban or account_id")
        if self.iban is not None and (
            not isinstance(self.iban, str) or _IBAN.fullmatch(self.iban) is None
        ):
            raise ConfigurationError(
                "iban must be an uppercase, structurally valid IBAN token"
            )
        if self.account_id is not None:
            _require_xml_token("account_id", self.account_id, 64)
        if self.currency is not None and (
            not isinstance(self.currency, str)
            or _CURRENCY.fullmatch(self.currency) is None
        ):
            raise ConfigurationError("currency must be a three-letter uppercase code")


@dataclass(frozen=True, slots=True)
class DownloadOptions:
    """Semantic download filters; never raw EBICS/XML parameters."""

    date_range: DateRange | None = None
    account: AccountSelector | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.date_range is not None and not isinstance(self.date_range, DateRange):
            raise TypeError("date_range must be a DateRange")
        if self.account is not None and not isinstance(self.account, AccountSelector):
            raise TypeError("account must be an AccountSelector")


@dataclass(frozen=True, slots=True)
class ProtocolLimits:
    """Fail-closed resource limits for future BTD processing."""

    max_segments: int = 10_000
    max_compressed_bytes: int = 64 * 1024 * 1024
    max_decompressed_bytes: int = 256 * 1024 * 1024
    max_zip_members: int = 1_000
    max_zip_member_bytes: int = 128 * 1024 * 1024
    max_compression_ratio: int = 100

    def __post_init__(self) -> None:
        values = (
            self.max_segments,
            self.max_compressed_bytes,
            self.max_decompressed_bytes,
            self.max_zip_members,
            self.max_zip_member_bytes,
            self.max_compression_ratio,
        )
        if not all(type(value) is int for value in values):
            raise TypeError("all protocol limits must be integers")
        if min(values) <= 0:
            raise ConfigurationError("all protocol limits must be positive")
        if self.max_zip_member_bytes > self.max_decompressed_bytes:
            raise ConfigurationError(
                "single ZIP member limit cannot exceed decompressed total limit"
            )


class DownloadPhase(str, Enum):
    """Security-meaningful BTD states; no positive receipt before acceptance."""

    NEW = "new"
    INITIALIZED = "initialized"
    RECEIVING_SEGMENTS = "receiving_segments"
    SEGMENTS_RECEIVED = "segments_received"
    SIGNATURES_AND_DIGESTS_VERIFIED = "signatures_and_digests_verified"
    DECRYPTED = "decrypted"
    CONTAINER_VERIFIED = "container_verified"
    DOCUMENTS_STAGED = "documents_staged"
    RECEIPT_PENDING = "receipt_pending"
    RECEIPT_RESPONSE_VERIFIED = "receipt_response_verified"
    DOCUMENTS_PUBLISHED = "documents_published"
    RECEIPT_AMBIGUOUS = "receipt_ambiguous"
    COMPLETE = "complete"
    NEGATIVE_COMPLETE = "negative_complete"
    FAILED = "failed"


class ReceiptKind(str, Enum):
    """Normative receipt code semantics."""

    POSITIVE = "positive"
    NEGATIVE = "negative"


@dataclass(frozen=True, slots=True)
class DownloadRequestIdentity:
    """Sensitive SHA-256 identity binding one resumable local BTD request."""

    sha256_hex: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.sha256_hex, str)
            or _SHA256_HEX.fullmatch(self.sha256_hex) is None
        ):
            raise ConfigurationError(
                "download request identity must be 64 uppercase hex characters"
            )


@dataclass(frozen=True, slots=True)
class DocumentStagingId:
    """Deterministic idempotency key for one unpublished document."""

    sha256_hex: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.sha256_hex, str)
            or _SHA256_HEX.fullmatch(self.sha256_hex) is None
        ):
            raise ConfigurationError(
                "document staging ID must be 64 uppercase hex characters"
            )

    @classmethod
    def derive(
        cls,
        request_identity: DownloadRequestIdentity,
        transaction_id: TransactionId,
        document_position: int,
    ) -> DocumentStagingId:
        """Bind one stage to its request, authenticated transaction, and position."""

        if not isinstance(request_identity, DownloadRequestIdentity):
            raise TypeError("request_identity must be a DownloadRequestIdentity")
        if not isinstance(transaction_id, TransactionId):
            raise TypeError("transaction_id must be a TransactionId")
        if (
            type(document_position) is not int
            or document_position < 1
            or document_position > 0xFFFFFFFF
        ):
            raise ConfigurationError(
                "document_position must be between 1 and 4294967295"
            )
        digest = sha256(
            b"ebics-read:document-stage:v1\0"
            + bytes.fromhex(request_identity.sha256_hex)
            + bytes.fromhex(transaction_id.value)
            + document_position.to_bytes(4, "big")
        )
        return cls(digest.hexdigest().upper())


@dataclass(frozen=True, slots=True)
class DocumentReference:
    """Opaque caller-sink reference to one published document."""

    value: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.value, str)
            or not self.value
            or len(self.value) > 256
            or any(ord(character) < 0x20 for character in self.value)
        ):
            raise ConfigurationError(
                "document reference must be bounded printable text"
            )


@dataclass(frozen=True, slots=True)
class TransactionId:
    """One exact, sensitive 128-bit bank transaction identifier."""

    value: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.value, str)
            or re.fullmatch(r"[0-9A-F]{32}", self.value) is None
        ):
            raise ConfigurationError(
                "transaction ID must be 16 bytes in uppercase hexadecimal"
            )

    @classmethod
    def from_bytes(cls, value: bytes) -> TransactionId:
        if not isinstance(value, bytes):
            raise TypeError("transaction ID bytes must be bytes")
        if len(value) != 16:
            raise ConfigurationError("transaction ID must contain exactly 16 bytes")
        return cls(value.hex().upper())


@dataclass(frozen=True, slots=True, init=False)
class DownloadSession:
    """Immutable BTD state constructible only through validated transitions."""

    session_id: str = field(repr=False, init=False)
    request_identity: DownloadRequestIdentity = field(repr=False, init=False)
    phase: DownloadPhase = field(init=False)
    transaction_id: TransactionId | None = field(default=None, repr=False)
    next_segment: int = field(init=False)
    total_segments: int | None = field(init=False)
    max_segments: int = field(init=False)
    revision: int = field(init=False)
    receipt_kind: ReceiptKind | None = field(init=False)
    staged_documents: tuple[StagedDocument, ...] = field(repr=False, init=False)
    published_documents: tuple[DownloadedDocument, ...] = field(repr=False, init=False)

    def __init__(
        self,
        session_id: str,
        request_identity: DownloadRequestIdentity,
        phase: DownloadPhase,
        transaction_id: TransactionId | None,
        next_segment: int,
        total_segments: int | None,
        max_segments: int,
        revision: int,
        receipt_kind: ReceiptKind | None,
        staged_documents: tuple[StagedDocument, ...],
        published_documents: tuple[DownloadedDocument, ...],
        *,
        _creation_token: object | None = None,
    ) -> None:
        if _creation_token is not _SESSION_CREATION_TOKEN:
            raise TypeError("download sessions are created through state methods")
        object.__setattr__(self, "session_id", session_id)
        object.__setattr__(self, "request_identity", request_identity)
        object.__setattr__(self, "phase", phase)
        object.__setattr__(self, "transaction_id", transaction_id)
        object.__setattr__(self, "next_segment", next_segment)
        object.__setattr__(self, "total_segments", total_segments)
        object.__setattr__(self, "max_segments", max_segments)
        object.__setattr__(self, "revision", revision)
        object.__setattr__(self, "receipt_kind", receipt_kind)
        object.__setattr__(self, "staged_documents", tuple(staged_documents))
        object.__setattr__(self, "published_documents", tuple(published_documents))
        _require_identifier("session_id", self.session_id)
        if not isinstance(self.request_identity, DownloadRequestIdentity):
            raise TypeError("request_identity must be a DownloadRequestIdentity")
        if not isinstance(self.phase, DownloadPhase):
            raise TypeError("phase must be a DownloadPhase")
        if self.transaction_id is not None and not isinstance(
            self.transaction_id, TransactionId
        ):
            raise TypeError("transaction_id must be a TransactionId")
        if type(self.next_segment) is not int:
            raise TypeError("next_segment must be an integer")
        if self.next_segment <= 0:
            raise ConfigurationError("next_segment must be positive")
        if type(self.max_segments) is not int or self.max_segments <= 0:
            raise ConfigurationError("max_segments must be a positive integer")
        if self.total_segments is not None:
            if type(self.total_segments) is not int:
                raise TypeError("total_segments must be an integer")
            if self.total_segments <= 0:
                raise ConfigurationError("total_segments must be positive")
            if self.next_segment > self.total_segments + 1:
                raise ConfigurationError("next_segment exceeds transaction bounds")
            if self.total_segments > self.max_segments:
                raise ConfigurationError("transaction exceeds configured segment limit")
        if type(self.revision) is not int or self.revision < 0:
            raise ConfigurationError("revision must be a non-negative integer")
        if self.receipt_kind is not None and not isinstance(
            self.receipt_kind, ReceiptKind
        ):
            raise TypeError("receipt_kind must be a ReceiptKind")
        if not all(
            isinstance(value, StagedDocument) for value in self.staged_documents
        ):
            raise TypeError("staged_documents must contain StagedDocument values")
        if not all(
            isinstance(value, DownloadedDocument) for value in self.published_documents
        ):
            raise TypeError(
                "published_documents must contain DownloadedDocument values"
            )
        self._validate_coherence()

    @classmethod
    def _create(
        cls,
        session_id: str,
        request_identity: DownloadRequestIdentity,
        phase: DownloadPhase,
        transaction_id: TransactionId | None,
        next_segment: int,
        total_segments: int | None,
        max_segments: int,
        revision: int,
        receipt_kind: ReceiptKind | None,
        staged_documents: tuple[StagedDocument, ...],
        published_documents: tuple[DownloadedDocument, ...],
    ) -> DownloadSession:
        return cls(
            session_id,
            request_identity,
            phase,
            transaction_id,
            next_segment,
            total_segments,
            max_segments,
            revision,
            receipt_kind,
            staged_documents,
            published_documents,
            _creation_token=_SESSION_CREATION_TOKEN,
        )

    @classmethod
    def start(
        cls,
        session_id: str,
        request_identity: DownloadRequestIdentity,
        limits: ProtocolLimits,
    ) -> DownloadSession:
        """Start a transaction before a bank transaction ID exists."""

        if not isinstance(limits, ProtocolLimits):
            raise TypeError("limits must be ProtocolLimits")
        return cls._create(
            session_id,
            request_identity,
            DownloadPhase.NEW,
            None,
            1,
            None,
            limits.max_segments,
            0,
            None,
            (),
            (),
        )

    @classmethod
    def restore(
        cls,
        *,
        session_id: str,
        request_identity: DownloadRequestIdentity,
        phase: DownloadPhase,
        transaction_id: TransactionId | None,
        next_segment: int,
        total_segments: int | None,
        max_segments: int,
        revision: int,
        receipt_kind: ReceiptKind | None = None,
        staged_documents: tuple[StagedDocument, ...] = (),
        published_documents: tuple[DownloadedDocument, ...] = (),
    ) -> DownloadSession:
        """Restore host-persisted state after applying every invariant."""

        return cls._create(
            session_id,
            request_identity,
            phase,
            transaction_id,
            next_segment,
            total_segments,
            max_segments,
            revision,
            receipt_kind,
            staged_documents,
            published_documents,
        )

    def initialize(
        self, *, transaction_id: TransactionId, total_segments: int
    ) -> DownloadSession:
        """Accept authenticated initialization metadata."""

        self._require_phase(DownloadPhase.NEW)
        return self._create(
            self.session_id,
            self.request_identity,
            DownloadPhase.INITIALIZED,
            transaction_id,
            1,
            total_segments,
            self.max_segments,
            self.revision + 1,
            None,
            (),
            (),
        )

    def record_segment(self, segment_number: int) -> DownloadSession:
        """Advance only for the exact next authenticated segment."""

        if type(segment_number) is not int:
            raise TypeError("segment_number must be an integer")
        if self.phase not in {
            DownloadPhase.INITIALIZED,
            DownloadPhase.RECEIVING_SEGMENTS,
        }:
            raise ConfigurationError("segments are not accepted in this phase")
        if segment_number != self.next_segment:
            raise ConfigurationError("segment is missing, duplicate, or reordered")
        if self.total_segments is None or self.transaction_id is None:
            raise ConfigurationError("initialized transaction metadata is missing")
        next_segment = segment_number + 1
        phase = (
            DownloadPhase.SEGMENTS_RECEIVED
            if segment_number == self.total_segments
            else DownloadPhase.RECEIVING_SEGMENTS
        )
        return self._advance(phase, next_segment=next_segment)

    def mark_signatures_and_digests_verified(self) -> DownloadSession:
        """Record authentication of every response and order-data digest."""

        self._require_phase(DownloadPhase.SEGMENTS_RECEIVED)
        return self._advance(DownloadPhase.SIGNATURES_AND_DIGESTS_VERIFIED)

    def mark_decrypted(self) -> DownloadSession:
        """Record authenticated decryption after digest verification."""

        self._require_phase(DownloadPhase.SIGNATURES_AND_DIGESTS_VERIFIED)
        return self._advance(DownloadPhase.DECRYPTED)

    def mark_container_verified(self) -> DownloadSession:
        """Record bounded decompression and complete container validation."""

        self._require_phase(DownloadPhase.DECRYPTED)
        return self._advance(DownloadPhase.CONTAINER_VERIFIED)

    def mark_documents_staged(
        self, documents: tuple[StagedDocument, ...]
    ) -> DownloadSession:
        """Persist accepted plaintext identities without publishing plaintext."""

        self._require_phase(DownloadPhase.CONTAINER_VERIFIED)
        if not documents:
            raise ConfigurationError("at least one staged document is required")
        return self._advance(
            DownloadPhase.DOCUMENTS_STAGED, staged_documents=tuple(documents)
        )

    def mark_positive_receipt_pending(self) -> DownloadSession:
        """Persist code 0 intent before any receipt request bytes are sent."""

        self._require_phase(DownloadPhase.DOCUMENTS_STAGED)
        return self._advance(
            DownloadPhase.RECEIPT_PENDING,
            receipt_kind=ReceiptKind.POSITIVE,
        )

    def mark_negative_receipt_pending(self) -> DownloadSession:
        """Persist code 1 intent before any receipt request bytes are sent."""

        if self.phase not in {
            DownloadPhase.SEGMENTS_RECEIVED,
            DownloadPhase.SIGNATURES_AND_DIGESTS_VERIFIED,
            DownloadPhase.DECRYPTED,
            DownloadPhase.CONTAINER_VERIFIED,
        }:
            raise ConfigurationError("negative receipt is not valid in this phase")
        return self._advance(
            DownloadPhase.RECEIPT_PENDING,
            receipt_kind=ReceiptKind.NEGATIVE,
        )

    def mark_receipt_ambiguous(self) -> DownloadSession:
        """Record an unknown receipt outcome after transmission began."""

        if self.phase is not DownloadPhase.RECEIPT_PENDING:
            raise ConfigurationError("receipt ambiguity requires pending receipt I/O")
        return self._advance(DownloadPhase.RECEIPT_AMBIGUOUS)

    def mark_receipt_response_verified(self) -> DownloadSession:
        """Record an authenticated response with the expected receipt return code."""

        if self.phase not in {
            DownloadPhase.RECEIPT_PENDING,
            DownloadPhase.RECEIPT_AMBIGUOUS,
        }:
            raise ConfigurationError("receipt response is not expected in this phase")
        return self._advance(DownloadPhase.RECEIPT_RESPONSE_VERIFIED)

    def mark_documents_published(
        self, documents: tuple[DownloadedDocument, ...]
    ) -> DownloadSession:
        """Persist idempotently published results after a positive receipt."""

        self._require_phase(DownloadPhase.RECEIPT_RESPONSE_VERIFIED)
        if self.receipt_kind is not ReceiptKind.POSITIVE:
            raise ConfigurationError("only a positive receipt publishes documents")
        published = tuple(documents)
        if len(published) != len(self.staged_documents) or any(
            (
                staged.staging_id,
                staged.provenance,
                staged.content_sha256,
                staged.size_bytes,
                staged.zip_members,
            )
            != (
                document.staging_id,
                document.provenance,
                document.content_sha256,
                document.size_bytes,
                document.zip_members,
            )
            for staged, document in zip(self.staged_documents, published, strict=True)
        ):
            raise ConfigurationError(
                "published documents do not match staged documents"
            )
        return self._advance(
            DownloadPhase.DOCUMENTS_PUBLISHED, published_documents=published
        )

    def finish(self) -> DownloadSession:
        """Finish only after the receipt response has been authenticated."""

        if self.receipt_kind is ReceiptKind.POSITIVE:
            self._require_phase(DownloadPhase.DOCUMENTS_PUBLISHED)
            target = DownloadPhase.COMPLETE
        else:
            self._require_phase(DownloadPhase.RECEIPT_RESPONSE_VERIFIED)
            target = DownloadPhase.NEGATIVE_COMPLETE
        return self._advance(target)

    def fail(self) -> DownloadSession:
        """Enter terminal failure after any unpersisted sink stage was discarded."""

        if self.phase in {
            DownloadPhase.RECEIPT_PENDING,
            DownloadPhase.DOCUMENTS_STAGED,
            DownloadPhase.RECEIPT_RESPONSE_VERIFIED,
            DownloadPhase.DOCUMENTS_PUBLISHED,
            DownloadPhase.RECEIPT_AMBIGUOUS,
            DownloadPhase.COMPLETE,
            DownloadPhase.NEGATIVE_COMPLETE,
            DownloadPhase.FAILED,
        }:
            raise ConfigurationError("terminal download session cannot be reused")
        return self._advance(
            DownloadPhase.FAILED, staged_documents=(), published_documents=()
        )

    def is_exact_successor_of(self, previous: DownloadSession) -> bool:
        """Validate one generic CAS transition; initialization has its own operation."""

        if not isinstance(previous, DownloadSession):
            raise TypeError("previous must be a DownloadSession")

        try:
            if self.phase in {
                DownloadPhase.RECEIVING_SEGMENTS,
                DownloadPhase.SEGMENTS_RECEIVED,
            }:
                expected = previous.record_segment(previous.next_segment)
            elif self.phase is DownloadPhase.SIGNATURES_AND_DIGESTS_VERIFIED:
                expected = previous.mark_signatures_and_digests_verified()
            elif self.phase is DownloadPhase.DECRYPTED:
                expected = previous.mark_decrypted()
            elif self.phase is DownloadPhase.CONTAINER_VERIFIED:
                expected = previous.mark_container_verified()
            elif self.phase is DownloadPhase.DOCUMENTS_STAGED:
                expected = previous.mark_documents_staged(self.staged_documents)
            elif self.phase is DownloadPhase.RECEIPT_PENDING:
                expected = (
                    previous.mark_positive_receipt_pending()
                    if self.receipt_kind is ReceiptKind.POSITIVE
                    else previous.mark_negative_receipt_pending()
                )
            elif self.phase is DownloadPhase.RECEIPT_AMBIGUOUS:
                expected = previous.mark_receipt_ambiguous()
            elif self.phase is DownloadPhase.RECEIPT_RESPONSE_VERIFIED:
                expected = previous.mark_receipt_response_verified()
            elif self.phase is DownloadPhase.DOCUMENTS_PUBLISHED:
                expected = previous.mark_documents_published(self.published_documents)
            elif self.phase in {
                DownloadPhase.COMPLETE,
                DownloadPhase.NEGATIVE_COMPLETE,
            }:
                expected = previous.finish()
            elif self.phase is DownloadPhase.FAILED:
                expected = previous.fail()
            else:
                return False
        except (ConfigurationError, TypeError):
            return False
        return self == expected

    def _advance(
        self,
        phase: DownloadPhase,
        *,
        next_segment: int | None = None,
        receipt_kind: ReceiptKind | None = None,
        staged_documents: tuple[StagedDocument, ...] | None = None,
        published_documents: tuple[DownloadedDocument, ...] | None = None,
    ) -> DownloadSession:
        return self._create(
            self.session_id,
            self.request_identity,
            phase,
            self.transaction_id,
            self.next_segment if next_segment is None else next_segment,
            self.total_segments,
            self.max_segments,
            self.revision + 1,
            self.receipt_kind if receipt_kind is None else receipt_kind,
            (self.staged_documents if staged_documents is None else staged_documents),
            (
                self.published_documents
                if published_documents is None
                else published_documents
            ),
        )

    def _require_phase(self, phase: DownloadPhase) -> None:
        if self.phase is not phase:
            raise ConfigurationError("invalid download-session transition")

    def _validate_coherence(self) -> None:
        if self.phase is DownloadPhase.NEW:
            if (
                self.transaction_id is not None
                or self.total_segments is not None
                or self.next_segment != 1
                or self.receipt_kind is not None
                or self.staged_documents
                or self.published_documents
            ):
                raise ConfigurationError("new session contains transaction state")
            return
        if self.phase is DownloadPhase.FAILED and self.transaction_id is None:
            if (
                self.total_segments is not None
                or self.next_segment != 1
                or self.receipt_kind is not None
                or self.staged_documents
                or self.published_documents
            ):
                raise ConfigurationError(
                    "failed pre-initialization state is incoherent"
                )
            return
        if self.transaction_id is None or self.total_segments is None:
            raise ConfigurationError("active session lacks transaction metadata")
        finished = self.next_segment == self.total_segments + 1
        if self.phase is DownloadPhase.INITIALIZED and self.next_segment != 1:
            raise ConfigurationError("initialized session must begin at segment one")
        if self.phase is DownloadPhase.RECEIVING_SEGMENTS and self.next_segment < 2:
            raise ConfigurationError("receiving session has no recorded segment")
        if (
            self.phase
            in {
                DownloadPhase.SEGMENTS_RECEIVED,
                DownloadPhase.SIGNATURES_AND_DIGESTS_VERIFIED,
                DownloadPhase.DECRYPTED,
                DownloadPhase.CONTAINER_VERIFIED,
                DownloadPhase.DOCUMENTS_STAGED,
                DownloadPhase.RECEIPT_PENDING,
                DownloadPhase.RECEIPT_RESPONSE_VERIFIED,
                DownloadPhase.RECEIPT_AMBIGUOUS,
                DownloadPhase.DOCUMENTS_PUBLISHED,
                DownloadPhase.COMPLETE,
                DownloadPhase.NEGATIVE_COMPLETE,
            }
            and not finished
        ):
            raise ConfigurationError("completed session has missing segments")
        if (
            self.phase
            in {
                DownloadPhase.INITIALIZED,
                DownloadPhase.RECEIVING_SEGMENTS,
            }
            and finished
        ):
            raise ConfigurationError("active session has no remaining segment")
        receipt_phases = {
            DownloadPhase.RECEIPT_PENDING,
            DownloadPhase.RECEIPT_RESPONSE_VERIFIED,
            DownloadPhase.RECEIPT_AMBIGUOUS,
            DownloadPhase.DOCUMENTS_PUBLISHED,
            DownloadPhase.COMPLETE,
            DownloadPhase.NEGATIVE_COMPLETE,
        }
        if (self.phase in receipt_phases) != (self.receipt_kind is not None):
            raise ConfigurationError("receipt state and receipt kind disagree")
        staged_phases = {
            DownloadPhase.DOCUMENTS_STAGED,
            DownloadPhase.DOCUMENTS_PUBLISHED,
            DownloadPhase.COMPLETE,
        }
        if self.phase in {
            DownloadPhase.RECEIPT_PENDING,
            DownloadPhase.RECEIPT_RESPONSE_VERIFIED,
            DownloadPhase.RECEIPT_AMBIGUOUS,
        }:
            expects_staged = self.receipt_kind is ReceiptKind.POSITIVE
        else:
            expects_staged = self.phase in staged_phases
        if bool(self.staged_documents) is not expects_staged:
            raise ConfigurationError("staged documents and transaction phase disagree")
        if self.staged_documents:
            staging_ids = [document.staging_id for document in self.staged_documents]
            if len(staging_ids) != len(set(staging_ids)):
                raise ConfigurationError("staged document IDs must be unique")
            if any(
                document.staging_id
                != DocumentStagingId.derive(
                    self.request_identity, self.transaction_id, position
                )
                for position, document in enumerate(self.staged_documents, start=1)
            ):
                raise ConfigurationError(
                    "staged document ID does not match its transaction position"
                )
            transaction_hash = ContentSha256.from_bytes(
                bytes.fromhex(self.transaction_id.value)
            )
            if any(
                document.provenance.transaction_id_sha256 != transaction_hash
                or document.provenance.segment_count != self.total_segments
                for document in self.staged_documents
            ):
                raise ConfigurationError(
                    "staged document provenance does not match the transaction"
                )
        published_phases = {
            DownloadPhase.DOCUMENTS_PUBLISHED,
            DownloadPhase.COMPLETE,
        }
        if bool(self.published_documents) is not (self.phase in published_phases):
            raise ConfigurationError(
                "published documents and transaction phase disagree"
            )
        if self.published_documents and len(self.published_documents) != len(
            self.staged_documents
        ):
            raise ConfigurationError("published and staged document counts disagree")
        if self.published_documents and any(
            (
                staged.staging_id,
                staged.provenance,
                staged.content_sha256,
                staged.size_bytes,
                staged.zip_members,
            )
            != (
                document.staging_id,
                document.provenance,
                document.content_sha256,
                document.size_bytes,
                document.zip_members,
            )
            for staged, document in zip(
                self.staged_documents, self.published_documents, strict=True
            )
        ):
            raise ConfigurationError(
                "published documents do not match staged documents"
            )
        if (
            self.phase is DownloadPhase.COMPLETE
            and self.receipt_kind is not ReceiptKind.POSITIVE
        ):
            raise ConfigurationError("complete session requires a positive receipt")
        if (
            self.phase is DownloadPhase.NEGATIVE_COMPLETE
            and self.receipt_kind is not ReceiptKind.NEGATIVE
        ):
            raise ConfigurationError("negative completion requires a negative receipt")


@dataclass(frozen=True, slots=True)
class ProtocolVersion:
    """One protocol version advertised by HEV."""

    protocol_version: str
    version_number: str

    def __post_init__(self) -> None:
        if _PROTOCOL_VERSION.fullmatch(self.protocol_version) is None:
            raise ConfigurationError(
                "protocol_version must match H followed by 3 digits"
            )
        if _VERSION_NUMBER.fullmatch(self.version_number) is None:
            raise ConfigurationError("version_number must match NN.NN")


@dataclass(frozen=True, slots=True)
class NegotiatedProtocol:
    """The one protocol/schema pair implemented by this release."""

    protocol_version: str = "H005"
    version_number: str = "03.00"
    request_namespace: str = "urn:org:ebics:H005"
    hev_namespace: str = "http://www.ebics.org/H000"

    def __post_init__(self) -> None:
        if (
            self.protocol_version,
            self.version_number,
            self.request_namespace,
            self.hev_namespace,
        ) != (
            "H005",
            "03.00",
            "urn:org:ebics:H005",
            "http://www.ebics.org/H000",
        ):
            raise UnsupportedProtocolVersionError(
                "negotiated protocol must be exact H005/03.00 with H000/H005 namespaces"
            )


@dataclass(frozen=True, slots=True)
class VersionDiscovery:
    """Authenticated only by TLS: the parsed result of HEV/H000."""

    versions: tuple[ProtocolVersion, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "versions", tuple(self.versions))
        if not all(isinstance(value, ProtocolVersion) for value in self.versions):
            raise TypeError("versions must contain ProtocolVersion values")
        if not self.versions:
            raise ConfigurationError(
                "version discovery must contain at least one version"
            )
        if len(set(self.versions)) != len(self.versions):
            raise ConfigurationError("version discovery contains duplicate versions")
        by_protocol: dict[str, str] = {}
        by_version: dict[str, str] = {}
        for value in self.versions:
            existing_version = by_protocol.setdefault(
                value.protocol_version, value.version_number
            )
            existing_protocol = by_version.setdefault(
                value.version_number, value.protocol_version
            )
            if existing_version != value.version_number:
                raise ConfigurationError("conflicting protocol advertisement")
            if existing_protocol != value.protocol_version:
                raise ConfigurationError("conflicting version advertisement")

    def select_h005(self) -> NegotiatedProtocol:
        """Select exactly H005/03.00; never downgrade or guess a revision."""

        supported = ProtocolVersion("H005", "03.00")
        if supported not in self.versions:
            raise UnsupportedProtocolVersionError(
                "bank did not advertise exact supported protocol H005/03.00"
            )
        return NegotiatedProtocol()


@dataclass(frozen=True, slots=True)
class ServiceCapability:
    """A service descriptor reported by a discovery order."""

    descriptor: BtfDescriptor
    source_order: OrderType

    def __post_init__(self) -> None:
        if not isinstance(self.descriptor, BtfDescriptor):
            raise TypeError("descriptor must be a BtfDescriptor")
        if not isinstance(self.source_order, OrderType):
            raise TypeError("source_order must be an OrderType")
        if self.source_order not in {
            OrderType.HAA,
            OrderType.HKD,
            OrderType.HTD,
        }:
            raise ConfigurationError("capability source must be a discovery order")


@dataclass(frozen=True, slots=True)
class AdvertisedBankUrl:
    """An informational HPD endpoint; never an automatic redirect target."""

    value: str = field(repr=False)
    valid_from: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not 0 < len(self.value) <= 2048:
            raise ConfigurationError("advertised bank URL must be a bounded string")
        if self.valid_from is not None and not isinstance(self.valid_from, datetime):
            raise TypeError("valid_from must be a datetime")


@dataclass(frozen=True, slots=True)
class BankParameters:
    """Read-relevant HPD access and protocol parameters."""

    urls: tuple[AdvertisedBankUrl, ...]
    institute: str = field(repr=False)
    host_id: str | None = field(repr=False)
    protocol_versions: tuple[str, ...]
    authentication_versions: tuple[str, ...]
    encryption_versions: tuple[str, ...]
    signature_versions: tuple[str, ...]
    recovery_supported: bool
    client_data_download_supported: bool
    downloadable_order_data_supported: bool

    def __post_init__(self) -> None:
        for name in (
            "urls",
            "protocol_versions",
            "authentication_versions",
            "encryption_versions",
            "signature_versions",
        ):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        if not self.urls or not all(
            isinstance(value, AdvertisedBankUrl) for value in self.urls
        ):
            raise ConfigurationError("bank parameters require advertised URLs")
        if (
            not isinstance(self.institute, str)
            or "\n" in self.institute
            or "\r" in self.institute
            or "\t" in self.institute
            or len(self.institute) > 80
        ):
            raise ConfigurationError(
                "institute must be a normalized string up to 80 chars"
            )
        if self.host_id is not None:
            _require_xml_token("host_id", self.host_id, 35)
        versions = (
            ("protocol_versions", self.protocol_versions, _PROTOCOL_VERSION),
            (
                "authentication_versions",
                self.authentication_versions,
                _AUTHENTICATION_VERSION,
            ),
            ("encryption_versions", self.encryption_versions, _ENCRYPTION_VERSION),
            ("signature_versions", self.signature_versions, _SIGNATURE_VERSION),
        )
        for name, values, pattern in versions:
            if not values or not all(
                isinstance(value, str) and pattern.fullmatch(value) is not None
                for value in values
            ):
                raise ConfigurationError(f"{name} contains invalid version values")
            if len(values) != len(set(values)):
                raise ConfigurationError(f"{name} contains duplicate versions")
        if not all(
            type(value) is bool
            for value in (
                self.recovery_supported,
                self.client_data_download_supported,
                self.downloadable_order_data_supported,
            )
        ):
            raise TypeError("HPD support flags must be booleans")


@dataclass(frozen=True, slots=True)
class DiscoveredAccount:
    """Minimum account identity needed to restrict a future BTD request."""

    account_id: str = field(repr=False)
    iban: str | None = field(default=None, repr=False)
    currency: str = field(default="EUR", repr=False)
    restricted_services: tuple[BtfDescriptor, ...] | None = field(
        default=None, repr=False
    )

    def __post_init__(self) -> None:
        _require_xml_token("account_id", self.account_id, 64)
        if self.iban is not None and (
            not isinstance(self.iban, str) or _IBAN.fullmatch(self.iban) is None
        ):
            raise ConfigurationError("iban must be an uppercase IBAN token")
        if (
            not isinstance(self.currency, str)
            or _CURRENCY.fullmatch(self.currency) is None
        ):
            raise ConfigurationError("currency must be a three-letter uppercase code")
        if self.restricted_services is not None:
            object.__setattr__(
                self, "restricted_services", tuple(self.restricted_services)
            )
            if not all(
                isinstance(value, BtfDescriptor) for value in self.restricted_services
            ):
                raise TypeError("restricted_services must contain BtfDescriptor values")


@dataclass(frozen=True, slots=True)
class DownloadPermission:
    """One HKD/HTD subscriber permission for the only business order, BTD."""

    descriptor: BtfDescriptor = field(repr=False)
    account_id: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.descriptor, BtfDescriptor):
            raise TypeError("descriptor must be a BtfDescriptor")
        if self.account_id is not None:
            _require_xml_token("account_id", self.account_id, 64)


@dataclass(frozen=True, slots=True)
class DiscoveredUser:
    """One bank-reported subscriber and its BTD-only permissions."""

    user_id: str = field(repr=False)
    status: int = field(repr=False)
    permissions: tuple[DownloadPermission, ...] = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.user_id, str)
            or _H005_SUBSCRIBER_ID.fullmatch(self.user_id) is None
        ):
            raise ConfigurationError("user_id is not a valid H005 subscriber ID")
        if type(self.status) is not int or not 0 <= self.status <= 99:
            raise ConfigurationError("subscriber status must be between 0 and 99")
        object.__setattr__(self, "permissions", tuple(self.permissions))
        if not all(isinstance(value, DownloadPermission) for value in self.permissions):
            raise TypeError("permissions must contain DownloadPermission values")
        if len(self.permissions) != len(set(self.permissions)):
            raise ConfigurationError("subscriber contains duplicate BTD permissions")


@dataclass(frozen=True, slots=True)
class CustomerInformation:
    """Read-relevant HKD or HTD customer, account, and subscriber data."""

    source_order: OrderType
    host_id: str = field(repr=False)
    accounts: tuple[DiscoveredAccount, ...] = field(repr=False)
    services: tuple[ServiceCapability, ...] = field(repr=False)
    users: tuple[DiscoveredUser, ...] = field(repr=False)

    def __post_init__(self) -> None:
        if self.source_order not in {OrderType.HKD, OrderType.HTD}:
            raise ConfigurationError("customer information must come from HKD or HTD")
        _require_xml_token("host_id", self.host_id, 35)
        for name in ("accounts", "services", "users"):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        if not all(isinstance(value, DiscoveredAccount) for value in self.accounts):
            raise TypeError("accounts must contain DiscoveredAccount values")
        if not all(isinstance(value, ServiceCapability) for value in self.services):
            raise TypeError("services must contain ServiceCapability values")
        if not self.users or not all(
            isinstance(value, DiscoveredUser) for value in self.users
        ):
            raise ConfigurationError("customer information requires discovered users")
        if self.source_order is OrderType.HTD and len(self.users) != 1:
            raise ConfigurationError("HTD must describe exactly one subscriber")
        if any(value.source_order is not self.source_order for value in self.services):
            raise ConfigurationError(
                "service source does not match customer data source"
            )
        account_ids = [value.account_id for value in self.accounts]
        if len(account_ids) != len(set(account_ids)):
            raise ConfigurationError(
                "customer information contains duplicate account IDs"
            )
        known_accounts = set(account_ids)
        user_ids = [value.user_id for value in self.users]
        if len(user_ids) != len(set(user_ids)):
            raise ConfigurationError("customer information contains duplicate users")
        customer_descriptors = {value.descriptor for value in self.services}
        if any(
            permission.descriptor not in customer_descriptors
            for user in self.users
            for permission in user.permissions
        ):
            raise ConfigurationError(
                "subscriber permission is absent from customer services"
            )
        if any(
            permission.account_id not in known_accounts
            for user in self.users
            for permission in user.permissions
            if permission.account_id is not None
        ):
            raise ConfigurationError("permission references an unknown account")


@dataclass(frozen=True, slots=True)
class CapabilityDiscovery:
    """Defensive union of supported discovery-order results."""

    services: tuple[ServiceCapability, ...] = field(default=(), repr=False)
    completed_orders: tuple[OrderType, ...] = ()
    unsupported_orders: tuple[OrderType, ...] = ()
    bank_parameters: BankParameters | None = None
    customer_information: tuple[CustomerInformation, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "services", tuple(self.services))
        object.__setattr__(
            self, "customer_information", tuple(self.customer_information)
        )
        object.__setattr__(self, "completed_orders", tuple(self.completed_orders))
        object.__setattr__(self, "unsupported_orders", tuple(self.unsupported_orders))
        if not all(isinstance(value, ServiceCapability) for value in self.services):
            raise TypeError("services must contain ServiceCapability values")
        if len(self.services) != len(set(self.services)):
            raise ConfigurationError("capability results contain duplicate services")
        if self.bank_parameters is not None and not isinstance(
            self.bank_parameters, BankParameters
        ):
            raise TypeError("bank_parameters must be BankParameters")
        if not all(
            isinstance(value, CustomerInformation)
            for value in self.customer_information
        ):
            raise TypeError(
                "customer_information must contain CustomerInformation values"
            )
        if not all(
            isinstance(value, OrderType)
            for value in (*self.completed_orders, *self.unsupported_orders)
        ):
            raise TypeError("capability orders must be OrderType values")
        if not all(
            value in DISCOVERY_ORDERS
            for value in (*self.completed_orders, *self.unsupported_orders)
        ):
            raise ConfigurationError("capability results accept discovery orders only")
        if set(self.completed_orders) & set(self.unsupported_orders):
            raise ConfigurationError("an order cannot be completed and unsupported")
        if len(self.completed_orders) != len(set(self.completed_orders)) or len(
            self.unsupported_orders
        ) != len(set(self.unsupported_orders)):
            raise ConfigurationError("capability results contain duplicate orders")
        if any(
            value.source_order not in self.completed_orders for value in self.services
        ):
            raise ConfigurationError("service capability requires its completed order")
        customer_services = {
            service
            for customer in self.customer_information
            for service in customer.services
        }
        aggregate_customer_services = {
            service
            for service in self.services
            if service.source_order in {OrderType.HKD, OrderType.HTD}
        }
        if customer_services != aggregate_customer_services:
            raise ConfigurationError("aggregate and customer services must agree")
        if (self.bank_parameters is not None) != (
            OrderType.HPD in self.completed_orders
        ):
            raise ConfigurationError("HPD completion and bank parameters must agree")
        customer_orders = [value.source_order for value in self.customer_information]
        if len(customer_orders) != len(set(customer_orders)):
            raise ConfigurationError("customer discovery order appears more than once")
        if any(value not in self.completed_orders for value in customer_orders):
            raise ConfigurationError("customer data requires its completed order")
        if any(
            value in self.completed_orders and value not in customer_orders
            for value in (OrderType.HKD, OrderType.HTD)
        ):
            raise ConfigurationError("HKD/HTD completion requires customer data")


@dataclass(frozen=True, slots=True)
class CertificateFingerprint:
    """Generic SHA-256 identity of one exact DER certificate."""

    sha256_hex: str

    def __post_init__(self) -> None:
        if _SHA256_HEX.fullmatch(self.sha256_hex) is None:
            raise ConfigurationError(
                "certificate fingerprint must be 64 uppercase hexadecimal characters"
            )

    @classmethod
    def from_der(cls, certificate_der: bytes) -> CertificateFingerprint:
        if not isinstance(certificate_der, bytes) or not certificate_der:
            raise ConfigurationError("certificate DER must be non-empty bytes")
        return cls(sha256(certificate_der).hexdigest().upper())


@dataclass(frozen=True, slots=True)
class EbicsPublicKeyDigest:
    """Normative H005 SHA-256 digest of a complete DER certificate."""

    sha256_hex: str

    def __post_init__(self) -> None:
        if _SHA256_HEX.fullmatch(self.sha256_hex) is None:
            raise ConfigurationError(
                "EBICS public-key digest must be 64 uppercase hexadecimal characters"
            )

    @classmethod
    def from_h005_certificate_der(cls, certificate_der: bytes) -> EbicsPublicKeyDigest:
        """Apply the H005 certificate-DER digest defined by EBICS 3.0.2."""

        if not isinstance(certificate_der, bytes) or not certificate_der:
            raise ConfigurationError("certificate DER must be non-empty bytes")
        return cls(sha256(certificate_der).hexdigest().upper())


@dataclass(frozen=True, slots=True, init=False)
class AcceptedBankKeyIdentity:
    """Two OOB-provided EBICS identities accepted together for one bank."""

    authentication: EbicsPublicKeyDigest = field(init=False)
    encryption: EbicsPublicKeyDigest = field(init=False)

    def __init__(
        self,
        authentication: EbicsPublicKeyDigest,
        encryption: EbicsPublicKeyDigest,
        *,
        _oob_token: object | None = None,
    ) -> None:
        if _oob_token is not _OOB_IDENTITY_TOKEN:
            raise TypeError(
                "accepted bank-key identity must be entered through from_out_of_band"
            )
        object.__setattr__(self, "authentication", authentication)
        object.__setattr__(self, "encryption", encryption)

    @classmethod
    def from_out_of_band(
        cls, authentication_sha256_hex: str, encryption_sha256_hex: str
    ) -> AcceptedBankKeyIdentity:
        """Parse values independently transcribed from the bank's OOB channel."""

        return cls(
            EbicsPublicKeyDigest(authentication_sha256_hex),
            EbicsPublicKeyDigest(encryption_sha256_hex),
            _oob_token=_OOB_IDENTITY_TOKEN,
        )


class BankKeyRole(str, Enum):
    """The two bank key roles transported by HPB in H005."""

    AUTHENTICATION = "authentication"
    ENCRYPTION = "encryption"


@dataclass(frozen=True, slots=True, init=False)
class ValidatedBankCertificate:
    """Strictly parsed profile metadata; validity does not imply trust."""

    role: BankKeyRole = field(init=False)
    certificate_der: bytes = field(repr=False, init=False)
    certificate_fingerprint: CertificateFingerprint = field(init=False)
    ebics_public_key_digest: EbicsPublicKeyDigest = field(init=False)
    rsa_key_size: int = field(init=False)

    def __init__(
        self,
        role: BankKeyRole,
        certificate_der: bytes,
        rsa_key_size: int,
        *,
        _validation_token: object | None = None,
    ) -> None:
        if _validation_token is not _CERTIFICATE_VALIDATION_TOKEN:
            raise TypeError(
                "validated bank certificates are created only by a certificate profile"
            )
        certificate = bytes(certificate_der)
        object.__setattr__(self, "role", role)
        object.__setattr__(self, "certificate_der", certificate)
        object.__setattr__(self, "rsa_key_size", rsa_key_size)
        object.__setattr__(
            self,
            "certificate_fingerprint",
            CertificateFingerprint.from_der(certificate),
        )
        object.__setattr__(
            self,
            "ebics_public_key_digest",
            EbicsPublicKeyDigest.from_h005_certificate_der(certificate),
        )


@dataclass(frozen=True, slots=True, init=False)
class UntrustedBankKeys:
    """Validated HPB certificates that remain unusable before OOB acceptance."""

    authentication: ValidatedBankCertificate = field(repr=False, init=False)
    encryption: ValidatedBankCertificate = field(repr=False, init=False)

    def __init__(
        self,
        authentication: ValidatedBankCertificate,
        encryption: ValidatedBankCertificate,
        *,
        _validation_token: object | None = None,
    ) -> None:
        if _validation_token is not _CERTIFICATE_VALIDATION_TOKEN:
            raise TypeError("HPB candidates require strict certificate validation")
        if authentication.role is not BankKeyRole.AUTHENTICATION:
            raise ConfigurationError("authentication certificate has the wrong role")
        if encryption.role is not BankKeyRole.ENCRYPTION:
            raise ConfigurationError("encryption certificate has the wrong role")
        object.__setattr__(self, "authentication", authentication)
        object.__setattr__(self, "encryption", encryption)


@dataclass(frozen=True, slots=True, init=False)
class TrustedBankKeys:
    """Bank keys returned only after explicit out-of-band digest acceptance."""

    authentication: ValidatedBankCertificate = field(repr=False, init=False)
    encryption: ValidatedBankCertificate = field(repr=False, init=False)
    accepted_identity: AcceptedBankKeyIdentity = field(init=False)

    def __init__(
        self,
        authentication: ValidatedBankCertificate,
        encryption: ValidatedBankCertificate,
        accepted_identity: AcceptedBankKeyIdentity,
        *,
        _creation_token: object | None = None,
    ) -> None:
        if _creation_token is not _TRUST_CREATION_TOKEN:
            raise TypeError(
                "trusted bank keys are created only by explicit OOB acceptance"
            )
        object.__setattr__(self, "authentication", authentication)
        object.__setattr__(self, "encryption", encryption)
        object.__setattr__(self, "accepted_identity", accepted_identity)

    @classmethod
    def accept_out_of_band(
        cls,
        candidate: UntrustedBankKeys,
        expected: AcceptedBankKeyIdentity,
    ) -> TrustedBankKeys:
        """Create trusted keys only through an explicit EBICS-digest comparison."""

        if not isinstance(candidate, UntrustedBankKeys):
            raise TypeError("candidate must be UntrustedBankKeys")
        if not isinstance(expected, AcceptedBankKeyIdentity):
            raise TypeError("expected must be AcceptedBankKeyIdentity")
        if not (
            hmac.compare_digest(
                candidate.authentication.ebics_public_key_digest.sha256_hex.encode(
                    "ascii"
                ),
                expected.authentication.sha256_hex.encode("ascii"),
            )
            and hmac.compare_digest(
                candidate.encryption.ebics_public_key_digest.sha256_hex.encode("ascii"),
                expected.encryption.sha256_hex.encode("ascii"),
            )
        ):
            raise BankKeyMismatchError("bank-key identities do not match OOB values")
        return cls(
            candidate.authentication,
            candidate.encryption,
            expected,
            _creation_token=_TRUST_CREATION_TOKEN,
        )


@dataclass(frozen=True, slots=True)
class InitializationLetter:
    """Printable initialization-letter data generated for INI or HIA."""

    order: OrderType
    content: bytes = field(repr=False)
    public_key_digests: tuple[EbicsPublicKeyDigest, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.order, OrderType):
            raise TypeError("initialization letter order must be an OrderType")
        if self.order not in {OrderType.INI, OrderType.HIA}:
            raise ConfigurationError("initialization letter order must be INI or HIA")
        object.__setattr__(self, "content", bytes(self.content))
        object.__setattr__(self, "public_key_digests", tuple(self.public_key_digests))
        if not all(
            isinstance(value, EbicsPublicKeyDigest) for value in self.public_key_digests
        ):
            raise TypeError(
                "public_key_digests must contain EbicsPublicKeyDigest values"
            )
        if not self.content or not self.public_key_digests:
            raise ConfigurationError(
                "initialization letter content and public-key digests are required"
            )


@dataclass(frozen=True, slots=True)
class DownloadedDocument:
    """Small verified result referring to bytes atomically committed by a sink."""

    staging_id: DocumentStagingId = field(repr=False)
    provenance: RetrievalProvenance
    content_sha256: ContentSha256
    size_bytes: int
    sink_reference: DocumentReference = field(repr=False)
    zip_members: tuple[ZipMemberIdentity, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.staging_id, DocumentStagingId):
            raise TypeError("staging_id must be a DocumentStagingId")
        if not isinstance(self.provenance, RetrievalProvenance):
            raise TypeError("provenance must be RetrievalProvenance")
        if not isinstance(self.content_sha256, ContentSha256):
            raise TypeError("content_sha256 must be ContentSha256")
        if type(self.size_bytes) is not int or self.size_bytes <= 0:
            raise ConfigurationError("size_bytes must be a positive integer")
        if not isinstance(self.sink_reference, DocumentReference):
            raise TypeError("sink_reference must be a DocumentReference")
        object.__setattr__(self, "zip_members", tuple(self.zip_members))
        if not all(isinstance(value, ZipMemberIdentity) for value in self.zip_members):
            raise TypeError("zip_members must contain ZipMemberIdentity values")


@dataclass(frozen=True, slots=True)
class StagedDocument:
    """Verified plaintext held unpublished until receipt acknowledgement."""

    staging_id: DocumentStagingId = field(repr=False)
    provenance: RetrievalProvenance
    content_sha256: ContentSha256
    size_bytes: int
    zip_members: tuple[ZipMemberIdentity, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.staging_id, DocumentStagingId):
            raise TypeError("staging_id must be a DocumentStagingId")
        if not isinstance(self.provenance, RetrievalProvenance):
            raise TypeError("provenance must be RetrievalProvenance")
        if not isinstance(self.content_sha256, ContentSha256):
            raise TypeError("content_sha256 must be ContentSha256")
        if type(self.size_bytes) is not int or self.size_bytes <= 0:
            raise ConfigurationError("size_bytes must be a positive integer")
        object.__setattr__(self, "zip_members", tuple(self.zip_members))
        if not all(isinstance(value, ZipMemberIdentity) for value in self.zip_members):
            raise TypeError("zip_members must contain ZipMemberIdentity values")


@dataclass(frozen=True, slots=True)
class ContentSha256:
    """SHA-256 content identity for deduplication without retaining bytes."""

    sha256_hex: str

    def __post_init__(self) -> None:
        if _SHA256_HEX.fullmatch(self.sha256_hex) is None:
            raise ConfigurationError(
                "content SHA-256 must be 64 uppercase hex characters"
            )

    @classmethod
    def from_bytes(cls, content: bytes) -> ContentSha256:
        if not isinstance(content, bytes):
            raise TypeError("content must be bytes")
        return cls(sha256(content).hexdigest().upper())


@dataclass(frozen=True, slots=True)
class ZipMemberIdentity:
    """Sanitized ZIP identity: stable index and hashes, never an unsafe path."""

    index: int
    name_sha256: ContentSha256
    content_sha256: ContentSha256
    size_bytes: int

    def __post_init__(self) -> None:
        if type(self.index) is not int or self.index < 0:
            raise ConfigurationError("ZIP member index must be non-negative")
        if not isinstance(self.name_sha256, ContentSha256) or not isinstance(
            self.content_sha256, ContentSha256
        ):
            raise TypeError("ZIP identities must use ContentSha256 values")
        if type(self.size_bytes) is not int or self.size_bytes < 0:
            raise ConfigurationError("ZIP member size must be non-negative")


@dataclass(frozen=True, slots=True)
class RetrievalProvenance:
    """Verified protocol and descriptor metadata attached to a committed document."""

    descriptor: BtfDescriptor
    protocol: NegotiatedProtocol
    retrieved_at: datetime
    transaction_id_sha256: ContentSha256
    segment_count: int
    bank_host_id: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.descriptor, BtfDescriptor):
            raise TypeError("descriptor must be BtfDescriptor")
        if not isinstance(self.protocol, NegotiatedProtocol):
            raise TypeError("protocol must be NegotiatedProtocol")
        if self.retrieved_at.tzinfo is None or self.retrieved_at.utcoffset() is None:
            raise ConfigurationError("retrieved_at must be timezone-aware")
        if not isinstance(self.transaction_id_sha256, ContentSha256):
            raise TypeError("transaction_id_sha256 must be ContentSha256")
        if type(self.segment_count) is not int or self.segment_count <= 0:
            raise ConfigurationError("segment_count must be positive")
        _require_identifier("bank_host_id", self.bank_host_id)


@dataclass(frozen=True, slots=True)
class SessionLease:
    """Exclusive caller-store lease used with compare-and-swap session updates."""

    session_id: str = field(repr=False)
    owner_token: bytes = field(repr=False)
    expires_at: datetime

    def __post_init__(self) -> None:
        _require_identifier("session_id", self.session_id)
        token = bytes(self.owner_token)
        if len(token) < 16:
            raise ConfigurationError("lease owner token must contain at least 16 bytes")
        object.__setattr__(self, "owner_token", token)
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ConfigurationError("lease expiry must be timezone-aware")


@dataclass(frozen=True, slots=True)
class SegmentReference:
    """Opaque reference to sensitive partial ciphertext in caller-controlled storage."""

    value: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not self.value or len(self.value) > 256:
            raise ConfigurationError("segment reference must be bounded text")
