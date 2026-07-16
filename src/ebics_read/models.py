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
_IBAN = re.compile(r"^[A-Z]{2}[0-9A-Z]{13,32}$")
_CURRENCY = re.compile(r"^[A-Z]{3}$")
_SHA256_HEX = re.compile(r"^[0-9A-F]{64}$")
_PROTOCOL_VERSION = re.compile(r"^H[0-9]{3}$")
_VERSION_NUMBER = re.compile(r"^[0-9]{2}\.[0-9]{2}$")
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


@dataclass(frozen=True, slots=True)
class Bank:
    """A caller-supplied bank endpoint and EBICS host identifier."""

    endpoint: str = field(repr=False)
    host_id: str = field(repr=False)

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


@dataclass(frozen=True, slots=True)
class Subscriber:
    """Bank-issued participant identifiers; deliberately hidden from repr."""

    partner_id: str = field(repr=False)
    user_id: str = field(repr=False)
    system_id: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        _require_identifier("partner_id", self.partner_id)
        _require_identifier("user_id", self.user_id)
        if self.system_id is not None:
            _require_identifier("system_id", self.system_id)


class ContainerType(str, Enum):
    """Container handling requested for a BTF download."""

    NONE = "NONE"
    ZIP = "ZIP"


@dataclass(frozen=True, slots=True)
class BtfDescriptor:
    """Complete caller-supplied BTF service descriptor for BTD."""

    service_name: str
    message_name: str
    message_version: str
    variant: str
    format: str
    service_option: str
    container_type: ContainerType
    scope: str | None = None

    def __post_init__(self) -> None:
        _require_token("service_name", self.service_name)
        _require_token("message_name", self.message_name)
        _require_token("message_version", self.message_version)
        _require_token("variant", self.variant)
        _require_token("format", self.format)
        _require_token("service_option", self.service_option)
        if self.scope is not None:
            _require_token("scope", self.scope)
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
        if self.iban is not None and _IBAN.fullmatch(self.iban) is None:
            raise ConfigurationError(
                "iban must be an uppercase, structurally valid IBAN token"
            )
        if self.account_id is not None:
            _require_identifier("account_id", self.account_id)
        if self.currency is not None and _CURRENCY.fullmatch(self.currency) is None:
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
    POSITIVE_RECEIPT_SENT = "positive_receipt_sent"
    NEGATIVE_RECEIPT_SENT = "negative_receipt_sent"
    RECEIPT_RESPONSE_VERIFIED = "receipt_response_verified"
    RECEIPT_AMBIGUOUS = "receipt_ambiguous"
    COMPLETE = "complete"
    NEGATIVE_COMPLETE = "negative_complete"
    FAILED = "failed"


class ReceiptKind(str, Enum):
    """Normative receipt code semantics."""

    POSITIVE = "positive"
    NEGATIVE = "negative"


@dataclass(frozen=True, slots=True, init=False)
class DownloadSession:
    """Immutable BTD state constructible only through validated transitions."""

    session_id: str = field(repr=False, init=False)
    phase: DownloadPhase = field(init=False)
    transaction_id: str | None = field(default=None, repr=False)
    next_segment: int = field(init=False)
    total_segments: int | None = field(init=False)
    max_segments: int = field(init=False)
    revision: int = field(init=False)
    receipt_kind: ReceiptKind | None = field(init=False)

    def __init__(
        self,
        session_id: str,
        phase: DownloadPhase,
        transaction_id: str | None,
        next_segment: int,
        total_segments: int | None,
        max_segments: int,
        revision: int,
        receipt_kind: ReceiptKind | None,
        *,
        _creation_token: object | None = None,
    ) -> None:
        if _creation_token is not _SESSION_CREATION_TOKEN:
            raise TypeError("download sessions are created through state methods")
        object.__setattr__(self, "session_id", session_id)
        object.__setattr__(self, "phase", phase)
        object.__setattr__(self, "transaction_id", transaction_id)
        object.__setattr__(self, "next_segment", next_segment)
        object.__setattr__(self, "total_segments", total_segments)
        object.__setattr__(self, "max_segments", max_segments)
        object.__setattr__(self, "revision", revision)
        object.__setattr__(self, "receipt_kind", receipt_kind)
        _require_identifier("session_id", self.session_id)
        if not isinstance(self.phase, DownloadPhase):
            raise TypeError("phase must be a DownloadPhase")
        if self.transaction_id is not None:
            _require_identifier("transaction_id", self.transaction_id)
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
        self._validate_coherence()

    @classmethod
    def _create(
        cls,
        session_id: str,
        phase: DownloadPhase,
        transaction_id: str | None,
        next_segment: int,
        total_segments: int | None,
        max_segments: int,
        revision: int,
        receipt_kind: ReceiptKind | None,
    ) -> DownloadSession:
        return cls(
            session_id,
            phase,
            transaction_id,
            next_segment,
            total_segments,
            max_segments,
            revision,
            receipt_kind,
            _creation_token=_SESSION_CREATION_TOKEN,
        )

    @classmethod
    def start(cls, session_id: str, limits: ProtocolLimits) -> DownloadSession:
        """Start a transaction before a bank transaction ID exists."""

        if not isinstance(limits, ProtocolLimits):
            raise TypeError("limits must be ProtocolLimits")
        return cls._create(
            session_id,
            DownloadPhase.NEW,
            None,
            1,
            None,
            limits.max_segments,
            0,
            None,
        )

    @classmethod
    def restore(
        cls,
        *,
        session_id: str,
        phase: DownloadPhase,
        transaction_id: str | None,
        next_segment: int,
        total_segments: int | None,
        max_segments: int,
        revision: int,
        receipt_kind: ReceiptKind | None = None,
    ) -> DownloadSession:
        """Restore host-persisted state after applying every invariant."""

        return cls._create(
            session_id,
            phase,
            transaction_id,
            next_segment,
            total_segments,
            max_segments,
            revision,
            receipt_kind,
        )

    def initialize(
        self, *, transaction_id: str, total_segments: int
    ) -> DownloadSession:
        """Accept authenticated initialization metadata."""

        self._require_phase(DownloadPhase.NEW)
        return self._create(
            self.session_id,
            DownloadPhase.INITIALIZED,
            transaction_id,
            1,
            total_segments,
            self.max_segments,
            self.revision + 1,
            None,
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

    def mark_positive_receipt_sent(self) -> DownloadSession:
        """Send code 0 only after the payload is fully acceptable."""

        self._require_phase(DownloadPhase.CONTAINER_VERIFIED)
        return self._advance(
            DownloadPhase.POSITIVE_RECEIPT_SENT,
            receipt_kind=ReceiptKind.POSITIVE,
        )

    def mark_negative_receipt_sent(self) -> DownloadSession:
        """Send code 1 after complete transfer but failed payload processing."""

        if self.phase not in {
            DownloadPhase.SEGMENTS_RECEIVED,
            DownloadPhase.SIGNATURES_AND_DIGESTS_VERIFIED,
            DownloadPhase.DECRYPTED,
        }:
            raise ConfigurationError("negative receipt is not valid in this phase")
        return self._advance(
            DownloadPhase.NEGATIVE_RECEIPT_SENT,
            receipt_kind=ReceiptKind.NEGATIVE,
        )

    def mark_receipt_ambiguous(self) -> DownloadSession:
        """Record an unknown receipt outcome after transmission began."""

        if self.phase not in {
            DownloadPhase.POSITIVE_RECEIPT_SENT,
            DownloadPhase.NEGATIVE_RECEIPT_SENT,
        }:
            raise ConfigurationError("receipt ambiguity requires a sent receipt")
        return self._advance(DownloadPhase.RECEIPT_AMBIGUOUS)

    def mark_receipt_response_verified(self) -> DownloadSession:
        """Record an authenticated response with the expected receipt return code."""

        if self.phase not in {
            DownloadPhase.POSITIVE_RECEIPT_SENT,
            DownloadPhase.NEGATIVE_RECEIPT_SENT,
            DownloadPhase.RECEIPT_AMBIGUOUS,
        }:
            raise ConfigurationError("receipt response is not expected in this phase")
        return self._advance(DownloadPhase.RECEIPT_RESPONSE_VERIFIED)

    def finish(self) -> DownloadSession:
        """Finish only after the receipt response has been authenticated."""

        self._require_phase(DownloadPhase.RECEIPT_RESPONSE_VERIFIED)
        target = (
            DownloadPhase.COMPLETE
            if self.receipt_kind is ReceiptKind.POSITIVE
            else DownloadPhase.NEGATIVE_COMPLETE
        )
        return self._advance(target)

    def fail(self) -> DownloadSession:
        """Enter terminal failure from a non-terminal state."""

        if self.phase in {
            DownloadPhase.POSITIVE_RECEIPT_SENT,
            DownloadPhase.NEGATIVE_RECEIPT_SENT,
            DownloadPhase.RECEIPT_RESPONSE_VERIFIED,
            DownloadPhase.RECEIPT_AMBIGUOUS,
            DownloadPhase.COMPLETE,
            DownloadPhase.NEGATIVE_COMPLETE,
            DownloadPhase.FAILED,
        }:
            raise ConfigurationError("terminal download session cannot be reused")
        return self._advance(DownloadPhase.FAILED)

    def _advance(
        self,
        phase: DownloadPhase,
        *,
        next_segment: int | None = None,
        receipt_kind: ReceiptKind | None = None,
    ) -> DownloadSession:
        return self._create(
            self.session_id,
            phase,
            self.transaction_id,
            self.next_segment if next_segment is None else next_segment,
            self.total_segments,
            self.max_segments,
            self.revision + 1,
            self.receipt_kind if receipt_kind is None else receipt_kind,
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
            ):
                raise ConfigurationError("new session contains transaction state")
            return
        if self.phase is DownloadPhase.FAILED and self.transaction_id is None:
            if (
                self.total_segments is not None
                or self.next_segment != 1
                or self.receipt_kind is not None
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
                DownloadPhase.POSITIVE_RECEIPT_SENT,
                DownloadPhase.NEGATIVE_RECEIPT_SENT,
                DownloadPhase.RECEIPT_RESPONSE_VERIFIED,
                DownloadPhase.RECEIPT_AMBIGUOUS,
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
            DownloadPhase.POSITIVE_RECEIPT_SENT,
            DownloadPhase.NEGATIVE_RECEIPT_SENT,
            DownloadPhase.RECEIPT_RESPONSE_VERIFIED,
            DownloadPhase.RECEIPT_AMBIGUOUS,
            DownloadPhase.COMPLETE,
            DownloadPhase.NEGATIVE_COMPLETE,
        }
        if (self.phase in receipt_phases) != (self.receipt_kind is not None):
            raise ConfigurationError("receipt state and receipt kind disagree")
        if (
            self.phase is DownloadPhase.POSITIVE_RECEIPT_SENT
            and self.receipt_kind is not ReceiptKind.POSITIVE
        ):
            raise ConfigurationError("positive receipt state has wrong receipt kind")
        if (
            self.phase is DownloadPhase.NEGATIVE_RECEIPT_SENT
            and self.receipt_kind is not ReceiptKind.NEGATIVE
        ):
            raise ConfigurationError("negative receipt state has wrong receipt kind")
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
        if self.source_order not in DISCOVERY_ORDERS:
            raise ConfigurationError("capability source must be a discovery order")


@dataclass(frozen=True, slots=True)
class CapabilityDiscovery:
    """Defensive union of supported discovery-order results."""

    services: tuple[ServiceCapability, ...] = ()
    completed_orders: tuple[OrderType, ...] = ()
    unsupported_orders: tuple[OrderType, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "services", tuple(self.services))
        object.__setattr__(self, "completed_orders", tuple(self.completed_orders))
        object.__setattr__(self, "unsupported_orders", tuple(self.unsupported_orders))
        if not all(isinstance(value, ServiceCapability) for value in self.services):
            raise TypeError("services must contain ServiceCapability values")
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

    provenance: RetrievalProvenance
    content_sha256: ContentSha256
    size_bytes: int
    sink_reference: str = field(repr=False)
    zip_members: tuple[ZipMemberIdentity, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.provenance, RetrievalProvenance):
            raise TypeError("provenance must be RetrievalProvenance")
        if not isinstance(self.content_sha256, ContentSha256):
            raise TypeError("content_sha256 must be ContentSha256")
        if type(self.size_bytes) is not int or self.size_bytes <= 0:
            raise ConfigurationError("size_bytes must be a positive integer")
        if (
            not isinstance(self.sink_reference, str)
            or not self.sink_reference
            or len(self.sink_reference) > 256
            or any(ord(value) < 0x20 for value in self.sink_reference)
        ):
            raise ConfigurationError("sink_reference must be bounded printable text")
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
