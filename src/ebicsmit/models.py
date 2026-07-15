"""Immutable, typed values accepted or returned by the public API."""

from __future__ import annotations

import hmac
import re
from dataclasses import dataclass, field
from datetime import date
from enum import Enum
from hashlib import sha256
from urllib.parse import urlsplit

from .errors import BankKeyMismatchError, ConfigurationError
from .orders import DISCOVERY_ORDERS, OrderType

_PROTOCOL_FIELD_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,63}$")
_IBAN = re.compile(r"^[A-Z]{2}[0-9A-Z]{13,32}$")
_CURRENCY = re.compile(r"^[A-Z]{3}$")
_FINGERPRINT = re.compile(r"^[0-9A-F]{64}$")
_TRUST_CREATION_TOKEN = object()
_SESSION_CREATION_TOKEN = object()


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
    """BTD states; terminal failures cannot be resumed."""

    NEW = "new"
    INITIALIZED = "initialized"
    TRANSFERRING = "transferring"
    COMPLETE = "complete"
    RECEIPT_SENT = "receipt_sent"
    VERIFIED = "verified"
    FAILED = "failed"


@dataclass(frozen=True, slots=True, init=False)
class DownloadSession:
    """Immutable BTD state constructible only through validated transitions."""

    session_id: str = field(repr=False, init=False)
    phase: DownloadPhase = field(init=False)
    transaction_id: str | None = field(default=None, repr=False)
    next_segment: int = field(init=False)
    total_segments: int | None = field(init=False)

    def __init__(
        self,
        session_id: str,
        phase: DownloadPhase,
        transaction_id: str | None,
        next_segment: int,
        total_segments: int | None,
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
        _require_identifier("session_id", self.session_id)
        if not isinstance(self.phase, DownloadPhase):
            raise TypeError("phase must be a DownloadPhase")
        if self.transaction_id is not None:
            _require_identifier("transaction_id", self.transaction_id)
        if type(self.next_segment) is not int:
            raise TypeError("next_segment must be an integer")
        if self.next_segment <= 0:
            raise ConfigurationError("next_segment must be positive")
        if self.total_segments is not None:
            if type(self.total_segments) is not int:
                raise TypeError("total_segments must be an integer")
            if self.total_segments <= 0:
                raise ConfigurationError("total_segments must be positive")
            if self.next_segment > self.total_segments + 1:
                raise ConfigurationError("next_segment exceeds transaction bounds")
        self._validate_coherence()

    @classmethod
    def _create(
        cls,
        session_id: str,
        phase: DownloadPhase,
        transaction_id: str | None,
        next_segment: int,
        total_segments: int | None,
    ) -> DownloadSession:
        return cls(
            session_id,
            phase,
            transaction_id,
            next_segment,
            total_segments,
            _creation_token=_SESSION_CREATION_TOKEN,
        )

    @classmethod
    def start(cls, session_id: str) -> DownloadSession:
        """Start a transaction before a bank transaction ID exists."""

        return cls._create(session_id, DownloadPhase.NEW, None, 1, None)

    @classmethod
    def restore(
        cls,
        *,
        session_id: str,
        phase: DownloadPhase,
        transaction_id: str | None,
        next_segment: int,
        total_segments: int | None,
    ) -> DownloadSession:
        """Restore host-persisted state after applying every invariant."""

        return cls._create(
            session_id, phase, transaction_id, next_segment, total_segments
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
        )

    def record_segment(self, segment_number: int) -> DownloadSession:
        """Advance only for the exact next authenticated segment."""

        if type(segment_number) is not int:
            raise TypeError("segment_number must be an integer")
        if self.phase not in {DownloadPhase.INITIALIZED, DownloadPhase.TRANSFERRING}:
            raise ConfigurationError("segments are not accepted in this phase")
        if segment_number != self.next_segment:
            raise ConfigurationError("segment is missing, duplicate, or reordered")
        if self.total_segments is None or self.transaction_id is None:
            raise ConfigurationError("initialized transaction metadata is missing")
        next_segment = segment_number + 1
        phase = (
            DownloadPhase.COMPLETE
            if segment_number == self.total_segments
            else DownloadPhase.TRANSFERRING
        )
        return self._create(
            self.session_id,
            phase,
            self.transaction_id,
            next_segment,
            self.total_segments,
        )

    def mark_receipt_sent(self) -> DownloadSession:
        """Record successful protocol receipt transmission."""

        self._require_phase(DownloadPhase.COMPLETE)
        return self._with_phase(DownloadPhase.RECEIPT_SENT)

    def mark_verified(self) -> DownloadSession:
        """Mark a response fully authenticated only after the receipt."""

        self._require_phase(DownloadPhase.RECEIPT_SENT)
        return self._with_phase(DownloadPhase.VERIFIED)

    def fail(self) -> DownloadSession:
        """Enter terminal failure from a non-terminal state."""

        if self.phase in {DownloadPhase.VERIFIED, DownloadPhase.FAILED}:
            raise ConfigurationError("terminal download session cannot be reused")
        return self._with_phase(DownloadPhase.FAILED)

    def _with_phase(self, phase: DownloadPhase) -> DownloadSession:
        return self._create(
            self.session_id,
            phase,
            self.transaction_id,
            self.next_segment,
            self.total_segments,
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
            ):
                raise ConfigurationError("new session contains transaction state")
            return
        if self.phase is DownloadPhase.FAILED and self.transaction_id is None:
            if self.total_segments is not None or self.next_segment != 1:
                raise ConfigurationError(
                    "failed pre-initialization state is incoherent"
                )
            return
        if self.transaction_id is None or self.total_segments is None:
            raise ConfigurationError("active session lacks transaction metadata")
        finished = self.next_segment == self.total_segments + 1
        if self.phase is DownloadPhase.INITIALIZED and self.next_segment != 1:
            raise ConfigurationError("initialized session must begin at segment one")
        if self.phase is DownloadPhase.TRANSFERRING and self.next_segment < 2:
            raise ConfigurationError("transferring session has no recorded segment")
        if (
            self.phase
            in {
                DownloadPhase.COMPLETE,
                DownloadPhase.RECEIPT_SENT,
                DownloadPhase.VERIFIED,
            }
            and not finished
        ):
            raise ConfigurationError("completed session has missing segments")
        if (
            self.phase
            in {
                DownloadPhase.INITIALIZED,
                DownloadPhase.TRANSFERRING,
            }
            and finished
        ):
            raise ConfigurationError("active session has no remaining segment")


@dataclass(frozen=True, slots=True)
class ProtocolVersion:
    """One protocol version advertised by HEV."""

    protocol_version: str
    version_number: str

    def __post_init__(self) -> None:
        _require_token("protocol_version", self.protocol_version)
        _require_token("version_number", self.version_number)


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
class KeyFingerprint:
    """A SHA-256 certificate fingerprint in printable EBICS letter form."""

    sha256_hex: str

    def __post_init__(self) -> None:
        if _FINGERPRINT.fullmatch(self.sha256_hex) is None:
            raise ConfigurationError(
                "fingerprint must be 64 uppercase hexadecimal characters"
            )

    @classmethod
    def from_certificate(cls, certificate_der: bytes) -> KeyFingerprint:
        if not certificate_der:
            raise ConfigurationError("certificate DER must not be empty")
        return cls(sha256(bytes(certificate_der)).hexdigest().upper())


@dataclass(frozen=True, slots=True)
class BankKeyFingerprints:
    authentication: KeyFingerprint
    encryption: KeyFingerprint

    def __post_init__(self) -> None:
        if not isinstance(self.authentication, KeyFingerprint) or not isinstance(
            self.encryption, KeyFingerprint
        ):
            raise TypeError("bank-key fingerprints must be KeyFingerprint values")


@dataclass(frozen=True, slots=True)
class UntrustedBankKeys:
    """HPB key material that must not authenticate any response yet."""

    authentication_certificate_der: bytes = field(repr=False)
    encryption_certificate_der: bytes = field(repr=False)
    fingerprints: BankKeyFingerprints = field(init=False)

    def __post_init__(self) -> None:
        authentication = bytes(self.authentication_certificate_der)
        encryption = bytes(self.encryption_certificate_der)
        object.__setattr__(self, "authentication_certificate_der", authentication)
        object.__setattr__(self, "encryption_certificate_der", encryption)
        object.__setattr__(
            self,
            "fingerprints",
            BankKeyFingerprints(
                authentication=KeyFingerprint.from_certificate(authentication),
                encryption=KeyFingerprint.from_certificate(encryption),
            ),
        )


@dataclass(frozen=True, slots=True, init=False)
class TrustedBankKeys:
    """Bank keys returned only after explicit out-of-band fingerprint acceptance."""

    authentication_certificate_der: bytes = field(repr=False, init=False)
    encryption_certificate_der: bytes = field(repr=False, init=False)
    fingerprints: BankKeyFingerprints

    def __init__(
        self,
        authentication_certificate_der: bytes,
        encryption_certificate_der: bytes,
        fingerprints: BankKeyFingerprints,
        *,
        _creation_token: object | None = None,
    ) -> None:
        if _creation_token is not _TRUST_CREATION_TOKEN:
            raise TypeError(
                "trusted bank keys are created only by explicit OOB acceptance"
            )
        object.__setattr__(
            self,
            "authentication_certificate_der",
            bytes(authentication_certificate_der),
        )
        object.__setattr__(
            self, "encryption_certificate_der", bytes(encryption_certificate_der)
        )
        object.__setattr__(self, "fingerprints", fingerprints)

    @classmethod
    def accept_out_of_band(
        cls,
        candidate: UntrustedBankKeys,
        expected: BankKeyFingerprints,
    ) -> TrustedBankKeys:
        """Create trusted keys only through an explicit fingerprint comparison."""

        actual = candidate.fingerprints
        if not (
            hmac.compare_digest(
                actual.authentication.sha256_hex.encode("ascii"),
                expected.authentication.sha256_hex.encode("ascii"),
            )
            and hmac.compare_digest(
                actual.encryption.sha256_hex.encode("ascii"),
                expected.encryption.sha256_hex.encode("ascii"),
            )
        ):
            raise BankKeyMismatchError("bank-key fingerprints do not match OOB values")
        return cls(
            candidate.authentication_certificate_der,
            candidate.encryption_certificate_der,
            actual,
            _creation_token=_TRUST_CREATION_TOKEN,
        )


@dataclass(frozen=True, slots=True)
class InitializationLetter:
    """Printable initialization-letter data generated for INI or HIA."""

    order: OrderType
    content: bytes = field(repr=False)
    fingerprints: tuple[KeyFingerprint, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.order, OrderType):
            raise TypeError("initialization letter order must be an OrderType")
        if self.order not in {OrderType.INI, OrderType.HIA}:
            raise ConfigurationError("initialization letter order must be INI or HIA")
        object.__setattr__(self, "content", bytes(self.content))
        object.__setattr__(self, "fingerprints", tuple(self.fingerprints))
        if not all(isinstance(value, KeyFingerprint) for value in self.fingerprints):
            raise TypeError("fingerprints must contain KeyFingerprint values")
        if not self.content or not self.fingerprints:
            raise ConfigurationError(
                "initialization letter content and fingerprints are required"
            )


@dataclass(frozen=True, slots=True)
class DownloadedDocument:
    """Verified opaque document bytes and trustworthy BTF metadata."""

    service_name: str
    message_name: str
    message_version: str
    variant: str
    format: str
    service_option: str
    container_type: ContainerType
    content: bytes = field(repr=False)
    scope: str | None = None

    def __post_init__(self) -> None:
        descriptor = BtfDescriptor(
            service_name=self.service_name,
            scope=self.scope,
            message_name=self.message_name,
            message_version=self.message_version,
            variant=self.variant,
            format=self.format,
            service_option=self.service_option,
            container_type=self.container_type,
        )
        object.__setattr__(self, "content", bytes(self.content))
        if not self.content:
            raise ConfigurationError("downloaded document content must not be empty")
        del descriptor
