"""Typed, data-minimizing EBICS Read exception hierarchy."""

from enum import Enum


class EbicsReadError(Exception):
    """Base exception for the EBICS Read library."""


class ConfigurationError(EbicsReadError, ValueError):
    """Raised for invalid immutable configuration or typed request values."""


class OperationNotImplementedError(EbicsReadError, NotImplementedError):
    """Raised for an allowlisted operation not implemented by the backend yet."""


class ProtocolError(EbicsReadError):
    """Raised when an EBICS peer violates the expected protocol."""


class UnknownReturnCodeError(ProtocolError):
    """Raised when an unrecognized EBICS return code is encountered."""


class UnsupportedProtocolVersionError(ProtocolError):
    """Raised when HEV cannot negotiate the exact supported H005 version."""


class SecurityError(ProtocolError):
    """Raised when authenticated or security-sensitive validation fails."""


class BankKeyNotTrustedError(SecurityError):
    """Raised until bank keys are explicitly accepted out of band."""


class BankKeyMismatchError(SecurityError):
    """Raised when presented bank keys do not match accepted OOB identities."""


class CertificateValidationError(SecurityError):
    """Raised when X.509 material violates the selected EBICS profile."""


class ReplayError(SecurityError):
    """Raised for duplicate identifiers, nonces, or replayed responses."""


class XmlSecurityError(SecurityError):
    """Raised when XML crosses a parser or structural security boundary."""


class ResponseLimitError(SecurityError):
    """Raised when a response exceeds a configured resource limit."""


class SegmentError(ProtocolError):
    """Raised for malformed, duplicate, missing, or reordered segments."""


class SessionConflictError(ProtocolError):
    """Raised when a session lease or compare-and-swap precondition fails."""


class OperationDeadlineError(EbicsReadError):
    """Raised before accepting work that cannot finish within the deadline."""


class OperationCancelledError(EbicsReadError):
    """Raised by the default operation control after explicit cancellation."""


class TransportError(EbicsReadError):
    """Raised for TLS, redirect, timeout, or HTTP transport failure."""


class TransientTransportError(TransportError):
    """Raised only when a transport proves no request bytes were sent."""


class AmbiguousTransportError(TransportError):
    """Raised when a request may have reached the bank; never blindly retry."""


class RetryClassification(str, Enum):
    """Host-visible retry safety without exposing protocol payloads."""

    TRANSIENT = "transient"
    AMBIGUOUS = "ambiguous"
    TERMINAL = "terminal"
    SECURITY = "security"


def classify_retry(error: BaseException) -> RetryClassification:
    """Classify only explicit transport interruptions as retryable."""

    if isinstance(error, SecurityError):
        return RetryClassification.SECURITY
    if isinstance(error, TransientTransportError):
        return RetryClassification.TRANSIENT
    if isinstance(error, AmbiguousTransportError):
        return RetryClassification.AMBIGUOUS
    return RetryClassification.TERMINAL
