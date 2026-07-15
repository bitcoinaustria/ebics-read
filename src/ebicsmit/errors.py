"""Typed, data-minimizing EBICSMIT exception hierarchy."""


class EbicsmitError(Exception):
    """Base exception for the EBICSMIT library."""


class ConfigurationError(EbicsmitError, ValueError):
    """Raised for invalid immutable configuration or typed request values."""


class OperationNotImplementedError(EbicsmitError, NotImplementedError):
    """Raised for an allowlisted operation not implemented by the backend yet."""


class ProtocolError(EbicsmitError):
    """Raised when an EBICS peer violates the expected protocol."""


class UnknownReturnCodeError(ProtocolError):
    """Raised when an unrecognized EBICS return code is encountered."""


class SecurityError(ProtocolError):
    """Raised when authenticated or security-sensitive validation fails."""


class BankKeyNotTrustedError(SecurityError):
    """Raised until bank keys are explicitly accepted out of band."""


class BankKeyMismatchError(SecurityError):
    """Raised when presented bank keys do not match accepted fingerprints."""


class ReplayError(SecurityError):
    """Raised for duplicate identifiers, nonces, or replayed responses."""


class XmlSecurityError(SecurityError):
    """Raised when XML crosses a parser or structural security boundary."""


class ResponseLimitError(SecurityError):
    """Raised when a response exceeds a configured resource limit."""


class SegmentError(ProtocolError):
    """Raised for malformed, duplicate, missing, or reordered segments."""


class TransportError(EbicsmitError):
    """Raised for TLS, redirect, timeout, or HTTP transport failure."""
