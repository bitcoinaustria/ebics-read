"""EBICSMIT exception hierarchy."""


class EbicsmitError(Exception):
    """Base exception for the EBICSMIT library."""


class OrderNotAllowedError(EbicsmitError):
    """Raised when a request is outside the explicit retrieval policy."""
