"""Public surface for the structurally read-only EBICSMIT scaffold."""

from .client import ReadOnlyClient
from .errors import EbicsmitError, OrderNotAllowedError
from .models import DownloadRequest, DownloadResult, RetrievalKind
from .policy import ExplicitReadOnlyPolicy
from .transport import DownloadTransport

__all__ = [
    "DownloadRequest",
    "DownloadResult",
    "DownloadTransport",
    "EbicsmitError",
    "ExplicitReadOnlyPolicy",
    "OrderNotAllowedError",
    "ReadOnlyClient",
    "RetrievalKind",
]
