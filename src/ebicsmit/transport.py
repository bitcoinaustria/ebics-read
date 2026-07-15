"""Download-only transport boundary."""

from typing import Protocol

from .models import DownloadRequest, DownloadResult


class DownloadTransport(Protocol):
    """A transport capable only of bank-to-customer downloads."""

    def download(self, request: DownloadRequest) -> DownloadResult:
        """Execute an already policy-approved download."""
