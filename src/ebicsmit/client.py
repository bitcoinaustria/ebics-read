"""Read-only client orchestration."""

from dataclasses import dataclass

from .models import DownloadRequest, DownloadResult
from .policy import ReadOnlyPolicy
from .transport import DownloadTransport


@dataclass(frozen=True, slots=True)
class ReadOnlyClient:
    """Dispatch approved downloads through a download-only transport."""

    transport: DownloadTransport
    policy: ReadOnlyPolicy

    def download(self, request: DownloadRequest) -> DownloadResult:
        """Validate and execute one explicitly approved download request."""

        self.policy.ensure_download_allowed(request.kind)
        return self.transport.download(request)
