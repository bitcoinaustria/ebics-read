"""HTTPS-only, bounded transport boundary with redirects disabled."""

from __future__ import annotations

import ssl
from dataclasses import dataclass, field
from http.client import HTTPResponse
from math import isfinite
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    Request,
    build_opener,
)

from .errors import ResponseLimitError, TransportError
from .models import Bank


@dataclass(frozen=True, slots=True)
class TransportResponse:
    """Bounded response bytes; headers are intentionally not exposed."""

    body: bytes = field(repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "body", bytes(self.body))


class TransportRequest(Protocol):
    """Read-only view received by caller-supplied transport implementations."""

    @property
    def bank(self) -> Bank:
        """Return the configured bank for this internally prepared request."""

    @property
    def body(self) -> bytes:
        """Return the internally constructed EBICS envelope."""


@dataclass(frozen=True, slots=True)
class _PreparedTransportRequest:
    bank: Bank = field(repr=False)
    body: bytes = field(repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "body", bytes(self.body))
        if not self.body:
            raise TransportError("request body must not be empty")


def _prepare_transport_request(bank: Bank, request_xml: bytes) -> TransportRequest:
    """Internal protocol-core factory; intentionally absent from the public API."""

    return _PreparedTransportRequest(bank, request_xml)


class EbicsTransport(Protocol):
    """Injected HTTP exchange for internally constructed EBICS envelopes."""

    def exchange(self, request: TransportRequest) -> TransportResponse:
        """POST one internal envelope to the configured bank endpoint."""


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(  # type: ignore[no-untyped-def]
        self, req, fp, code, msg, headers, newurl
    ):
        raise TransportError("redirects are forbidden")


@dataclass(frozen=True, slots=True)
class HttpsTransport:
    """Default HTTPS transport: verified TLS 1.2+, no redirects, bounded body."""

    timeout_seconds: float = 30.0
    max_response_bytes: int = 16 * 1024 * 1024
    _ssl_context: ssl.SSLContext = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if isinstance(self.timeout_seconds, bool) or not isinstance(
            self.timeout_seconds, (int, float)
        ):
            raise TypeError("timeout_seconds must be a finite number")
        if not isfinite(self.timeout_seconds):
            raise ValueError("timeout_seconds must be finite")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if type(self.max_response_bytes) is not int:
            raise TypeError("max_response_bytes must be an integer")
        if self.max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        object.__setattr__(self, "_ssl_context", context)

    def exchange(self, request: TransportRequest) -> TransportResponse:
        if not isinstance(request, _PreparedTransportRequest):
            raise TransportError(
                "transport requests must be prepared by the protocol core"
            )
        http_request = Request(
            request.bank.endpoint,
            data=request.body,
            headers={"Content-Type": "text/xml; charset=utf-8"},
            method="POST",
        )
        opener = build_opener(
            _RejectRedirects(), HTTPSHandler(context=self._ssl_context)
        )
        try:
            with opener.open(http_request, timeout=self.timeout_seconds) as response:
                return TransportResponse(self._read_bounded(response))
        except ResponseLimitError:
            raise
        except TransportError:
            raise
        except HTTPError as exc:
            raise TransportError("bank returned an HTTP error") from exc
        except (URLError, TimeoutError, ssl.SSLError, OSError) as exc:
            raise TransportError("HTTPS exchange failed") from exc

    def _read_bounded(self, response: HTTPResponse) -> bytes:
        declared = response.headers.get("Content-Length")
        if declared is not None:
            try:
                declared_size = int(declared)
            except ValueError as exc:
                raise TransportError("invalid Content-Length") from exc
            if declared_size < 0 or declared_size > self.max_response_bytes:
                raise ResponseLimitError("response exceeds configured byte limit")
        chunks: list[bytes] = []
        received = 0
        while received <= self.max_response_bytes:
            chunk = response.read(
                min(64 * 1024, self.max_response_bytes + 1 - received)
            )
            if not chunk:
                break
            chunks.append(bytes(chunk))
            received += len(chunk)
        if received > self.max_response_bytes:
            raise ResponseLimitError("response exceeds configured byte limit")
        return b"".join(chunks)
