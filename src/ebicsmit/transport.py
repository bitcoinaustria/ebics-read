"""HTTPS-only, bounded transport boundary with redirects disabled."""

from __future__ import annotations

import ssl
from dataclasses import dataclass, field
from http.client import HTTPResponse
from math import isfinite
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from lxml import etree

from .errors import (
    AmbiguousTransportError,
    OperationDeadlineError,
    ResponseLimitError,
    TransportError,
)
from .interfaces import Clock, OperationControl
from .models import Bank
from .orders import OrderType

_HEV_NAMESPACE = "http://www.ebics.org/H000"


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

    @property
    def order(self) -> OrderType:
        """Return the fixed allowlisted operation represented by the envelope."""


@dataclass(frozen=True, slots=True, init=False)
class _PreparedTransportRequest:
    bank: Bank = field(repr=False, init=False)
    body: bytes = field(repr=False, init=False)
    order: OrderType = field(init=False)

    def __init__(self) -> None:
        raise TypeError("transport requests require an operation-specific builder")

    @classmethod
    def _for_hev(cls, bank: Bank) -> _PreparedTransportRequest:
        """Build the only currently implemented request shape: exact HEV/H000."""

        root = etree.Element(
            etree.QName(_HEV_NAMESPACE, "ebicsHEVRequest"),
            nsmap={None: _HEV_NAMESPACE},  # type: ignore[dict-item]
        )
        host_id = etree.SubElement(root, etree.QName(_HEV_NAMESPACE, "HostID"))
        host_id.text = bank.host_id
        body = etree.tostring(root, encoding="UTF-8", xml_declaration=True)
        request = object.__new__(cls)
        object.__setattr__(request, "bank", bank)
        object.__setattr__(request, "body", body)
        object.__setattr__(request, "order", OrderType.HEV)
        return request


class EbicsTransport(Protocol):
    """Injected HTTP exchange for internally constructed EBICS envelopes."""

    def exchange(
        self, request: TransportRequest, control: OperationControl
    ) -> TransportResponse:
        """POST one internal envelope to the configured bank endpoint."""


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(  # type: ignore[no-untyped-def]
        self, req, fp, code, msg, headers, newurl
    ):
        raise TransportError("redirects are forbidden")


@dataclass(frozen=True, slots=True)
class ProxyConfiguration:
    """Explicit unauthenticated HTTP CONNECT proxy; never inferred from environment."""

    url: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.url, str):
            raise TypeError("proxy URL must be text")
        parts = urlsplit(self.url)
        if (
            parts.scheme not in {"http", "https"}
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
        ):
            raise ValueError(
                "proxy URL must be HTTP(S) without credentials, query, or fragment"
            )


@dataclass(frozen=True, slots=True)
class HttpsTransport:
    """Default HTTPS transport: verified TLS 1.2+, no redirects, bounded body."""

    clock: Clock = field(repr=False)
    timeout_seconds: float = 30.0
    max_response_bytes: int = 16 * 1024 * 1024
    proxy: ProxyConfiguration | None = field(default=None, repr=False)
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
        if self.proxy is not None and not isinstance(self.proxy, ProxyConfiguration):
            raise TypeError("proxy must be ProxyConfiguration")
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        object.__setattr__(self, "_ssl_context", context)

    def exchange(
        self, request: TransportRequest, control: OperationControl
    ) -> TransportResponse:
        if not isinstance(request, _PreparedTransportRequest):
            raise TransportError(
                "transport requests must be prepared by the protocol core"
            )
        timeout = self._remaining_timeout(control)
        http_request = Request(
            request.bank.endpoint,
            data=request.body,
            headers={"Content-Type": "text/xml; charset=utf-8"},
            method="POST",
        )
        opener = build_opener(
            self._proxy_handler(),
            _RejectRedirects(),
            HTTPSHandler(context=self._ssl_context),
        )
        try:
            with opener.open(http_request, timeout=timeout) as response:
                result = TransportResponse(self._read_bounded(response, control))
                self._remaining_timeout(control)
                return result
        except ResponseLimitError:
            raise
        except TransportError:
            raise
        except HTTPError as exc:
            raise TransportError("bank returned an HTTP error") from exc
        except URLError as exc:
            if isinstance(exc.reason, ssl.SSLError):
                raise TransportError("HTTPS validation failed") from exc
            raise AmbiguousTransportError(
                "HTTPS exchange ended with unknown delivery status"
            ) from exc
        except ssl.SSLError as exc:
            raise TransportError("HTTPS exchange failed") from exc
        except (TimeoutError, OSError) as exc:
            raise AmbiguousTransportError(
                "HTTPS exchange ended with unknown delivery status"
            ) from exc

    def _read_bounded(self, response: HTTPResponse, control: OperationControl) -> bytes:
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
            remaining = self._remaining_timeout(control)
            self._set_read_timeout(response, remaining)
            reader = getattr(response, "read1", response.read)
            chunk = reader(min(64 * 1024, self.max_response_bytes + 1 - received))
            if not chunk:
                break
            chunks.append(bytes(chunk))
            received += len(chunk)
        if received > self.max_response_bytes:
            raise ResponseLimitError("response exceeds configured byte limit")
        return b"".join(chunks)

    @staticmethod
    def _set_read_timeout(response: HTTPResponse, timeout: float) -> None:
        """Cap each urllib response read to the remaining operation deadline."""

        fp = getattr(response, "fp", None)
        raw = getattr(fp, "raw", None)
        sock = getattr(raw, "_sock", None)
        setter = getattr(sock, "settimeout", None)
        if not callable(setter):
            raise TransportError("response stream cannot enforce operation deadline")
        setter(timeout)

    def _proxy_handler(self) -> ProxyHandler:
        if self.proxy is None:
            return ProxyHandler({})
        return ProxyHandler({"https": self.proxy.url})

    def _remaining_timeout(self, control: OperationControl) -> float:
        control.raise_if_cancelled()
        now = self.clock.now()
        deadline = control.deadline
        if (
            now.tzinfo is None
            or now.utcoffset() is None
            or deadline.tzinfo is None
            or deadline.utcoffset() is None
        ):
            raise OperationDeadlineError("clock and operation deadline must be aware")
        remaining = (deadline - now).total_seconds()
        if remaining <= 0:
            raise OperationDeadlineError("operation deadline has expired")
        return min(float(self.timeout_seconds), remaining)
