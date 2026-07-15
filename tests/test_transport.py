from __future__ import annotations

import inspect
import math
import ssl
from email.message import Message

import pytest

from ebicsmit import HttpsTransport, ResponseLimitError, TransportError
from ebicsmit.transport import _RejectRedirects


class FakeResponse:
    def __init__(self, body: bytes, content_length: str | None = None) -> None:
        self._body = body
        self._offset = 0
        self.headers = Message()
        if content_length is not None:
            self.headers["Content-Length"] = content_length

    def read(self, amount: int) -> bytes:
        chunk = self._body[self._offset : self._offset + amount]
        self._offset += len(chunk)
        return chunk


def test_default_transport_is_tls12_verified_and_has_no_insecure_flag() -> None:
    transport = HttpsTransport()
    assert transport._ssl_context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert transport._ssl_context.check_hostname is True
    assert transport._ssl_context.verify_mode == ssl.CERT_REQUIRED
    parameters = inspect.signature(HttpsTransport).parameters
    assert "verify" not in parameters
    assert "insecure" not in parameters
    assert "follow_redirects" not in parameters


def test_transport_configuration_rejects_nonfinite_or_fractional_limits() -> None:
    with pytest.raises(ValueError):
        HttpsTransport(timeout_seconds=math.inf)
    with pytest.raises(TypeError):
        HttpsTransport(max_response_bytes=4.5)  # type: ignore[arg-type]


def test_redirect_handler_fails_closed() -> None:
    handler = _RejectRedirects()
    with pytest.raises(TransportError):
        handler.redirect_request(None, None, 302, "Found", {}, "https://other.invalid")


def test_default_transport_rejects_caller_constructed_raw_requests() -> None:
    class CallerRequest:
        bank = object()
        body = b"<BTU/>"

    with pytest.raises(TransportError):
        HttpsTransport().exchange(CallerRequest())  # type: ignore[arg-type]


def test_response_reader_bounds_declared_and_streamed_sizes() -> None:
    transport = HttpsTransport(max_response_bytes=4)
    with pytest.raises(ResponseLimitError):
        transport._read_bounded(FakeResponse(b"12345"))  # type: ignore[arg-type]
    with pytest.raises(ResponseLimitError):
        transport._read_bounded(FakeResponse(b"", "5"))  # type: ignore[arg-type]
    with pytest.raises(TransportError):
        transport._read_bounded(FakeResponse(b"", "invalid"))  # type: ignore[arg-type]
    assert transport._read_bounded(FakeResponse(b"1234")) == b"1234"  # type: ignore[arg-type]


def test_response_reader_handles_short_stream_reads() -> None:
    class ShortReadResponse(FakeResponse):
        def read(self, amount: int) -> bytes:
            return super().read(min(amount, 2))

    transport = HttpsTransport(max_response_bytes=6)
    response = ShortReadResponse(b"123456")
    assert transport._read_bounded(response) == b"123456"  # type: ignore[arg-type]
