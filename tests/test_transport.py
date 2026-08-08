from __future__ import annotations

import inspect
import math
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.message import Message
from urllib.error import HTTPError, URLError

import pytest

from ebics_read import (
    AmbiguousTransportError,
    HttpsTransport,
    NegotiatedProtocol,
    OperationDeadlineError,
    OrderType,
    ProxyConfiguration,
    ResponseLimitError,
    Subscriber,
    TransientTransportError,
    TransportError,
)
from ebics_read.models import Bank
from ebics_read.testing import FixedClock
from ebics_read.transport import _PreparedTransportRequest, _RejectRedirects


class FakeResponse:
    def __init__(self, body: bytes, content_length: str | None = None) -> None:
        self._body = body
        self._offset = 0
        self.timeouts: list[float] = []
        socket = type(
            "FakeSocket",
            (),
            {"settimeout": lambda _self, value: self.timeouts.append(value)},
        )()
        raw = type("FakeRaw", (), {"_sock": socket})()
        self.fp = type("FakeFile", (), {"raw": raw})()
        self.headers = Message()
        if content_length is not None:
            self.headers["Content-Length"] = content_length

    def read(self, amount: int) -> bytes:
        chunk = self._body[self._offset : self._offset + amount]
        self._offset += len(chunk)
        return chunk


@dataclass(frozen=True)
class OperationControlStub:
    deadline: datetime = datetime(2026, 7, 16, tzinfo=timezone.utc)
    cancelled: bool = False

    def raise_if_cancelled(self) -> None:
        if self.cancelled:
            raise RuntimeError("synthetic cancellation")


NOW = datetime(2026, 7, 15, tzinfo=timezone.utc)
CLOCK = FixedClock(NOW)
CONTROL = OperationControlStub()


def test_default_transport_is_tls12_verified_and_has_no_insecure_flag() -> None:
    transport = HttpsTransport(clock=CLOCK)
    assert transport._ssl_context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert transport._ssl_context.check_hostname is True
    assert transport._ssl_context.verify_mode == ssl.CERT_REQUIRED
    parameters = inspect.signature(HttpsTransport).parameters
    assert "verify" not in parameters
    assert "insecure" not in parameters
    assert "follow_redirects" not in parameters


def test_transport_configuration_rejects_nonfinite_or_fractional_limits() -> None:
    with pytest.raises(ValueError):
        HttpsTransport(clock=CLOCK, timeout_seconds=math.inf)
    with pytest.raises(TypeError):
        HttpsTransport(clock=CLOCK, max_response_bytes=4.5)  # type: ignore[arg-type]


def test_environment_proxies_are_disabled_unless_explicitly_configured() -> None:
    assert HttpsTransport(clock=CLOCK)._proxy_handler().proxies == {}
    proxy = ProxyConfiguration("http://proxy.invalid:8080")
    assert HttpsTransport(clock=CLOCK, proxy=proxy)._proxy_handler().proxies == {
        "https": "http://proxy.invalid:8080"
    }
    with pytest.raises(ValueError):
        ProxyConfiguration("http://" + "user" + ":" + "pass" + "@proxy.invalid")


def test_redirect_handler_fails_closed() -> None:
    handler = _RejectRedirects()
    with pytest.raises(TransportError):
        handler.redirect_request(None, None, 302, "Found", {}, "https://other.invalid")


def test_default_transport_rejects_caller_constructed_raw_requests() -> None:
    class CallerRequest:
        bank = object()
        body = b"<BTU/>"

    with pytest.raises(TransportError):
        HttpsTransport(clock=CLOCK).exchange(  # type: ignore[arg-type]
            CallerRequest(), CONTROL
        )


def test_default_transport_treats_interruption_as_ambiguous(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BrokenOpener:
        def open(self, request: object, timeout: float) -> object:
            raise URLError(TimeoutError("synthetic timeout"))

    monkeypatch.setattr(
        "ebics_read.transport.build_opener", lambda *handlers: BrokenOpener()
    )
    request = _PreparedTransportRequest._for_hev(
        Bank("https://bank.invalid/ebics", "HOST")
    )
    with pytest.raises(AmbiguousTransportError):
        HttpsTransport(clock=CLOCK).exchange(request, CONTROL)


def test_initialization_post_response_failures_are_ambiguous(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class OpenedResponse(FakeResponse):
        def __enter__(self) -> OpenedResponse:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    class ResponseOpener:
        def __init__(self, response: OpenedResponse) -> None:
            self.response = response

        def open(self, request: object, timeout: float) -> OpenedResponse:
            return self.response

    request = _PreparedTransportRequest._for_ini(
        Bank("https://bank.invalid/ebics", "HOST", "Synthetic Bank AG"),
        Subscriber("PARTNER", "USER"),
        NegotiatedProtocol(),
        b"synthetic certificate",
    )
    hia_request = _PreparedTransportRequest._for_hia(
        Bank("https://bank.invalid/ebics", "HOST", "Synthetic Bank AG"),
        Subscriber("PARTNER", "USER"),
        NegotiatedProtocol(),
        b"synthetic authentication certificate",
        b"synthetic encryption certificate",
    )

    class BrokenTlsResponse(OpenedResponse):
        def read(self, amount: int) -> bytes:
            raise ssl.SSLError("synthetic TLS read failure")

    for current_request in (request, hia_request):
        for response in (
            OpenedResponse(b"", "5"),
            OpenedResponse(b"123", "4"),
            BrokenTlsResponse(b"response"),
        ):
            monkeypatch.setattr(
                "ebics_read.transport.build_opener",
                lambda *handlers, response=response: ResponseOpener(response),
            )
            with pytest.raises(AmbiguousTransportError):
                HttpsTransport(clock=CLOCK, max_response_bytes=4).exchange(
                    current_request, CONTROL
                )

    class HttpErrorOpener:
        def open(self, request: object, timeout: float) -> object:
            raise HTTPError(
                "https://bank.invalid/ebics", 500, "synthetic", Message(), None
            )

    monkeypatch.setattr(
        "ebics_read.transport.build_opener", lambda *handlers: HttpErrorOpener()
    )
    for current_request in (request, hia_request):
        with pytest.raises(AmbiguousTransportError):
            HttpsTransport(clock=CLOCK).exchange(current_request, CONTROL)

    class TlsErrorOpener:
        def open(self, request: object, timeout: float) -> object:
            raise URLError(ssl.SSLError("synthetic handshake failure"))

    monkeypatch.setattr(
        "ebics_read.transport.build_opener", lambda *handlers: TlsErrorOpener()
    )
    for current_request in (request, hia_request):
        with pytest.raises(AmbiguousTransportError):
            HttpsTransport(clock=CLOCK).exchange(current_request, CONTROL)

    class CertificateErrorOpener:
        def open(self, request: object, timeout: float) -> object:
            raise URLError(
                ssl.SSLCertVerificationError(1, "synthetic verification failure")
            )

    monkeypatch.setattr(
        "ebics_read.transport.build_opener",
        lambda *handlers: CertificateErrorOpener(),
    )
    for current_request in (request, hia_request):
        with pytest.raises(TransientTransportError):
            HttpsTransport(clock=CLOCK).exchange(current_request, CONTROL)

    @dataclass
    class CancelAfterSend:
        calls: int = 0
        deadline: datetime = NOW + timedelta(seconds=5)

        def raise_if_cancelled(self) -> None:
            self.calls += 1
            if self.calls > 1:
                raise RuntimeError("synthetic caller cancellation")

    for current_request in (request, hia_request):
        response = OpenedResponse(b"response")
        monkeypatch.setattr(
            "ebics_read.transport.build_opener",
            lambda *handlers, response=response: ResponseOpener(response),
        )
        with pytest.raises(AmbiguousTransportError) as cancelled:
            HttpsTransport(clock=CLOCK).exchange(current_request, CancelAfterSend())
        assert isinstance(cancelled.value.__cause__, RuntimeError)


def test_only_fixed_operation_specific_requests_can_be_prepared() -> None:
    bank = Bank("https://bank.invalid/ebics", "HOST")
    with pytest.raises(TypeError):
        _PreparedTransportRequest()
    assert tuple(inspect.signature(_PreparedTransportRequest._for_hev).parameters) == (
        "bank",
    )
    request = _PreparedTransportRequest._for_hev(bank)
    assert request.order is OrderType.HEV
    assert b"ebicsHEVRequest" in request.body
    assert b"BTU" not in request.body
    ini_parameters = tuple(
        inspect.signature(_PreparedTransportRequest._for_ini).parameters
    )
    assert ini_parameters == ("bank", "subscriber", "protocol", "certificate_der")
    assert {"body", "xml", "order"}.isdisjoint(ini_parameters)
    hia_parameters = tuple(
        inspect.signature(_PreparedTransportRequest._for_hia).parameters
    )
    assert hia_parameters == (
        "bank",
        "subscriber",
        "protocol",
        "authentication_certificate_der",
        "encryption_certificate_der",
    )
    assert {"body", "xml", "order"}.isdisjoint(hia_parameters)
    hpb_parameters = tuple(
        inspect.signature(_PreparedTransportRequest._for_hpb).parameters
    )
    assert hpb_parameters == (
        "bank",
        "subscriber",
        "protocol",
        "nonce",
        "timestamp",
        "key_provider",
        "authentication_certificate_der",
    )
    assert {"body", "xml", "order"}.isdisjoint(hpb_parameters)
    assert tuple(
        inspect.signature(_PreparedTransportRequest._for_haa_initialization).parameters
    ) == (
        "bank",
        "subscriber",
        "protocol",
        "trusted_bank_keys",
        "nonce",
        "timestamp",
        "key_provider",
        "authentication_certificate_der",
    )
    assert tuple(
        inspect.signature(_PreparedTransportRequest._for_haa_transfer).parameters
    ) == (
        "bank",
        "protocol",
        "transaction_id",
        "segment_number",
        "key_provider",
        "authentication_certificate_der",
    )
    assert tuple(
        inspect.signature(_PreparedTransportRequest._for_haa_receipt).parameters
    ) == (
        "bank",
        "protocol",
        "transaction_id",
        "receipt",
        "key_provider",
        "authentication_certificate_der",
    )
    assert not hasattr(_PreparedTransportRequest, "_prepared")


def test_operation_control_bounds_each_exchange(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _PreparedTransportRequest._for_hev(
        Bank("https://bank.invalid/ebics", "HOST")
    )
    expired = OperationControlStub(deadline=NOW)
    with pytest.raises(OperationDeadlineError):
        HttpsTransport(clock=CLOCK).exchange(request, expired)
    with pytest.raises(RuntimeError, match="cancellation"):
        HttpsTransport(clock=CLOCK).exchange(
            request, OperationControlStub(cancelled=True)
        )

    observed: list[float] = []

    class OpenedResponse(FakeResponse):
        def __enter__(self) -> OpenedResponse:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    class RecordingOpener:
        def open(self, request: object, timeout: float) -> OpenedResponse:
            observed.append(timeout)
            return OpenedResponse(b"response")

    monkeypatch.setattr(
        "ebics_read.transport.build_opener", lambda *handlers: RecordingOpener()
    )
    short = OperationControlStub(deadline=NOW + timedelta(seconds=5))
    result = HttpsTransport(clock=CLOCK, timeout_seconds=30).exchange(request, short)
    assert result.body == b"response"
    assert observed == [5.0]


def test_response_reader_bounds_declared_and_streamed_sizes() -> None:
    transport = HttpsTransport(clock=CLOCK, max_response_bytes=4)
    with pytest.raises(ResponseLimitError):
        transport._read_bounded(  # type: ignore[arg-type]
            FakeResponse(b"12345"), CONTROL
        )
    with pytest.raises(ResponseLimitError):
        transport._read_bounded(FakeResponse(b"", "5"), CONTROL)  # type: ignore[arg-type]
    with pytest.raises(TransportError):
        transport._read_bounded(  # type: ignore[arg-type]
            FakeResponse(b"", "invalid"), CONTROL
        )
    with pytest.raises(TransportError, match="declared byte length"):
        transport._read_bounded(FakeResponse(b"123", "4"), CONTROL)  # type: ignore[arg-type]
    assert (  # type: ignore[arg-type]
        transport._read_bounded(FakeResponse(b"1234"), CONTROL) == b"1234"
    )


def test_response_reader_rejects_conflicting_http_framing() -> None:
    response = FakeResponse(b"<root/>junk", "7")
    response.headers["Transfer-Encoding"] = "chunked"

    with pytest.raises(TransportError, match="conflicting"):
        HttpsTransport(clock=CLOCK)._read_bounded(response, CONTROL)  # type: ignore[arg-type]


def test_response_reader_handles_short_stream_reads() -> None:
    class ShortReadResponse(FakeResponse):
        def read(self, amount: int) -> bytes:
            return super().read(min(amount, 2))

    transport = HttpsTransport(clock=CLOCK, max_response_bytes=6)
    response = ShortReadResponse(b"123456")
    assert transport._read_bounded(response, CONTROL) == b"123456"  # type: ignore[arg-type]
    assert response.timeouts
