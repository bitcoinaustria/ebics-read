from __future__ import annotations

import base64
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta

import pytest
from lxml import etree
from test_haa import (
    _NOW,
    _TRANSACTION_ID,
    _assert_request_signature,
    _Provider,
    _response,
    _setup,
    _Transport,
)

from ebics_read import (
    AccountSelector,
    AmbiguousTransportError,
    Bank,
    BtfDescriptor,
    ConfigurationError,
    ContainerType,
    DateRange,
    DownloadOptions,
    DownloadPhase,
    DownloadSession,
    KeyPurpose,
    NegotiatedProtocol,
    ProtocolError,
    ProtocolLimits,
    ReceiptKind,
    ReplayError,
    ResponseLimitError,
    SessionConflictError,
    SessionLease,
    Subscriber,
    TransactionId,
    TransportResponse,
)
from ebics_read.btd import (
    _parse_btd_initial_response,
    _parse_btd_receipt_response,
    _parse_btd_transfer_response,
)
from ebics_read.testing import InMemorySegmentStore, InMemorySessionStore
from ebics_read.transport import _PreparedTransportRequest

_H005 = "urn:org:ebics:H005"


@dataclass
class _Control:
    deadline: datetime = _NOW + timedelta(minutes=5)

    def raise_if_cancelled(self) -> None:
        pass


@dataclass
class _CrashOnceSessionStore:
    inner: InMemorySessionStore
    crash_initialization: bool = True
    crash_phase: DownloadPhase | None = None
    crashed: bool = False

    def acquire_lease(
        self, session_id: str, owner_token: bytes, expires_at: datetime
    ) -> SessionLease:
        return self.inner.acquire_lease(session_id, owner_token, expires_at)

    def load(self, lease: SessionLease) -> DownloadSession | None:
        return self.inner.load(lease)

    def compare_and_swap(
        self,
        lease: SessionLease,
        expected_revision: int | None,
        state: DownloadSession,
    ) -> bool:
        if not self.crashed and state.phase is self.crash_phase:
            self.crashed = True
            raise RuntimeError("synthetic crash after segment spool")
        return self.inner.compare_and_swap(lease, expected_revision, state)

    def initialize_transaction(
        self,
        lease: SessionLease,
        expected_revision: int,
        state: DownloadSession,
    ) -> bool:
        if self.crash_initialization and not self.crashed:
            self.crashed = True
            raise RuntimeError("synthetic crash after bootstrap spool")
        return self.inner.initialize_transaction(lease, expected_revision, state)

    def claim_transaction_id(self, transaction_id: TransactionId) -> None:
        self.inner.claim_transaction_id(transaction_id)

    def delete(self, lease: SessionLease, expected_revision: int) -> bool:
        return self.inner.delete(lease, expected_revision)

    def release_lease(self, lease: SessionLease) -> None:
        self.inner.release_lease(lease)


@dataclass
class _AmbiguousTransferTransport:
    inner: _Transport
    calls: int = 0

    def exchange(
        self, request: _PreparedTransportRequest, control: object
    ) -> TransportResponse:
        self.calls += 1
        root = etree.fromstring(request.body)
        if root.findtext(f".//{{{_H005}}}TransactionPhase") == "Transfer":
            raise AmbiguousTransportError("synthetic ambiguous transfer")
        return self.inner.exchange(request, control)


@dataclass(slots=True)
class _CrashOnceSegmentStore(InMemorySegmentStore):
    crash_once: bool = True

    def discard(self, lease: SessionLease) -> None:
        if self.crash_once:
            self.crash_once = False
            raise RuntimeError("synthetic crash during spool discard")
        InMemorySegmentStore.discard(self, lease)


def _descriptor(container: ContainerType = ContainerType.ZIP) -> BtfDescriptor:
    return BtfDescriptor("EOP", "camt.053", "08", "001", "XML", "STM", container, "AT")


def _initialization_request(
    *, options: DownloadOptions | None = None
) -> tuple[_PreparedTransportRequest, _Provider]:
    backend, _, trusted = _setup()
    assert isinstance(backend.key_provider, _Provider)
    provider = backend.key_provider
    request = _PreparedTransportRequest._for_btd_initialization(
        Bank("https://bank.invalid/ebics", "HOST"),
        Subscriber("PARTNER=1", "USER,1", "SYSTEM1"),
        NegotiatedProtocol(),
        trusted,
        _descriptor(),
        DownloadOptions() if options is None else options,
        bytes(range(16)),
        _NOW,
        provider,
        provider.certificate_der(KeyPurpose.AUTHENTICATION),
    )
    return request, provider


def test_btd_builds_only_the_exact_typed_download_parameters() -> None:
    request, provider = _initialization_request(
        options=DownloadOptions(DateRange(date(2026, 1, 1), date(2026, 1, 31)))
    )
    root = etree.fromstring(request.body)

    assert request.order.value == "BTD"
    assert root.findtext(f".//{{{_H005}}}AdminOrderType") == "BTD"
    parameters = root.find(f".//{{{_H005}}}BTDOrderParams")
    assert parameters is not None
    assert [etree.QName(child).localname for child in parameters] == [
        "Service",
        "DateRange",
    ]
    service = parameters[0]
    assert [etree.QName(child).localname for child in service] == [
        "ServiceName",
        "Scope",
        "ServiceOption",
        "Container",
        "MsgName",
    ]
    assert service.findtext(f"{{{_H005}}}ServiceName") == "EOP"
    assert service.find(f"{{{_H005}}}Container").get("containerType") == "ZIP"  # type: ignore[union-attr]
    assert service.find(f"{{{_H005}}}MsgName").attrib == {  # type: ignore[union-attr]
        "version": "08",
        "variant": "001",
        "format": "XML",
    }
    assert parameters.findtext(f"{{{_H005}}}DateRange/{{{_H005}}}Start") == (
        "2026-01-01"
    )
    assert not root.findall(f".//{{{_H005}}}Parameter")
    assert not root.findall(f".//{{{_H005}}}OrderID")
    _assert_request_signature(request.body, provider.authentication_key)


def test_btd_rejects_nonstandard_account_parameter_before_signing() -> None:
    with pytest.raises(ConfigurationError, match="no portable"):
        _initialization_request(
            options=DownloadOptions(account=AccountSelector(account_id="ACCOUNT-1"))
        )


def test_btd_reuses_the_exact_authenticated_download_response_contract() -> None:
    backend, transport, trusted = _setup()
    assert isinstance(backend.key_provider, _Provider)
    initial = _parse_btd_initial_response(
        _response(
            transport.bank_key,
            "Initialisation",
            transaction_id=_TRANSACTION_ID,
            total_segments=2,
            segment_number=1,
            fragment="QUJDRA==",
            encryption_der=transport.encryption_der,
        ),
        trusted,
        transport.encryption_der,
        backend.key_provider,
        backend.xml_limits,
        backend.protocol_limits,
    )
    assert initial.transaction_id == TransactionId(_TRANSACTION_ID)
    transfer = _parse_btd_transfer_response(
        _response(
            transport.bank_key,
            "Transfer",
            transaction_id=_TRANSACTION_ID,
            total_segments=2,
            segment_number=2,
            fragment="RUZHSA==",
        ),
        trusted,
        initial.transaction_id,
        2,
        2,
        backend.xml_limits,
    )
    assert transfer.text == "RUZHSA=="
    _parse_btd_receipt_response(
        _response(
            transport.bank_key,
            "Receipt",
            transaction_id=_TRANSACTION_ID,
            technical="011000",
        ),
        trusted,
        initial.transaction_id,
        ReceiptKind.POSITIVE,
        backend.xml_limits,
    )


def test_btd_transfer_and_receipt_builders_remain_fixed() -> None:
    _, provider = _initialization_request()
    bank = Bank("https://bank.invalid/ebics", "HOST")
    transaction_id = TransactionId(_TRANSACTION_ID)
    transfer = _PreparedTransportRequest._for_btd_transfer(
        bank,
        NegotiatedProtocol(),
        transaction_id,
        2,
        provider,
        provider.certificate_der(KeyPurpose.AUTHENTICATION),
    )
    receipt = _PreparedTransportRequest._for_btd_receipt(
        bank,
        NegotiatedProtocol(),
        transaction_id,
        ReceiptKind.NEGATIVE,
        provider,
        provider.certificate_der(KeyPurpose.AUTHENTICATION),
    )

    assert transfer.order.value == receipt.order.value == "BTD"
    assert (
        etree.fromstring(transfer.body).findtext(f".//{{{_H005}}}TransactionPhase")
        == "Transfer"
    )
    assert etree.fromstring(receipt.body).findtext(f".//{{{_H005}}}ReceiptCode") == "1"
    for request in (transfer, receipt):
        _assert_request_signature(request.body, provider.authentication_key)


def _receive(backend, trusted, session_id: str = "btd-session"):  # type: ignore[no-untyped-def]
    return backend._receive_btd_segments(
        Bank("https://bank.invalid/ebics", "HOST"),
        Subscriber("PARTNER=1", "USER,1", "SYSTEM1"),
        NegotiatedProtocol(),
        trusted,
        session_id,
        _descriptor(ContainerType.NONE),
        DownloadOptions(),
        _Control(),
    )


def test_btd_receives_verified_responses_into_a_restartable_spool() -> None:
    backend, transport, trusted = _setup(order_data=b"synthetic BTD document")
    spool = InMemorySegmentStore()
    backend = replace(backend, segment_store=spool)

    state = _receive(backend, trusted)

    assert state.phase is DownloadPhase.SIGNATURES_AND_DIGESTS_VERIFIED
    assert [request.order.value for request in transport.requests] == ["BTD", "BTD"]
    lease = SessionLease("btd-session", b"0123456789abcdef", _Control.deadline)
    assert [number for number, _ in spool.list_segments(lease)] == [1, 2]

    assert _receive(backend, trusted) == state
    assert len(transport.requests) == 2


def test_btd_recovers_bootstrap_spooled_before_transaction_cas() -> None:
    backend, transport, trusted = _setup(order_data=b"synthetic BTD document")
    underlying = InMemorySessionStore()
    crashing = _CrashOnceSessionStore(underlying)
    spool = InMemorySegmentStore()
    backend = replace(
        backend,
        session_store=crashing,
        segment_store=spool,
    )

    with pytest.raises(RuntimeError, match="synthetic crash"):
        _receive(backend, trusted)
    assert len(transport.requests) == 1

    state = _receive(backend, trusted)

    assert state.phase is DownloadPhase.SIGNATURES_AND_DIGESTS_VERIFIED
    assert len(transport.requests) == 2


def test_btd_recovers_segment_spooled_before_state_cas() -> None:
    backend, transport, trusted = _setup(order_data=b"synthetic BTD document")
    crashing = _CrashOnceSessionStore(
        InMemorySessionStore(),
        crash_initialization=False,
        crash_phase=DownloadPhase.SEGMENTS_RECEIVED,
    )
    backend = replace(
        backend,
        session_store=crashing,
        segment_store=InMemorySegmentStore(),
    )

    with pytest.raises(RuntimeError, match="segment spool"):
        _receive(backend, trusted)
    assert len(transport.requests) == 2

    state = _receive(backend, trusted)

    assert state.phase is DownloadPhase.SIGNATURES_AND_DIGESTS_VERIFIED
    assert len(transport.requests) == 2


def test_btd_recovers_first_segment_spooled_after_transaction_claim() -> None:
    backend, transport, trusted = _setup(order_data=b"synthetic BTD document")
    crashing = _CrashOnceSessionStore(
        InMemorySessionStore(),
        crash_initialization=False,
        crash_phase=DownloadPhase.RECEIVING_SEGMENTS,
    )
    backend = replace(
        backend,
        session_store=crashing,
        segment_store=InMemorySegmentStore(),
    )

    with pytest.raises(RuntimeError, match="segment spool"):
        _receive(backend, trusted)
    assert len(transport.requests) == 1

    state = _receive(backend, trusted)

    assert state.phase is DownloadPhase.SIGNATURES_AND_DIGESTS_VERIFIED
    assert len(transport.requests) == 2


def test_btd_ambiguous_transfer_is_terminal_and_never_retried() -> None:
    backend, transport, trusted = _setup(order_data=b"synthetic BTD document")
    ambiguous = _AmbiguousTransferTransport(transport)
    backend = replace(
        backend,
        transport=ambiguous,
        segment_store=InMemorySegmentStore(),
    )

    with pytest.raises(AmbiguousTransportError):
        _receive(backend, trusted)
    assert ambiguous.calls == 2

    with pytest.raises(SessionConflictError, match="cannot be resumed"):
        _receive(backend, trusted)
    assert ambiguous.calls == 2


def test_btd_rejects_an_oversized_first_fragment_before_another_request() -> None:
    backend, transport, trusted = _setup(
        limits=ProtocolLimits(max_compressed_bytes=1)
    )
    transport.fragments = (base64.b64encode(b"x" * 20).decode("ascii"),)
    backend = replace(backend, segment_store=InMemorySegmentStore())

    with pytest.raises(ResponseLimitError, match="encoded order data"):
        _receive(backend, trusted)

    assert len(transport.requests) == 1


def test_btd_verified_spool_corruption_fails_and_discards() -> None:
    backend, _, trusted = _setup(order_data=b"synthetic BTD document")
    sessions = InMemorySessionStore()
    spool = InMemorySegmentStore()
    backend = replace(backend, session_store=sessions, segment_store=spool)
    _receive(backend, trusted)
    reference, response = spool._segments["btd-session"][2]
    root = etree.fromstring(response)
    order_data = root.find(f".//{{{_H005}}}OrderData")
    assert order_data is not None
    order_data.text = "!"
    spool._segments["btd-session"][2] = (reference, etree.tostring(root))

    with pytest.raises(ProtocolError):
        _receive(backend, trusted)

    lease = sessions.acquire_lease(
        "btd-session", b"0123456789abcdef", _Control.deadline
    )
    state = sessions.load(lease)
    assert state is not None and state.phase is DownloadPhase.FAILED
    assert spool.list_segments(lease) == ()


def test_btd_verified_spool_missing_segment_fails_and_discards() -> None:
    backend, _, trusted = _setup(order_data=b"synthetic BTD document")
    sessions = InMemorySessionStore()
    spool = InMemorySegmentStore()
    backend = replace(backend, session_store=sessions, segment_store=spool)
    _receive(backend, trusted)
    del spool._segments["btd-session"][2]

    with pytest.raises(ProtocolError, match="spool"):
        _receive(backend, trusted)

    lease = sessions.acquire_lease(
        "btd-session", b"0123456789abcdef", _Control.deadline
    )
    state = sessions.load(lease)
    assert state is not None and state.phase is DownloadPhase.FAILED
    assert spool.list_segments(lease) == ()


def test_btd_verified_spool_bootstrap_substitution_fails_and_discards() -> None:
    backend, transport, trusted = _setup(order_data=b"synthetic BTD document")
    sessions = InMemorySessionStore()
    spool = InMemorySegmentStore()
    backend = replace(backend, session_store=sessions, segment_store=spool)
    _receive(backend, trusted)
    reference, _ = spool._segments["btd-session"][1]
    spool._segments["btd-session"][1] = (
        reference,
        _response(
            transport.bank_key,
            "Initialisation",
            transaction_id="FFEEDDCCBBAA99887766554433221100",
            total_segments=2,
            segment_number=1,
            fragment=transport.fragments[0],
            encryption_der=transport.encryption_der,
        ),
    )

    with pytest.raises(ProtocolError, match="metadata disagree"):
        _receive(backend, trusted)

    lease = sessions.acquire_lease(
        "btd-session", b"0123456789abcdef", _Control.deadline
    )
    state = sessions.load(lease)
    assert state is not None and state.phase is DownloadPhase.FAILED
    assert spool.list_segments(lease) == ()


def test_btd_failed_session_retries_crashed_spool_cleanup() -> None:
    backend, transport, trusted = _setup(order_data=b"synthetic BTD document")
    ambiguous = _AmbiguousTransferTransport(transport)
    spool = _CrashOnceSegmentStore()
    backend = replace(backend, transport=ambiguous, segment_store=spool)

    with pytest.raises(RuntimeError, match="spool discard"):
        _receive(backend, trusted)
    assert ambiguous.calls == 2

    with pytest.raises(SessionConflictError, match="cannot be resumed"):
        _receive(backend, trusted)
    assert ambiguous.calls == 2
    lease = SessionLease("btd-session", b"0123456789abcdef", _Control.deadline)
    assert spool.list_segments(lease) == ()


def test_btd_request_identity_and_global_transaction_claim_fail_closed() -> None:
    backend, transport, trusted = _setup(order_data=b"synthetic BTD document")
    backend = replace(backend, segment_store=InMemorySegmentStore())
    _receive(backend, trusted, "first-session")

    with pytest.raises(ReplayError):
        _receive(backend, trusted, "second-session")
    assert len(transport.requests) == 3

    before = len(transport.requests)
    with pytest.raises(SessionConflictError, match="another request"):
        backend._receive_btd_segments(
            Bank("https://bank.invalid/ebics", "HOST"),
            Subscriber("PARTNER=1", "USER,1", "SYSTEM1"),
            NegotiatedProtocol(),
            trusted,
            "first-session",
            BtfDescriptor(
                "EOP",
                "camt.054",
                "08",
                "001",
                "XML",
                "STM",
                ContainerType.NONE,
                "AT",
            ),
            DownloadOptions(),
            _Control(),
        )
    assert len(transport.requests) == before
