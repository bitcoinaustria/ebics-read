from datetime import date

import pytest

from ebics_read import (
    AccountSelector,
    Bank,
    BtfDescriptor,
    CapabilityDiscovery,
    ConfigurationError,
    ContainerType,
    DateRange,
    DownloadOptions,
    DownloadPhase,
    DownloadSession,
    EbicsPublicKeyDigest,
    InitializationLetter,
    NegotiatedProtocol,
    OrderType,
    ProtocolLimits,
    ProtocolVersion,
    ServiceCapability,
    Subscriber,
    UnsupportedProtocolVersionError,
    VersionDiscovery,
)


def test_bank_requires_strict_https_endpoint() -> None:
    for endpoint in (
        "http://bank.invalid/ebics",
        "https://" + "user" + ":" + "pass" + "@bank.invalid/ebics",
        "https://bank.invalid/ebics?raw=1",
        "https://bank.invalid/ebics#fragment",
    ):
        with pytest.raises(ConfigurationError):
            Bank(endpoint, "HOST")


def test_sensitive_models_hide_values_from_repr() -> None:
    bank = Bank("https://bank.invalid/ebics", "HOST-REPR")
    subscriber = Subscriber("PARTNER-REPR", "USER-REPR")
    account = AccountSelector(iban="AT611904300234573201")
    assert "bank.invalid" not in repr(bank)
    assert "HOST-REPR" not in repr(bank)
    assert "PARTNER-REPR" not in repr(subscriber)
    assert "AT611" not in repr(account)


def test_btf_descriptor_supports_omitted_and_non_at_scopes() -> None:
    def descriptor(scope: str | None) -> BtfDescriptor:
        return BtfDescriptor(
            service_name="EOP",
            scope=scope,
            message_name="camt.053",
            message_version="08",
            variant="001",
            format="XML",
            service_option="STM",
            container_type=ContainerType.ZIP,
        )

    assert descriptor(None).scope is None
    assert descriptor("GLB").scope == "GLB"
    assert descriptor("BIL").scope == "BIL"
    assert descriptor("BANK01").scope == "BANK01"


def test_dates_and_accounts_are_typed() -> None:
    with pytest.raises(ConfigurationError):
        DateRange(date(2026, 2, 1), date(2026, 1, 1))
    with pytest.raises(ConfigurationError):
        AccountSelector()
    with pytest.raises(ConfigurationError):
        AccountSelector(iban="AT611904300234573201", account_id="duplicate")

    options = DownloadOptions(
        DateRange(date(2026, 1, 1), date(2026, 1, 31)),
        AccountSelector(account_id="ACCOUNT-1", currency="EUR"),
    )
    assert options.date_range is not None
    with pytest.raises(TypeError):
        DownloadOptions(date_range="2026-01")  # type: ignore[arg-type]


def test_download_state_machine_rejects_skips_and_terminal_reuse() -> None:
    state = DownloadSession.start("local-session", ProtocolLimits(max_segments=2))
    with pytest.raises(ConfigurationError):
        state.record_segment(1)

    state = state.initialize(transaction_id="transaction", total_segments=2)
    with pytest.raises(ConfigurationError):
        state.record_segment(2)
    state = state.record_segment(1)
    assert state.phase is DownloadPhase.RECEIVING_SEGMENTS
    state = state.record_segment(2)
    assert state.phase is DownloadPhase.SEGMENTS_RECEIVED
    with pytest.raises(ConfigurationError):
        state.mark_positive_receipt_sent()
    state = state.mark_signatures_and_digests_verified()
    state = state.mark_decrypted()
    state = state.mark_container_verified()
    state = state.mark_positive_receipt_sent()
    state = state.mark_receipt_response_verified()
    state = state.finish()
    assert state.phase is DownloadPhase.COMPLETE
    with pytest.raises(ConfigurationError):
        state.fail()


def test_download_state_cannot_be_forged_or_restored_incoherently() -> None:
    with pytest.raises(TypeError):
        DownloadSession(  # type: ignore[call-arg]
            "session", DownloadPhase.COMPLETE, None, 1, None, 10, 0, None
        )
    with pytest.raises(ConfigurationError):
        DownloadSession.restore(
            session_id="session",
            phase=DownloadPhase.COMPLETE,
            transaction_id="transaction",
            next_segment=1,
            total_segments=2,
            max_segments=2,
            revision=1,
        )
    with pytest.raises(ConfigurationError):
        DownloadSession.restore(
            session_id="session",
            phase=DownloadPhase.INITIALIZED,
            transaction_id="transaction",
            next_segment=2,
            total_segments=3,
            max_segments=3,
            revision=1,
        )
    with pytest.raises(ConfigurationError):
        DownloadSession.start("session", ProtocolLimits(max_segments=1)).initialize(
            transaction_id="transaction", total_segments=2
        )


def test_negative_receipt_and_ambiguous_receipt_are_explicit() -> None:
    state = DownloadSession.start("session", ProtocolLimits(max_segments=1))
    state = state.initialize(transaction_id="transaction", total_segments=1)
    state = state.record_segment(1)
    negative = state.mark_negative_receipt_sent()
    ambiguous = negative.mark_receipt_ambiguous()
    finished = ambiguous.mark_receipt_response_verified().finish()
    assert finished.phase is DownloadPhase.NEGATIVE_COMPLETE


def test_protocol_limits_are_immutable_and_consistent() -> None:
    limits = ProtocolLimits()
    assert limits.max_segments == 10_000
    with pytest.raises(ConfigurationError):
        ProtocolLimits(max_segments=0)
    with pytest.raises(ConfigurationError):
        ProtocolLimits(max_decompressed_bytes=10, max_zip_member_bytes=11)
    with pytest.raises(TypeError):
        ProtocolLimits(max_segments=1.5)  # type: ignore[arg-type]


def test_capability_results_reject_non_discovery_orders() -> None:
    with pytest.raises(ConfigurationError):
        CapabilityDiscovery(completed_orders=(OrderType.BTD,))


def test_nested_models_reject_enum_lookalikes_and_wrong_values() -> None:
    with pytest.raises(TypeError):
        ServiceCapability("not-a-descriptor", "HPD")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        InitializationLetter("INI", b"letter", (EbicsPublicKeyDigest("A" * 64),))  # type: ignore[arg-type]


def test_collection_models_defensively_freeze_caller_lists() -> None:
    versions = [ProtocolVersion("H005", "03.00")]
    result = VersionDiscovery(versions)  # type: ignore[arg-type]
    versions.append(ProtocolVersion("H004", "02.50"))
    assert len(result.versions) == 1

    orders = [OrderType.HPD]
    capabilities = CapabilityDiscovery(completed_orders=orders)  # type: ignore[arg-type]
    orders.append(OrderType.HAA)
    assert capabilities.completed_orders == (OrderType.HPD,)


def test_h005_negotiation_rejects_downgrade_and_conflicts() -> None:
    discovery = VersionDiscovery(
        (ProtocolVersion("H004", "02.50"), ProtocolVersion("H005", "03.00"))
    )
    assert discovery.select_h005() == NegotiatedProtocol()
    with pytest.raises(UnsupportedProtocolVersionError):
        VersionDiscovery((ProtocolVersion("H004", "02.50"),)).select_h005()
    with pytest.raises(UnsupportedProtocolVersionError):
        NegotiatedProtocol(protocol_version="H004")
    with pytest.raises(ConfigurationError):
        VersionDiscovery(
            (ProtocolVersion("H005", "03.00"), ProtocolVersion("H005", "03.01"))
        )
