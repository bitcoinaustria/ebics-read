from dataclasses import replace
from datetime import date, datetime, timezone

import pytest

from ebics_read import (
    AccountSelector,
    AdvertisedBankUrl,
    Bank,
    BankParameters,
    BtfDescriptor,
    CapabilityDiscovery,
    ConfigurationError,
    ContainerType,
    ContentSha256,
    CustomerInformation,
    DateRange,
    DiscoveredAccount,
    DiscoveredUser,
    DocumentReference,
    DocumentStagingId,
    DownloadedDocument,
    DownloadOptions,
    DownloadPermission,
    DownloadPhase,
    DownloadRequestIdentity,
    DownloadSession,
    EbicsPublicKeyDigest,
    InitializationLetter,
    NegotiatedProtocol,
    OrderType,
    ProtocolLimits,
    ProtocolVersion,
    RetrievalProvenance,
    ServiceCapability,
    StagedDocument,
    Subscriber,
    TransactionId,
    UnsupportedProtocolVersionError,
    VersionDiscovery,
)

_TRANSACTION_ID = TransactionId("0123456789ABCDEF0123456789ABCDEF")
_REQUEST_IDENTITY = DownloadRequestIdentity("C" * 64)


def _document_pair(segment_count: int = 1) -> tuple[StagedDocument, DownloadedDocument]:
    descriptor = BtfDescriptor(
        "EOP", "camt.053", "08", "001", "XML", "STM", ContainerType.NONE
    )
    provenance = RetrievalProvenance(
        descriptor,
        NegotiatedProtocol(),
        datetime(2026, 8, 8, tzinfo=timezone.utc),
        ContentSha256.from_bytes(bytes.fromhex(_TRANSACTION_ID.value)),
        segment_count,
        "HOST",
    )
    metadata = {
        "staging_id": DocumentStagingId.derive(_REQUEST_IDENTITY, _TRANSACTION_ID, 1),
        "provenance": provenance,
        "content_sha256": ContentSha256.from_bytes(b"document"),
        "size_bytes": 8,
    }
    return (
        StagedDocument(**metadata),
        DownloadedDocument(**metadata, sink_reference=DocumentReference("document-1")),
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
    with pytest.raises(ConfigurationError, match="H005 limit"):
        Bank("https://bank.invalid/ebics", "H" * 36)
    with pytest.raises(ConfigurationError, match="institution_name"):
        Bank("https://bank.invalid/ebics", "HOST", "")
    assert Bank("https://bank.invalid/ebics", "HOST", "Bank A") == Bank(
        "https://bank.invalid/ebics", "HOST", "Bank B"
    )


def test_sensitive_models_hide_values_from_repr() -> None:
    bank = Bank("https://bank.invalid/ebics", "HOST-REPR", "PRIVATE BANK NAME")
    subscriber = Subscriber("PARTNER=REPR", "USER,REPR")
    account = AccountSelector(iban="AT611904300234573201")
    transaction_id = TransactionId("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    assert "bank.invalid" not in repr(bank)
    assert "HOST-REPR" not in repr(bank)
    assert "PRIVATE BANK NAME" not in repr(bank)
    assert "PARTNER-REPR" not in repr(subscriber)
    assert "AT611" not in repr(account)
    assert "AAAAAAAA" not in repr(transaction_id)


def test_subscriber_ids_match_the_h005_and_s002_profile() -> None:
    assert Subscriber("PARTNER=1", "USER,1", "SYSTEM1")
    for invalid in ("", "USER-1", "A" * 36):
        with pytest.raises(ConfigurationError, match="H005 subscriber"):
            Subscriber("PARTNER", invalid)
    for invalid in ((None, "USER"), ("PARTNER", None)):
        with pytest.raises(ConfigurationError, match="H005 subscriber"):
            Subscriber(*invalid)  # type: ignore[arg-type]


def test_transaction_ids_are_exact_typed_128_bit_values() -> None:
    assert TransactionId.from_bytes(bytes(range(16))).value == (
        "000102030405060708090A0B0C0D0E0F"
    )
    for invalid in ("transaction", "a" * 32, "A" * 31, "A" * 34):
        with pytest.raises(ConfigurationError):
            TransactionId(invalid)
    with pytest.raises(ConfigurationError):
        TransactionId.from_bytes(b"short")
    with pytest.raises(TypeError):
        TransactionId.from_bytes("not-bytes")  # type: ignore[arg-type]
    with pytest.raises(ConfigurationError):
        DownloadRequestIdentity("c" * 64)
    assert "CCCC" not in repr(_REQUEST_IDENTITY)

    first = DocumentStagingId.derive(_REQUEST_IDENTITY, _TRANSACTION_ID, 1)
    assert first == DocumentStagingId.derive(_REQUEST_IDENTITY, _TRANSACTION_ID, 1)
    assert first != DocumentStagingId.derive(
        _REQUEST_IDENTITY,
        TransactionId("FEDCBA9876543210FEDCBA9876543210"),
        1,
    )
    with pytest.raises(ConfigurationError):
        DocumentStagingId.derive(_REQUEST_IDENTITY, _TRANSACTION_ID, 0)


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
    assert descriptor("XYZ").scope == "XYZ"
    with pytest.raises(ConfigurationError):
        descriptor("BANK01")


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
    state = DownloadSession.start(
        "local-session", _REQUEST_IDENTITY, ProtocolLimits(max_segments=2)
    )
    with pytest.raises(ConfigurationError):
        state.record_segment(1)

    state = state.initialize(transaction_id=_TRANSACTION_ID, total_segments=2)
    with pytest.raises(ConfigurationError):
        state.record_segment(2)
    state = state.record_segment(1)
    assert state.phase is DownloadPhase.RECEIVING_SEGMENTS
    state = state.record_segment(2)
    assert state.phase is DownloadPhase.SEGMENTS_RECEIVED
    with pytest.raises(ConfigurationError):
        state.mark_positive_receipt_pending()
    state = state.mark_signatures_and_digests_verified()
    state = state.mark_decrypted()
    state = state.mark_container_verified()
    with pytest.raises(ConfigurationError):
        state.mark_documents_staged(())
    with pytest.raises(TypeError):
        state.mark_documents_staged((object(),))  # type: ignore[arg-type]
    staged, published = _document_pair(2)
    with pytest.raises(ConfigurationError):
        DocumentReference("bad\nreference")
    with pytest.raises(ConfigurationError):
        state.mark_documents_staged(
            (
                replace(
                    staged,
                    provenance=replace(
                        staged.provenance,
                        transaction_id_sha256=ContentSha256.from_bytes(b"wrong"),
                    ),
                ),
            )
        )
    with pytest.raises(ConfigurationError, match="transaction position"):
        state.mark_documents_staged(
            (replace(staged, staging_id=DocumentStagingId("F" * 64)),)
        )
    state = state.mark_documents_staged((staged,))
    with pytest.raises(ConfigurationError):
        state.fail()
    state = state.mark_positive_receipt_pending()
    state = state.mark_receipt_response_verified()
    with pytest.raises(ConfigurationError):
        state.finish()
    with pytest.raises(ConfigurationError):
        state.mark_documents_published((replace(published, size_bytes=9),))
    with pytest.raises(ConfigurationError):
        state.mark_documents_published(
            (replace(published, staging_id=DocumentStagingId("F" * 64)),)
        )
    state = state.mark_documents_published((published,))
    with pytest.raises(ConfigurationError):
        DownloadSession.restore(
            session_id=state.session_id,
            request_identity=state.request_identity,
            phase=state.phase,
            transaction_id=state.transaction_id,
            next_segment=state.next_segment,
            total_segments=state.total_segments,
            max_segments=state.max_segments,
            revision=state.revision,
            receipt_kind=state.receipt_kind,
            staged_documents=state.staged_documents,
            published_documents=(replace(published, size_bytes=9),),
        )
    state = state.finish()
    assert state.phase is DownloadPhase.COMPLETE
    assert state.published_documents == (published,)
    with pytest.raises(ConfigurationError):
        state.fail()

    with pytest.raises(TypeError):
        state.is_exact_successor_of(object())  # type: ignore[arg-type]


def test_download_state_cannot_be_forged_or_restored_incoherently() -> None:
    with pytest.raises(TypeError):
        DownloadSession(  # type: ignore[call-arg]
            "session", DownloadPhase.COMPLETE, None, 1, None, 10, 0, None
        )
    with pytest.raises(ConfigurationError):
        DownloadSession.restore(
            session_id="session",
            request_identity=_REQUEST_IDENTITY,
            phase=DownloadPhase.COMPLETE,
            transaction_id=_TRANSACTION_ID,
            next_segment=1,
            total_segments=2,
            max_segments=2,
            revision=1,
        )
    with pytest.raises(ConfigurationError):
        DownloadSession.restore(
            session_id="session",
            request_identity=_REQUEST_IDENTITY,
            phase=DownloadPhase.INITIALIZED,
            transaction_id=_TRANSACTION_ID,
            next_segment=2,
            total_segments=3,
            max_segments=3,
            revision=1,
        )
    with pytest.raises(ConfigurationError):
        DownloadSession.start(
            "session", _REQUEST_IDENTITY, ProtocolLimits(max_segments=1)
        ).initialize(transaction_id=_TRANSACTION_ID, total_segments=2)


def test_negative_receipt_and_ambiguous_receipt_are_explicit() -> None:
    state = DownloadSession.start(
        "session", _REQUEST_IDENTITY, ProtocolLimits(max_segments=1)
    )
    state = state.initialize(transaction_id=_TRANSACTION_ID, total_segments=1)
    state = state.record_segment(1)
    negative = state.mark_negative_receipt_pending()
    ambiguous = negative.mark_receipt_ambiguous()
    verified = ambiguous.mark_receipt_response_verified()
    with pytest.raises(ConfigurationError):
        verified.mark_documents_published((_document_pair()[1],))
    finished = verified.finish()
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

    orders = [OrderType.HAA]
    capabilities = CapabilityDiscovery(completed_orders=orders)  # type: ignore[arg-type]
    orders.append(OrderType.HPD)
    assert capabilities.completed_orders == (OrderType.HAA,)


def test_discovery_models_preserve_only_read_relevant_typed_results() -> None:
    descriptor = BtfDescriptor(
        service_name="EOP",
        scope=None,
        message_name="camt.053",
        message_version=None,
        variant=None,
        format="XML",
        service_option=None,
        container_type=ContainerType.NONE,
    )
    urls = [
        AdvertisedBankUrl(
            "https://future-bank.invalid/ebics",
            datetime(2027, 1, 1, tzinfo=timezone.utc),
        )
    ]
    parameters = BankParameters(
        urls=urls,  # type: ignore[arg-type]
        institute="Synthetic Bank",
        host_id="HOST",
        protocol_versions=["H005"],  # type: ignore[arg-type]
        authentication_versions=["X002"],  # type: ignore[arg-type]
        encryption_versions=["E002"],  # type: ignore[arg-type]
        signature_versions=["A006"],  # type: ignore[arg-type]
        recovery_supported=True,
        client_data_download_supported=True,
        downloadable_order_data_supported=True,
    )
    urls.append(AdvertisedBankUrl("https://ignored.invalid/ebics"))
    account = DiscoveredAccount(
        "ACCOUNT,= 1", "AT611904300234573201", restricted_services=[descriptor]
    )
    permission = DownloadPermission(descriptor, account.account_id)
    user = DiscoveredUser("USER,=1", 1, [permission])  # type: ignore[arg-type]
    customer_service = ServiceCapability(descriptor, OrderType.HTD)
    customer = CustomerInformation(
        OrderType.HTD,
        "HOST",
        [account],  # type: ignore[arg-type]
        [customer_service],  # type: ignore[arg-type]
        [user],  # type: ignore[arg-type]
    )
    result = CapabilityDiscovery(
        services=(customer_service,),
        bank_parameters=parameters,
        customer_information=[customer],  # type: ignore[arg-type]
        completed_orders=(OrderType.HPD, OrderType.HTD),
    )

    assert len(parameters.urls) == 1
    assert account.restricted_services == (descriptor,)
    assert result.customer_information == (customer,)
    assert "future-bank" not in repr(parameters)
    assert "ACCOUNT" not in repr(result)
    assert "USER" not in repr(result)
    assert "EOP" not in repr(result)
    assert "camt.053" not in repr(result)
    assert "status" not in repr(result)
    assert "EUR" not in repr(account)

    for changes in (
        {"service_name": "EO"},
        {"message_name": "CAMT.053"},
        {"message_version": "8"},
        {"variant": "0001"},
        {"format": "PLAIN"},
        {"service_option": "X"},
    ):
        with pytest.raises(ConfigurationError):
            replace(descriptor, **changes)  # type: ignore[arg-type]

    with pytest.raises(ConfigurationError):
        CustomerInformation(
            OrderType.HTD,
            "HOST",
            (account,),
            (),
            (user, DiscoveredUser("SECOND", 1, ())),
        )
    with pytest.raises(ConfigurationError):
        CustomerInformation(
            OrderType.HKD,
            "HOST",
            (),
            (ServiceCapability(descriptor, OrderType.HKD),),
            (DiscoveredUser("USER", 1, (DownloadPermission(descriptor, "MISSING"),)),),
        )
    with pytest.raises(ConfigurationError):
        CustomerInformation(
            OrderType.HKD,
            "HOST",
            (account,),
            (ServiceCapability(descriptor, OrderType.HKD),),
            (user, user),
        )
    with pytest.raises(ConfigurationError):
        DiscoveredUser("USER", 1, (permission, permission))
    with pytest.raises(ConfigurationError):
        CapabilityDiscovery(completed_orders=(OrderType.HPD,))
    with pytest.raises(ConfigurationError):
        ServiceCapability(descriptor, OrderType.HPD)
    with pytest.raises(ConfigurationError):
        replace(parameters, protocol_versions=("H005", "H005"))
    with pytest.raises(ConfigurationError):
        replace(parameters, authentication_versions=("A006",))
    with pytest.raises(TypeError):
        replace(parameters, recovery_supported=1)  # type: ignore[arg-type]
    with pytest.raises(ConfigurationError):
        DiscoveredAccount("ACCOUNT", currency="EURO")
    with pytest.raises(ConfigurationError):
        DiscoveredUser("bad-user", 1, ())
    with pytest.raises(ConfigurationError):
        DiscoveredUser("USER", 100, ())
    with pytest.raises(ConfigurationError):
        CapabilityDiscovery(
            services=(ServiceCapability(descriptor, OrderType.HAA),),
        )
    with pytest.raises(ConfigurationError):
        CapabilityDiscovery(
            completed_orders=(OrderType.HTD,),
            customer_information=(customer,),
        )
    with pytest.raises(ConfigurationError):
        CapabilityDiscovery(
            completed_orders=(OrderType.HAA, OrderType.HAA),
        )


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
