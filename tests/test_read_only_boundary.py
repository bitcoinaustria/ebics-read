from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from datetime import datetime, timezone

import pytest

import ebicsmit
from ebicsmit import (
    Bank,
    BtfDescriptor,
    CapabilityDiscovery,
    ContainerType,
    ContentSha256,
    DownloadedDocument,
    DownloadOptions,
    EbicsPublicKeyDigest,
    InitializationLetter,
    NegotiatedProtocol,
    OrderType,
    ProtocolVersion,
    ReadOnlyClient,
    RetrievalProvenance,
    Subscriber,
    TrustedBankKeys,
    UntrustedBankKeys,
    VersionDiscovery,
)
from ebicsmit.testing import (
    InMemoryBankKeyTrustStore,
    generate_synthetic_bank_keys,
    synthetic_out_of_band_identity,
)


@dataclass(slots=True)
class RecordingBackend:
    candidate: UntrustedBankKeys
    calls: list[str] = field(default_factory=list)
    controls: list[object] = field(default_factory=list)

    def probe_versions(self, bank: Bank, control: object) -> VersionDiscovery:
        self.calls.append("HEV")
        self.controls.append(control)
        return VersionDiscovery((ProtocolVersion("H005", "03.00"),))

    def initialize_signature_key(
        self,
        bank: Bank,
        subscriber: Subscriber,
        protocol: NegotiatedProtocol,
        control: object,
    ) -> InitializationLetter:
        assert protocol == NegotiatedProtocol()
        self.calls.append("INI")
        self.controls.append(control)
        return InitializationLetter(
            OrderType.INI, b"synthetic-letter", (EbicsPublicKeyDigest("A" * 64),)
        )

    def initialize_auth_encryption_keys(
        self,
        bank: Bank,
        subscriber: Subscriber,
        protocol: NegotiatedProtocol,
        control: object,
    ) -> InitializationLetter:
        assert protocol == NegotiatedProtocol()
        self.calls.append("HIA")
        self.controls.append(control)
        return InitializationLetter(
            OrderType.HIA, b"synthetic-letter", (EbicsPublicKeyDigest("B" * 64),)
        )

    def fetch_bank_keys(
        self,
        bank: Bank,
        subscriber: Subscriber,
        protocol: NegotiatedProtocol,
        control: object,
    ) -> UntrustedBankKeys:
        assert protocol == NegotiatedProtocol()
        self.calls.append("HPB")
        self.controls.append(control)
        return self.candidate

    def discover_capabilities(
        self,
        bank: Bank,
        subscriber: Subscriber,
        protocol: NegotiatedProtocol,
        trusted_bank_keys: TrustedBankKeys,
        control: object,
    ) -> CapabilityDiscovery:
        assert protocol == NegotiatedProtocol()
        self.calls.append("DISCOVERY")
        self.controls.append(control)
        return CapabilityDiscovery(completed_orders=(OrderType.HAA,))

    def download(
        self,
        bank: Bank,
        subscriber: Subscriber,
        protocol: NegotiatedProtocol,
        trusted_bank_keys: TrustedBankKeys,
        descriptor: BtfDescriptor,
        options: DownloadOptions,
        sink: object,
        control: object,
    ) -> tuple[DownloadedDocument, ...]:
        assert protocol == NegotiatedProtocol()
        self.calls.append("BTD")
        self.controls.append(control)
        return (
            DownloadedDocument(
                provenance=RetrievalProvenance(
                    descriptor=descriptor,
                    protocol=NegotiatedProtocol(),
                    retrieved_at=datetime(2026, 7, 15, tzinfo=timezone.utc),
                    transaction_id_sha256=ContentSha256.from_bytes(b"transaction"),
                    segment_count=1,
                    bank_host_id=bank.host_id,
                ),
                content_sha256=ContentSha256.from_bytes(b"opaque-synthetic-document"),
                size_bytes=len(b"opaque-synthetic-document"),
                sink_reference="synthetic-document-1",
            ),
        )


@dataclass(frozen=True)
class DummySink:
    pass


@dataclass(frozen=True)
class DummyControl:
    deadline: datetime = datetime(2026, 7, 16, tzinfo=timezone.utc)

    def raise_if_cancelled(self) -> None:
        return None


@pytest.fixture
def descriptor() -> BtfDescriptor:
    return BtfDescriptor(
        service_name="EOP",
        scope="AT",
        message_name="camt.053",
        message_version="08",
        variant="001",
        format="XML",
        service_option="STM",
        container_type=ContainerType.ZIP,
    )


@pytest.fixture
def client() -> tuple[ReadOnlyClient, RecordingBackend]:
    backend = RecordingBackend(
        generate_synthetic_bank_keys(datetime(2026, 7, 15, tzinfo=timezone.utc))
    )
    value = ReadOnlyClient(
        Bank("https://bank.invalid/ebics", "HOST"),
        Subscriber("PARTNER", "USER"),
        backend,
        InMemoryBankKeyTrustStore(),
    )
    return value, backend


def test_exact_order_allowlist_rejects_every_prohibited_order() -> None:
    assert {order.value for order in OrderType} == {
        "HEV",
        "INI",
        "HIA",
        "HPB",
        "HPD",
        "HAA",
        "HKD",
        "HTD",
        "BTD",
    }
    for prohibited in (
        "BTU",
        "HCA",
        "HCS",
        "SPR",
        "VEU",
        "EDS",
        "pain.001",
        "UPLOAD",
    ):
        with pytest.raises(ValueError):
            OrderType(prohibited)


def test_public_client_has_only_explicit_protocol_operations() -> None:
    methods = {
        name
        for name, value in inspect.getmembers(ReadOnlyClient, inspect.isfunction)
        if not name.startswith("_")
    }
    assert methods == {
        "accept_bank_keys",
        "discover_capabilities",
        "download",
        "fetch_bank_keys",
        "initialize_auth_encryption_keys",
        "initialize_signature_key",
        "probe_versions",
    }
    forbidden = {
        "execute",
        "execute_order",
        "raw_request",
        "request",
        "send",
        "submit",
        "upload",
        "send_payment",
        "btu",
    }
    assert forbidden.isdisjoint(ebicsmit.__all__)


def test_every_network_operation_requires_caller_control() -> None:
    operations = {
        "probe_versions",
        "initialize_signature_key",
        "initialize_auth_encryption_keys",
        "fetch_bank_keys",
        "discover_capabilities",
        "download",
    }
    for operation in operations:
        assert (
            "control"
            in inspect.signature(getattr(ReadOnlyClient, operation)).parameters
        )
        assert (
            "control"
            in inspect.signature(
                getattr(ebicsmit.ReadOnlyBackend, operation)
            ).parameters
        )


def test_initialization_is_explicit_and_not_a_business_upload(
    client: tuple[ReadOnlyClient, RecordingBackend],
) -> None:
    value, backend = client
    control = DummyControl()
    assert value.probe_versions(control) == NegotiatedProtocol()  # type: ignore[arg-type]
    assert value.initialize_signature_key(control).order is OrderType.INI  # type: ignore[arg-type]
    assert (
        value.initialize_auth_encryption_keys(control).order is OrderType.HIA  # type: ignore[arg-type]
    )
    assert backend.calls == ["HEV", "HEV", "INI", "HEV", "HIA"]
    assert backend.controls == [control] * 5


def test_hpb_keys_are_untrusted_until_oob_acceptance(
    client: tuple[ReadOnlyClient, RecordingBackend], descriptor: BtfDescriptor
) -> None:
    value, backend = client
    control = DummyControl()
    candidate = value.fetch_bank_keys(control)  # type: ignore[arg-type]

    with pytest.raises(ebicsmit.BankKeyNotTrustedError):
        value.download(descriptor, DummySink(), control)  # type: ignore[arg-type]
    assert backend.calls == ["HEV", "HPB"]

    expected = synthetic_out_of_band_identity(candidate)
    value.accept_bank_keys(candidate, expected)
    documents = value.download(  # type: ignore[arg-type]
        descriptor, DummySink(), control
    )

    assert documents[0].content_sha256 == ContentSha256.from_bytes(
        b"opaque-synthetic-document"
    )
    assert backend.calls == ["HEV", "HPB", "HEV", "BTD"]
    assert backend.controls == [control] * 4


def test_generic_request_parameter_mapping_no_longer_exists() -> None:
    assert "DownloadRequest" not in ebicsmit.__all__
    assert not hasattr(ebicsmit, "DownloadRequest")
    assert "parameters" not in inspect.signature(BtfDescriptor).parameters
