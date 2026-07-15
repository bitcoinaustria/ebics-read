from __future__ import annotations

import inspect
from dataclasses import dataclass, field

import pytest

import ebicsmit
from ebicsmit import (
    Bank,
    BankKeyFingerprints,
    BtfDescriptor,
    CapabilityDiscovery,
    ContainerType,
    DownloadedDocument,
    DownloadOptions,
    InitializationLetter,
    KeyFingerprint,
    OrderType,
    ProtocolVersion,
    ReadOnlyClient,
    Subscriber,
    TrustedBankKeys,
    UntrustedBankKeys,
    VersionDiscovery,
)
from ebicsmit.testing import InMemoryBankKeyTrustStore


@dataclass(slots=True)
class RecordingBackend:
    calls: list[str] = field(default_factory=list)

    def probe_versions(self, bank: Bank) -> VersionDiscovery:
        self.calls.append("HEV")
        return VersionDiscovery((ProtocolVersion("H005", "3.0"),))

    def initialize_signature_key(
        self, bank: Bank, subscriber: Subscriber
    ) -> InitializationLetter:
        self.calls.append("INI")
        return InitializationLetter(
            OrderType.INI, b"synthetic-letter", (KeyFingerprint("A" * 64),)
        )

    def initialize_auth_encryption_keys(
        self, bank: Bank, subscriber: Subscriber
    ) -> InitializationLetter:
        self.calls.append("HIA")
        return InitializationLetter(
            OrderType.HIA, b"synthetic-letter", (KeyFingerprint("B" * 64),)
        )

    def fetch_bank_keys(self, bank: Bank, subscriber: Subscriber) -> UntrustedBankKeys:
        self.calls.append("HPB")
        return UntrustedBankKeys(b"synthetic-auth-cert", b"synthetic-enc-cert")

    def discover_capabilities(
        self,
        bank: Bank,
        subscriber: Subscriber,
        trusted_bank_keys: TrustedBankKeys,
    ) -> CapabilityDiscovery:
        self.calls.append("DISCOVERY")
        return CapabilityDiscovery(completed_orders=(OrderType.HAA,))

    def download(
        self,
        bank: Bank,
        subscriber: Subscriber,
        trusted_bank_keys: TrustedBankKeys,
        descriptor: BtfDescriptor,
        options: DownloadOptions,
    ) -> tuple[DownloadedDocument, ...]:
        self.calls.append("BTD")
        return (
            DownloadedDocument(
                service_name=descriptor.service_name,
                scope=descriptor.scope,
                message_name=descriptor.message_name,
                message_version=descriptor.message_version,
                variant=descriptor.variant,
                format=descriptor.format,
                service_option=descriptor.service_option,
                container_type=descriptor.container_type,
                content=b"opaque-synthetic-document",
            ),
        )


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
    backend = RecordingBackend()
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


def test_initialization_is_explicit_and_not_a_business_upload(
    client: tuple[ReadOnlyClient, RecordingBackend],
) -> None:
    value, backend = client
    assert value.probe_versions().versions[0].protocol_version == "H005"
    assert value.initialize_signature_key().order is OrderType.INI
    assert value.initialize_auth_encryption_keys().order is OrderType.HIA
    assert backend.calls == ["HEV", "INI", "HIA"]


def test_hpb_keys_are_untrusted_until_oob_acceptance(
    client: tuple[ReadOnlyClient, RecordingBackend], descriptor: BtfDescriptor
) -> None:
    value, backend = client
    candidate = value.fetch_bank_keys()

    with pytest.raises(ebicsmit.BankKeyNotTrustedError):
        value.download(descriptor)
    assert backend.calls == ["HPB"]

    expected = BankKeyFingerprints(
        candidate.fingerprints.authentication,
        candidate.fingerprints.encryption,
    )
    value.accept_bank_keys(candidate, expected)
    documents = value.download(descriptor)

    assert documents[0].content == b"opaque-synthetic-document"
    assert backend.calls == ["HPB", "BTD"]


def test_generic_request_parameter_mapping_no_longer_exists() -> None:
    assert "DownloadRequest" not in ebicsmit.__all__
    assert not hasattr(ebicsmit, "DownloadRequest")
    assert "parameters" not in inspect.signature(BtfDescriptor).parameters
