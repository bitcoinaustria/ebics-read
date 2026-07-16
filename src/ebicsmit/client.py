"""Small high-level API for the fixed read-only operation set."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .interfaces import BankKeyTrustStore, DocumentSink, OperationControl
from .models import (
    AcceptedBankKeyIdentity,
    Bank,
    BtfDescriptor,
    CapabilityDiscovery,
    DownloadedDocument,
    DownloadOptions,
    InitializationLetter,
    NegotiatedProtocol,
    Subscriber,
    TrustedBankKeys,
    UntrustedBankKeys,
    VersionDiscovery,
)


class ReadOnlyBackend(Protocol):
    """Internal protocol engine contract with no generic order execution method."""

    def probe_versions(self, bank: Bank) -> VersionDiscovery:
        """Execute HEV/H000."""

    def initialize_signature_key(
        self,
        bank: Bank,
        subscriber: Subscriber,
        protocol: NegotiatedProtocol,
    ) -> InitializationLetter:
        """Execute INI and return initialization-letter data."""

    def initialize_auth_encryption_keys(
        self,
        bank: Bank,
        subscriber: Subscriber,
        protocol: NegotiatedProtocol,
    ) -> InitializationLetter:
        """Execute HIA and return initialization-letter data."""

    def fetch_bank_keys(
        self,
        bank: Bank,
        subscriber: Subscriber,
        protocol: NegotiatedProtocol,
    ) -> UntrustedBankKeys:
        """Execute HPB and return keys that are still unusable."""

    def discover_capabilities(
        self,
        bank: Bank,
        subscriber: Subscriber,
        protocol: NegotiatedProtocol,
        trusted_bank_keys: TrustedBankKeys,
    ) -> CapabilityDiscovery:
        """Defensively execute supported HPD/HAA/HKD/HTD discovery orders."""

    def download(
        self,
        bank: Bank,
        subscriber: Subscriber,
        protocol: NegotiatedProtocol,
        trusted_bank_keys: TrustedBankKeys,
        descriptor: BtfDescriptor,
        options: DownloadOptions,
        sink: DocumentSink,
        control: OperationControl,
    ) -> tuple[DownloadedDocument, ...]:
        """Execute a complete BTD transaction and receipt."""


@dataclass(frozen=True, slots=True)
class ReadOnlyClient:
    """Application-neutral facade over exactly the allowlisted EBICS operations."""

    bank: Bank
    subscriber: Subscriber
    backend: ReadOnlyBackend
    bank_key_trust_store: BankKeyTrustStore

    def probe_versions(self) -> NegotiatedProtocol:
        """Execute HEV and pin the exact H005/03.00 protocol pair."""

        return self.backend.probe_versions(self.bank).select_h005()

    def initialize_signature_key(self) -> InitializationLetter:
        return self.backend.initialize_signature_key(
            self.bank, self.subscriber, self._negotiate()
        )

    def initialize_auth_encryption_keys(self) -> InitializationLetter:
        return self.backend.initialize_auth_encryption_keys(
            self.bank, self.subscriber, self._negotiate()
        )

    def fetch_bank_keys(self) -> UntrustedBankKeys:
        """Fetch, but never silently accept, HPB bank keys."""

        return self.backend.fetch_bank_keys(
            self.bank, self.subscriber, self._negotiate()
        )

    def accept_bank_keys(
        self,
        candidate: UntrustedBankKeys,
        expected_out_of_band: AcceptedBankKeyIdentity,
    ) -> TrustedBankKeys:
        """Explicitly pin EBICS key identities obtained out of band."""

        return self.bank_key_trust_store.accept(
            self.bank, candidate, expected_out_of_band
        )

    def discover_capabilities(self) -> CapabilityDiscovery:
        trusted = self.bank_key_trust_store.require_trusted(self.bank)
        return self.backend.discover_capabilities(
            self.bank, self.subscriber, self._negotiate(), trusted
        )

    def download(
        self,
        descriptor: BtfDescriptor,
        sink: DocumentSink,
        control: OperationControl,
        options: DownloadOptions | None = None,
    ) -> tuple[DownloadedDocument, ...]:
        trusted = self.bank_key_trust_store.require_trusted(self.bank)
        return self.backend.download(
            self.bank,
            self.subscriber,
            self._negotiate(),
            trusted,
            descriptor,
            options if options is not None else DownloadOptions(),
            sink,
            control,
        )

    def _negotiate(self) -> NegotiatedProtocol:
        """Re-negotiate and pass the exact protocol into every H005 operation."""

        return self.backend.probe_versions(self.bank).select_h005()
