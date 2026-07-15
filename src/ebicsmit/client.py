"""Small high-level API for the fixed read-only operation set."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .interfaces import BankKeyTrustStore
from .models import (
    Bank,
    BankKeyFingerprints,
    BtfDescriptor,
    CapabilityDiscovery,
    DownloadedDocument,
    DownloadOptions,
    InitializationLetter,
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
        self, bank: Bank, subscriber: Subscriber
    ) -> InitializationLetter:
        """Execute INI and return initialization-letter data."""

    def initialize_auth_encryption_keys(
        self, bank: Bank, subscriber: Subscriber
    ) -> InitializationLetter:
        """Execute HIA and return initialization-letter data."""

    def fetch_bank_keys(self, bank: Bank, subscriber: Subscriber) -> UntrustedBankKeys:
        """Execute HPB and return keys that are still unusable."""

    def discover_capabilities(
        self,
        bank: Bank,
        subscriber: Subscriber,
        trusted_bank_keys: TrustedBankKeys,
    ) -> CapabilityDiscovery:
        """Defensively execute supported HPD/HAA/HKD/HTD discovery orders."""

    def download(
        self,
        bank: Bank,
        subscriber: Subscriber,
        trusted_bank_keys: TrustedBankKeys,
        descriptor: BtfDescriptor,
        options: DownloadOptions,
    ) -> tuple[DownloadedDocument, ...]:
        """Execute a complete BTD transaction and receipt."""


@dataclass(frozen=True, slots=True)
class ReadOnlyClient:
    """Application-neutral facade over exactly the allowlisted EBICS operations."""

    bank: Bank
    subscriber: Subscriber
    backend: ReadOnlyBackend
    bank_key_trust_store: BankKeyTrustStore

    def probe_versions(self) -> VersionDiscovery:
        return self.backend.probe_versions(self.bank)

    def initialize_signature_key(self) -> InitializationLetter:
        return self.backend.initialize_signature_key(self.bank, self.subscriber)

    def initialize_auth_encryption_keys(self) -> InitializationLetter:
        return self.backend.initialize_auth_encryption_keys(self.bank, self.subscriber)

    def fetch_bank_keys(self) -> UntrustedBankKeys:
        """Fetch, but never silently accept, HPB bank keys."""

        return self.backend.fetch_bank_keys(self.bank, self.subscriber)

    def accept_bank_keys(
        self,
        candidate: UntrustedBankKeys,
        expected_out_of_band: BankKeyFingerprints,
    ) -> TrustedBankKeys:
        """Explicitly pin fingerprints obtained through an out-of-band channel."""

        return self.bank_key_trust_store.accept(
            self.bank, candidate, expected_out_of_band
        )

    def discover_capabilities(self) -> CapabilityDiscovery:
        trusted = self.bank_key_trust_store.require_trusted(self.bank)
        return self.backend.discover_capabilities(self.bank, self.subscriber, trusted)

    def download(
        self,
        descriptor: BtfDescriptor,
        options: DownloadOptions | None = None,
    ) -> tuple[DownloadedDocument, ...]:
        trusted = self.bank_key_trust_store.require_trusted(self.bank)
        return self.backend.download(
            self.bank,
            self.subscriber,
            trusted,
            descriptor,
            options if options is not None else DownloadOptions(),
        )
