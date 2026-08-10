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

    def probe_versions(self, bank: Bank, control: OperationControl) -> VersionDiscovery:
        """Execute HEV/H000."""

    def initialize_signature_key(
        self,
        bank: Bank,
        subscriber: Subscriber,
        protocol: NegotiatedProtocol,
        control: OperationControl,
    ) -> InitializationLetter:
        """Execute INI and return initialization-letter data."""

    def initialize_auth_encryption_keys(
        self,
        bank: Bank,
        subscriber: Subscriber,
        protocol: NegotiatedProtocol,
        control: OperationControl,
    ) -> InitializationLetter:
        """Execute HIA and return initialization-letter data."""

    def fetch_bank_keys(
        self,
        bank: Bank,
        subscriber: Subscriber,
        protocol: NegotiatedProtocol,
        control: OperationControl,
    ) -> UntrustedBankKeys:
        """Execute HPB and return keys that are still unusable."""

    def discover_capabilities(
        self,
        bank: Bank,
        subscriber: Subscriber,
        protocol: NegotiatedProtocol,
        trusted_bank_keys: TrustedBankKeys,
        control: OperationControl,
    ) -> CapabilityDiscovery:
        """Defensively execute supported HPD/HAA/HKD/HTD discovery orders."""

    def download(
        self,
        bank: Bank,
        subscriber: Subscriber,
        protocol: NegotiatedProtocol,
        trusted_bank_keys: TrustedBankKeys,
        session_id: str,
        descriptor: BtfDescriptor,
        options: DownloadOptions,
        sink: DocumentSink,
        control: OperationControl,
    ) -> tuple[DownloadedDocument, ...]:
        """Execute a complete BTD transaction and receipt."""

    def resolve_ambiguous_receipt(
        self,
        bank: Bank,
        subscriber: Subscriber,
        protocol: NegotiatedProtocol,
        trusted_bank_keys: TrustedBankKeys,
        session_id: str,
        descriptor: BtfDescriptor,
        options: DownloadOptions,
        sink: DocumentSink,
        control: OperationControl,
        *,
        bank_confirmed_acceptance: bool,
    ) -> tuple[DownloadedDocument, ...]:
        """Publish or discard stages left by an unknown positive-receipt outcome."""


@dataclass(frozen=True, slots=True)
class ReadOnlyClient:
    """Application-neutral facade over exactly the allowlisted EBICS operations."""

    bank: Bank
    subscriber: Subscriber
    backend: ReadOnlyBackend
    bank_key_trust_store: BankKeyTrustStore

    def probe_versions(self, control: OperationControl) -> NegotiatedProtocol:
        """Execute HEV and pin the exact H005/03.00 protocol pair."""

        return self.backend.probe_versions(self.bank, control).select_h005()

    def initialize_signature_key(
        self,
        control: OperationControl,
        protocol: NegotiatedProtocol | None = None,
    ) -> InitializationLetter:
        return self.backend.initialize_signature_key(
            self.bank, self.subscriber, self._negotiate(control, protocol), control
        )

    def initialize_auth_encryption_keys(
        self,
        control: OperationControl,
        protocol: NegotiatedProtocol | None = None,
    ) -> InitializationLetter:
        return self.backend.initialize_auth_encryption_keys(
            self.bank, self.subscriber, self._negotiate(control, protocol), control
        )

    def fetch_bank_keys(
        self,
        control: OperationControl,
        protocol: NegotiatedProtocol | None = None,
    ) -> UntrustedBankKeys:
        """Fetch, but never silently accept, HPB bank keys."""

        return self.backend.fetch_bank_keys(
            self.bank, self.subscriber, self._negotiate(control, protocol), control
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

    def discover_capabilities(
        self,
        control: OperationControl,
        protocol: NegotiatedProtocol | None = None,
    ) -> CapabilityDiscovery:
        trusted = self.bank_key_trust_store.require_trusted(self.bank)
        return self.backend.discover_capabilities(
            self.bank,
            self.subscriber,
            self._negotiate(control, protocol),
            trusted,
            control,
        )

    def download(
        self,
        session_id: str,
        descriptor: BtfDescriptor,
        sink: DocumentSink,
        control: OperationControl,
        options: DownloadOptions | None = None,
        protocol: NegotiatedProtocol | None = None,
    ) -> tuple[DownloadedDocument, ...]:
        """Start or resume one caller-identified BTD transaction."""

        trusted = self.bank_key_trust_store.require_trusted(self.bank)
        return self.backend.download(
            self.bank,
            self.subscriber,
            self._negotiate(control, protocol),
            trusted,
            session_id,
            descriptor,
            options if options is not None else DownloadOptions(),
            sink,
            control,
        )

    def resolve_ambiguous_receipt(
        self,
        session_id: str,
        descriptor: BtfDescriptor,
        sink: DocumentSink,
        control: OperationControl,
        *,
        bank_confirmed_acceptance: bool,
        options: DownloadOptions | None = None,
        protocol: NegotiatedProtocol | None = None,
    ) -> tuple[DownloadedDocument, ...]:
        """Close out one BTD session whose positive receipt had no known outcome.

        Call this only after establishing with the bank whether it recorded the
        positive receipt. Every argument must match the original download, since
        the session is bound to the exact request identity.
        """

        trusted = self.bank_key_trust_store.require_trusted(self.bank)
        return self.backend.resolve_ambiguous_receipt(
            self.bank,
            self.subscriber,
            self._negotiate(control, protocol),
            trusted,
            session_id,
            descriptor,
            options if options is not None else DownloadOptions(),
            sink,
            control,
            bank_confirmed_acceptance=bank_confirmed_acceptance,
        )

    def _negotiate(
        self, control: OperationControl, protocol: NegotiatedProtocol | None
    ) -> NegotiatedProtocol:
        """Reuse a caller-supplied protocol or re-negotiate it with a fresh HEV.

        Passing the result of :meth:`probe_versions` avoids one extra HEV round
        trip per operation. It never widens the accepted versions: every value
        this can return has already been through ``select_h005``.
        """

        if protocol is None:
            return self.backend.probe_versions(self.bank, control).select_h005()
        if not isinstance(protocol, NegotiatedProtocol):
            raise TypeError("protocol must be a NegotiatedProtocol")
        return protocol
