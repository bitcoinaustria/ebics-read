"""Concrete protocol backend; currently only the complete HEV exchange exists."""

from __future__ import annotations

from dataclasses import dataclass, field

from .errors import OperationNotImplementedError
from .hev import parse_hev_response
from .interfaces import DocumentSink, OperationControl
from .models import (
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
from .transport import EbicsTransport, _PreparedTransportRequest
from .xml import XmlLimits


@dataclass(frozen=True, slots=True)
class EbicsBackend:
    """Connect fixed envelope builders, transport, and strict response parsers."""

    transport: EbicsTransport
    xml_limits: XmlLimits = field(default_factory=XmlLimits)

    def probe_versions(self, bank: Bank, control: OperationControl) -> VersionDiscovery:
        request = _PreparedTransportRequest._for_hev(bank)
        response = self.transport.exchange(request, control)
        return parse_hev_response(response.body, self.xml_limits)

    def initialize_signature_key(
        self,
        bank: Bank,
        subscriber: Subscriber,
        protocol: NegotiatedProtocol,
        control: OperationControl,
    ) -> InitializationLetter:
        raise OperationNotImplementedError("INI is not implemented")

    def initialize_auth_encryption_keys(
        self,
        bank: Bank,
        subscriber: Subscriber,
        protocol: NegotiatedProtocol,
        control: OperationControl,
    ) -> InitializationLetter:
        raise OperationNotImplementedError("HIA is not implemented")

    def fetch_bank_keys(
        self,
        bank: Bank,
        subscriber: Subscriber,
        protocol: NegotiatedProtocol,
        control: OperationControl,
    ) -> UntrustedBankKeys:
        raise OperationNotImplementedError("HPB is not implemented")

    def discover_capabilities(
        self,
        bank: Bank,
        subscriber: Subscriber,
        protocol: NegotiatedProtocol,
        trusted_bank_keys: TrustedBankKeys,
        control: OperationControl,
    ) -> CapabilityDiscovery:
        raise OperationNotImplementedError("discovery is not implemented")

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
        raise OperationNotImplementedError("BTD is not implemented")
