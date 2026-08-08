"""Concrete fixed-operation protocol backend."""

from __future__ import annotations

from dataclasses import dataclass, field

from .certificates import _validate_subscriber_signature_certificate
from .errors import (
    AmbiguousInitializationError,
    ConfigurationError,
    OperationNotImplementedError,
    ResponseLimitError,
    TransientTransportError,
    TransportError,
)
from .hev import parse_hev_response
from .ini import _parse_ini_response, _render_ini_letter
from .interfaces import Clock, DocumentSink, KeyProvider, KeyPurpose, OperationControl
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
    key_provider: KeyProvider | None = field(default=None, repr=False)
    clock: Clock | None = field(default=None, repr=False)

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
        if self.key_provider is None or self.clock is None:
            raise ConfigurationError("INI requires a key provider and clock")
        if bank.institution_name is None:
            raise ConfigurationError("INI requires the recipient institution name")
        processed_at = self.clock.now()
        certificate_der = self.key_provider.certificate_der(KeyPurpose.SIGNATURE)
        certificate = _validate_subscriber_signature_certificate(
            certificate_der, processed_at
        )
        request = _PreparedTransportRequest._for_ini(
            bank, subscriber, protocol, certificate_der
        )
        letter = _render_ini_letter(bank, subscriber, certificate, processed_at)
        try:
            response = self.transport.exchange(request, control)
            _parse_ini_response(response.body, self.xml_limits)
        except TransientTransportError:
            raise
        except (ResponseLimitError, TransportError) as exc:
            raise AmbiguousInitializationError(letter) from exc
        return letter

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
        session_id: str,
        descriptor: BtfDescriptor,
        options: DownloadOptions,
        sink: DocumentSink,
        control: OperationControl,
    ) -> tuple[DownloadedDocument, ...]:
        raise OperationNotImplementedError("BTD is not implemented")
