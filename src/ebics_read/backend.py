"""Concrete fixed-operation protocol backend."""

from __future__ import annotations

from dataclasses import dataclass, field

from .certificates import (
    SelfSignedH005BankCertificateProfile,
    _validate_subscriber_authentication_encryption_certificates,
    _validate_subscriber_signature_certificate,
    _validate_subscriber_transport_certificates,
)
from .errors import (
    AmbiguousInitializationError,
    ConfigurationError,
    OperationNotImplementedError,
    ResponseLimitError,
    TransientTransportError,
    TransportError,
)
from .hev import parse_hev_response
from .hia import _render_hia_letter
from .hpb import _parse_hpb_response
from .ini import _parse_key_initialization_response, _render_ini_letter
from .interfaces import (
    BankCertificateProfile,
    Clock,
    DocumentSink,
    KeyProvider,
    KeyPurpose,
    NonceSource,
    OperationControl,
)
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
    nonce_source: NonceSource | None = field(default=None, repr=False)
    bank_certificate_profile: BankCertificateProfile = field(
        default_factory=SelfSignedH005BankCertificateProfile, repr=False
    )

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
            _parse_key_initialization_response(response.body, self.xml_limits)
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
        if self.key_provider is None or self.clock is None:
            raise ConfigurationError("HIA requires a key provider and clock")
        if bank.institution_name is None:
            raise ConfigurationError("HIA requires the recipient institution name")
        processed_at = self.clock.now()
        signature_der = self.key_provider.certificate_der(KeyPurpose.SIGNATURE)
        authentication_der = self.key_provider.certificate_der(
            KeyPurpose.AUTHENTICATION
        )
        encryption_der = self.key_provider.certificate_der(KeyPurpose.ENCRYPTION)
        authentication, encryption = (
            _validate_subscriber_authentication_encryption_certificates(
                signature_der, authentication_der, encryption_der, processed_at
            )
        )
        request = _PreparedTransportRequest._for_hia(
            bank,
            subscriber,
            protocol,
            authentication_der,
            encryption_der,
        )
        letter = _render_hia_letter(
            bank, subscriber, authentication, encryption, processed_at
        )
        try:
            response = self.transport.exchange(request, control)
            _parse_key_initialization_response(response.body, self.xml_limits)
        except TransientTransportError:
            raise
        except (ResponseLimitError, TransportError) as exc:
            raise AmbiguousInitializationError(letter) from exc
        return letter

    def fetch_bank_keys(
        self,
        bank: Bank,
        subscriber: Subscriber,
        protocol: NegotiatedProtocol,
        control: OperationControl,
    ) -> UntrustedBankKeys:
        if self.key_provider is None or self.clock is None or self.nonce_source is None:
            raise ConfigurationError(
                "HPB requires a key provider, clock, and nonce source"
            )
        authentication_der = self.key_provider.certificate_der(
            KeyPurpose.AUTHENTICATION
        )
        encryption_der = self.key_provider.certificate_der(KeyPurpose.ENCRYPTION)
        nonce = self.nonce_source.random_bytes(16)
        if type(nonce) is not bytes or len(nonce) != 16:
            raise ConfigurationError("HPB nonce source must return exactly 16 bytes")
        requested_at = self.clock.now()
        _validate_subscriber_transport_certificates(
            authentication_der, encryption_der, requested_at
        )
        request = _PreparedTransportRequest._for_hpb(
            bank,
            subscriber,
            protocol,
            nonce,
            requested_at,
            self.key_provider,
            authentication_der,
        )
        response = self.transport.exchange(request, control)
        return _parse_hpb_response(
            response.body,
            bank,
            encryption_der,
            self.key_provider,
            self.bank_certificate_profile,
            self.clock.now(),
            self.xml_limits,
        )

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
