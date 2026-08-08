"""Concrete fixed-operation protocol backend."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TypeVar

from .certificates import (
    SelfSignedH005BankCertificateProfile,
    _validate_subscriber_authentication_encryption_certificates,
    _validate_subscriber_signature_certificate,
    _validate_subscriber_transport_certificates,
)
from .errors import (
    AmbiguousInitializationError,
    ConfigurationError,
    EbicsReturnCodeError,
    OperationNotImplementedError,
    ProtocolError,
    ResponseLimitError,
    TransientTransportError,
    TransportError,
)
from .haa import (
    _decode_haa_services,
    _encoded_order_data_limit,
    _HaaInitialResponse,
    _HaaOrderDataFragment,
    _parse_haa_initial_response,
    _parse_haa_receipt_response,
    _parse_haa_transfer_response,
    _validate_order_data_fragment,
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
    SessionStore,
)
from .models import (
    Bank,
    BtfDescriptor,
    CapabilityDiscovery,
    DownloadedDocument,
    DownloadOptions,
    InitializationLetter,
    NegotiatedProtocol,
    ProtocolLimits,
    ReceiptKind,
    Subscriber,
    TransactionId,
    TrustedBankKeys,
    UntrustedBankKeys,
    VersionDiscovery,
)
from .orders import OrderType
from .transport import EbicsTransport, _PreparedTransportRequest
from .xml import XmlLimits

_DiscoveryPayload = TypeVar("_DiscoveryPayload")


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
    session_store: SessionStore | None = field(default=None, repr=False)
    protocol_limits: ProtocolLimits = field(default_factory=ProtocolLimits, repr=False)

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
        if (
            self.key_provider is None
            or self.clock is None
            or self.nonce_source is None
            or self.session_store is None
        ):
            raise ConfigurationError(
                "HAA requires a key provider, clock, nonce source, and session store"
            )
        key_provider = self.key_provider
        authentication_der = key_provider.certificate_der(KeyPurpose.AUTHENTICATION)
        encryption_der = key_provider.certificate_der(KeyPurpose.ENCRYPTION)
        nonce = self.nonce_source.random_bytes(16)
        if type(nonce) is not bytes or len(nonce) != 16:
            raise ConfigurationError("HAA nonce source must return exactly 16 bytes")
        requested_at = self.clock.now()
        _validate_subscriber_transport_certificates(
            authentication_der, encryption_der, requested_at
        )
        request = _PreparedTransportRequest._for_haa_initialization(
            bank,
            subscriber,
            protocol,
            trusted_bank_keys,
            nonce,
            requested_at,
            key_provider,
            authentication_der,
        )
        response = self.transport.exchange(request, control)
        try:
            initialization = _parse_haa_initial_response(
                response.body,
                trusted_bank_keys,
                encryption_der,
                key_provider,
                self.xml_limits,
                self.protocol_limits,
            )
        except EbicsReturnCodeError as exc:
            if exc.technical == "091006" and exc.business == "000000":
                return CapabilityDiscovery(unsupported_orders=(OrderType.HAA,))
            raise
        services = self._download_metadata(
            initialization,
            lambda transaction_id, segment_number: (
                _PreparedTransportRequest._for_haa_transfer(
                    bank,
                    protocol,
                    transaction_id,
                    segment_number,
                    key_provider,
                    authentication_der,
                )
            ),
            lambda body, transaction_id, segment_number, total_segments: (
                _parse_haa_transfer_response(
                    body,
                    trusted_bank_keys,
                    transaction_id,
                    segment_number,
                    total_segments,
                    self.xml_limits,
                )
            ),
            lambda fragments, transaction_key: _decode_haa_services(
                fragments,
                transaction_key,
                self.xml_limits,
                self.protocol_limits,
            ),
            lambda transaction_id, receipt: _PreparedTransportRequest._for_haa_receipt(
                bank,
                protocol,
                transaction_id,
                receipt,
                key_provider,
                authentication_der,
            ),
            lambda body, transaction_id, receipt: _parse_haa_receipt_response(
                body,
                trusted_bank_keys,
                transaction_id,
                receipt,
                self.xml_limits,
            ),
            control,
        )
        return CapabilityDiscovery(services=services, completed_orders=(OrderType.HAA,))

    def _download_metadata(
        self,
        initialization: _HaaInitialResponse,
        transfer_request: Callable[[TransactionId, int], _PreparedTransportRequest],
        parse_transfer: Callable[
            [bytes, TransactionId, int, int], _HaaOrderDataFragment
        ],
        decode_payload: Callable[[list[str], bytes], _DiscoveryPayload],
        receipt_request: Callable[
            [TransactionId, ReceiptKind], _PreparedTransportRequest
        ],
        parse_receipt: Callable[[bytes, TransactionId, ReceiptKind], None],
        control: OperationControl,
    ) -> _DiscoveryPayload:
        if self.session_store is None:
            raise AssertionError("metadata-download session store disappeared")
        self.session_store.claim_transaction_id(initialization.transaction_id)
        fragments: list[str] = []
        final_fragment = (
            initialization.first_fragment
            if initialization.total_segments == 1
            else None
        )
        encoded_size = 0
        encoded_limit = _encoded_order_data_limit(self.protocol_limits)
        if initialization.total_segments > 1:
            first_fragment = _validate_order_data_fragment(
                initialization.first_fragment, last=False
            )
            fragments.append(first_fragment)
            encoded_size = len(first_fragment)
            if encoded_size > encoded_limit:
                raise ResponseLimitError(
                    "HAA encoded order data exceeds the configured limit"
                )
        for segment_number in range(2, initialization.total_segments + 1):
            request = transfer_request(initialization.transaction_id, segment_number)
            response = self.transport.exchange(request, control)
            fragment = parse_transfer(
                response.body,
                initialization.transaction_id,
                segment_number,
                initialization.total_segments,
            )
            if segment_number < initialization.total_segments:
                value = _validate_order_data_fragment(fragment, last=False)
                next_encoded_size = encoded_size + len(value)
                if next_encoded_size > encoded_limit:
                    raise ResponseLimitError(
                        "HAA encoded order data exceeds the configured limit"
                    )
                fragments.append(value)
                encoded_size = next_encoded_size
            else:
                final_fragment = fragment
        if final_fragment is None:
            raise AssertionError("HAA final segment was not collected")
        try:
            fragments.append(_validate_order_data_fragment(final_fragment, last=True))
            payload = decode_payload(fragments, initialization.transaction_key)
        except ProtocolError:
            self._acknowledge_metadata(
                initialization.transaction_id,
                ReceiptKind.NEGATIVE,
                receipt_request,
                parse_receipt,
                control,
            )
            raise
        self._acknowledge_metadata(
            initialization.transaction_id,
            ReceiptKind.POSITIVE,
            receipt_request,
            parse_receipt,
            control,
        )
        return payload

    def _acknowledge_metadata(
        self,
        transaction_id: TransactionId,
        receipt: ReceiptKind,
        receipt_request: Callable[
            [TransactionId, ReceiptKind], _PreparedTransportRequest
        ],
        parse_receipt: Callable[[bytes, TransactionId, ReceiptKind], None],
        control: OperationControl,
    ) -> None:
        request = receipt_request(transaction_id, receipt)
        response = self.transport.exchange(request, control)
        parse_receipt(response.body, transaction_id, receipt)

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
