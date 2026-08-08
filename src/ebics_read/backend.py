"""Concrete fixed-operation protocol backend."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TypeVar

from .btd import (
    _download_request_identity,
    _parse_btd_initial_response,
    _parse_btd_transfer_response,
)
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
    SecurityError,
    SessionConflictError,
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
from .hkd import (
    _decode_hkd_information,
    _parse_hkd_initial_response,
    _parse_hkd_receipt_response,
    _parse_hkd_transfer_response,
)
from .hpb import _parse_hpb_response
from .hpd import (
    _decode_hpd_parameters,
    _parse_hpd_initial_response,
    _parse_hpd_receipt_response,
    _parse_hpd_transfer_response,
)
from .htd import (
    _decode_htd_information,
    _parse_htd_initial_response,
    _parse_htd_receipt_response,
    _parse_htd_transfer_response,
)
from .ini import _parse_key_initialization_response, _render_ini_letter
from .interfaces import (
    BankCertificateProfile,
    Clock,
    DocumentSink,
    KeyProvider,
    KeyPurpose,
    NonceSource,
    OperationControl,
    SegmentStore,
    SessionStore,
)
from .models import (
    Bank,
    BtfDescriptor,
    CapabilityDiscovery,
    DownloadedDocument,
    DownloadOptions,
    DownloadPhase,
    DownloadSession,
    InitializationLetter,
    NegotiatedProtocol,
    ProtocolLimits,
    ReceiptKind,
    SegmentReference,
    SessionLease,
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


def _btd_spool_index(
    state: DownloadSession,
    entries: tuple[tuple[int, SegmentReference], ...],
) -> dict[int, SegmentReference]:
    numbers = tuple(number for number, _ in entries)
    references = tuple(reference for _, reference in entries)
    if (
        any(type(number) is not int or number <= 0 for number in numbers)
        or numbers != tuple(sorted(numbers))
        or len(numbers) != len(set(numbers))
        or len(references) != len(set(references))
    ):
        raise SecurityError("BTD spool integrity check failed")
    if state.phase is DownloadPhase.NEW:
        allowed = {(), (1,)}
    elif state.phase in {
        DownloadPhase.INITIALIZED,
        DownloadPhase.RECEIVING_SEGMENTS,
    }:
        prefix = tuple(range(1, state.next_segment))
        allowed = {prefix, (*prefix, state.next_segment)}
        if state.phase is DownloadPhase.INITIALIZED:
            allowed = {(1,)}
    elif state.phase in {
        DownloadPhase.SEGMENTS_RECEIVED,
        DownloadPhase.SIGNATURES_AND_DIGESTS_VERIFIED,
    }:
        if state.total_segments is None:
            raise SessionConflictError("BTD session lacks a segment count")
        allowed = {tuple(range(1, state.total_segments + 1))}
    else:
        raise SessionConflictError("BTD receive phase cannot be resumed")
    if numbers not in allowed:
        raise SecurityError("BTD spool does not match durable session state")
    return dict(entries)


def _validate_btd_first_fragment(
    initialization: _HaaInitialResponse, protocol_limits: ProtocolLimits
) -> None:
    value = _validate_order_data_fragment(
        initialization.first_fragment,
        last=initialization.total_segments == 1,
    )
    if len(value) > _encoded_order_data_limit(protocol_limits):
        raise ResponseLimitError("BTD encoded order data exceeds the configured limit")


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
    segment_store: SegmentStore | None = field(default=None, repr=False)

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
        hpd = self._discover_hpd(bank, subscriber, protocol, trusted_bank_keys, control)
        if (
            hpd.bank_parameters is not None
            and not hpd.bank_parameters.downloadable_order_data_supported
        ):
            haa = CapabilityDiscovery(unsupported_orders=(OrderType.HAA,))
        else:
            haa = self._discover_haa(
                bank, subscriber, protocol, trusted_bank_keys, control
            )
        if (
            hpd.bank_parameters is not None
            and not hpd.bank_parameters.client_data_download_supported
        ):
            hkd = CapabilityDiscovery(unsupported_orders=(OrderType.HKD,))
            htd = CapabilityDiscovery(unsupported_orders=(OrderType.HTD,))
        else:
            hkd = self._discover_hkd(
                bank, subscriber, protocol, trusted_bank_keys, control
            )
            htd = self._discover_htd(
                bank, subscriber, protocol, trusted_bank_keys, control
            )
        return CapabilityDiscovery(
            services=(*haa.services, *hkd.services, *htd.services),
            completed_orders=(
                *hpd.completed_orders,
                *haa.completed_orders,
                *hkd.completed_orders,
                *htd.completed_orders,
            ),
            unsupported_orders=(
                *hpd.unsupported_orders,
                *haa.unsupported_orders,
                *hkd.unsupported_orders,
                *htd.unsupported_orders,
            ),
            bank_parameters=hpd.bank_parameters,
            customer_information=(
                *hkd.customer_information,
                *htd.customer_information,
            ),
        )

    def _discover_haa(
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

    def _discover_hpd(
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
                "HPD requires a key provider, clock, nonce source, and session store"
            )
        key_provider = self.key_provider
        authentication_der = key_provider.certificate_der(KeyPurpose.AUTHENTICATION)
        encryption_der = key_provider.certificate_der(KeyPurpose.ENCRYPTION)
        nonce = self.nonce_source.random_bytes(16)
        if type(nonce) is not bytes or len(nonce) != 16:
            raise ConfigurationError("HPD nonce source must return exactly 16 bytes")
        requested_at = self.clock.now()
        _validate_subscriber_transport_certificates(
            authentication_der, encryption_der, requested_at
        )
        request = _PreparedTransportRequest._for_hpd_initialization(
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
            initialization = _parse_hpd_initial_response(
                response.body,
                trusted_bank_keys,
                encryption_der,
                key_provider,
                self.xml_limits,
                self.protocol_limits,
            )
        except EbicsReturnCodeError as exc:
            if exc.technical == "091006" and exc.business == "000000":
                return CapabilityDiscovery(unsupported_orders=(OrderType.HPD,))
            raise
        parameters = self._download_metadata(
            initialization,
            lambda transaction_id, segment_number: (
                _PreparedTransportRequest._for_hpd_transfer(
                    bank,
                    protocol,
                    transaction_id,
                    segment_number,
                    key_provider,
                    authentication_der,
                )
            ),
            lambda body, transaction_id, segment_number, total_segments: (
                _parse_hpd_transfer_response(
                    body,
                    trusted_bank_keys,
                    transaction_id,
                    segment_number,
                    total_segments,
                    self.xml_limits,
                )
            ),
            lambda fragments, transaction_key: _decode_hpd_parameters(
                fragments,
                transaction_key,
                bank.host_id,
                initialization.bank_parameter_timestamp,
                self.xml_limits,
                self.protocol_limits,
            ),
            lambda transaction_id, receipt: _PreparedTransportRequest._for_hpd_receipt(
                bank,
                protocol,
                transaction_id,
                receipt,
                key_provider,
                authentication_der,
            ),
            lambda body, transaction_id, receipt: _parse_hpd_receipt_response(
                body,
                trusted_bank_keys,
                transaction_id,
                receipt,
                self.xml_limits,
            ),
            control,
        )
        return CapabilityDiscovery(
            bank_parameters=parameters, completed_orders=(OrderType.HPD,)
        )

    def _discover_hkd(
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
                "HKD requires a key provider, clock, nonce source, and session store"
            )
        key_provider = self.key_provider
        authentication_der = key_provider.certificate_der(KeyPurpose.AUTHENTICATION)
        encryption_der = key_provider.certificate_der(KeyPurpose.ENCRYPTION)
        nonce = self.nonce_source.random_bytes(16)
        if type(nonce) is not bytes or len(nonce) != 16:
            raise ConfigurationError("HKD nonce source must return exactly 16 bytes")
        requested_at = self.clock.now()
        _validate_subscriber_transport_certificates(
            authentication_der, encryption_der, requested_at
        )
        request = _PreparedTransportRequest._for_hkd_initialization(
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
            initialization = _parse_hkd_initial_response(
                response.body,
                trusted_bank_keys,
                encryption_der,
                key_provider,
                self.xml_limits,
                self.protocol_limits,
            )
        except EbicsReturnCodeError as exc:
            if exc.technical == "091006" and exc.business == "000000":
                return CapabilityDiscovery(unsupported_orders=(OrderType.HKD,))
            raise
        information = self._download_metadata(
            initialization,
            lambda transaction_id, segment_number: (
                _PreparedTransportRequest._for_hkd_transfer(
                    bank,
                    protocol,
                    transaction_id,
                    segment_number,
                    key_provider,
                    authentication_der,
                )
            ),
            lambda body, transaction_id, segment_number, total_segments: (
                _parse_hkd_transfer_response(
                    body,
                    trusted_bank_keys,
                    transaction_id,
                    segment_number,
                    total_segments,
                    self.xml_limits,
                )
            ),
            lambda fragments, transaction_key: _decode_hkd_information(
                fragments,
                transaction_key,
                bank.host_id,
                subscriber.user_id,
                self.xml_limits,
                self.protocol_limits,
            ),
            lambda transaction_id, receipt: _PreparedTransportRequest._for_hkd_receipt(
                bank,
                protocol,
                transaction_id,
                receipt,
                key_provider,
                authentication_der,
            ),
            lambda body, transaction_id, receipt: _parse_hkd_receipt_response(
                body,
                trusted_bank_keys,
                transaction_id,
                receipt,
                self.xml_limits,
            ),
            control,
        )
        return CapabilityDiscovery(
            services=information.services,
            completed_orders=(OrderType.HKD,),
            customer_information=(information,),
        )

    def _discover_htd(
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
                "HTD requires a key provider, clock, nonce source, and session store"
            )
        key_provider = self.key_provider
        authentication_der = key_provider.certificate_der(KeyPurpose.AUTHENTICATION)
        encryption_der = key_provider.certificate_der(KeyPurpose.ENCRYPTION)
        nonce = self.nonce_source.random_bytes(16)
        if type(nonce) is not bytes or len(nonce) != 16:
            raise ConfigurationError("HTD nonce source must return exactly 16 bytes")
        requested_at = self.clock.now()
        _validate_subscriber_transport_certificates(
            authentication_der, encryption_der, requested_at
        )
        request = _PreparedTransportRequest._for_htd_initialization(
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
            initialization = _parse_htd_initial_response(
                response.body,
                trusted_bank_keys,
                encryption_der,
                key_provider,
                self.xml_limits,
                self.protocol_limits,
            )
        except EbicsReturnCodeError as exc:
            if exc.technical == "091006" and exc.business == "000000":
                return CapabilityDiscovery(unsupported_orders=(OrderType.HTD,))
            raise
        information = self._download_metadata(
            initialization,
            lambda transaction_id, segment_number: (
                _PreparedTransportRequest._for_htd_transfer(
                    bank,
                    protocol,
                    transaction_id,
                    segment_number,
                    key_provider,
                    authentication_der,
                )
            ),
            lambda body, transaction_id, segment_number, total_segments: (
                _parse_htd_transfer_response(
                    body,
                    trusted_bank_keys,
                    transaction_id,
                    segment_number,
                    total_segments,
                    self.xml_limits,
                )
            ),
            lambda fragments, transaction_key: _decode_htd_information(
                fragments,
                transaction_key,
                bank.host_id,
                subscriber.user_id,
                self.xml_limits,
                self.protocol_limits,
            ),
            lambda transaction_id, receipt: _PreparedTransportRequest._for_htd_receipt(
                bank,
                protocol,
                transaction_id,
                receipt,
                key_provider,
                authentication_der,
            ),
            lambda body, transaction_id, receipt: _parse_htd_receipt_response(
                body,
                trusted_bank_keys,
                transaction_id,
                receipt,
                self.xml_limits,
            ),
            control,
        )
        return CapabilityDiscovery(
            services=information.services,
            completed_orders=(OrderType.HTD,),
            customer_information=(information,),
        )

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

    def _receive_btd_segments(
        self,
        bank: Bank,
        subscriber: Subscriber,
        protocol: NegotiatedProtocol,
        trusted_bank_keys: TrustedBankKeys,
        session_id: str,
        descriptor: BtfDescriptor,
        options: DownloadOptions,
        control: OperationControl,
    ) -> DownloadSession:
        """Receive and durably verify all BTD response segments without plaintext."""

        if (
            self.key_provider is None
            or self.clock is None
            or self.nonce_source is None
            or self.session_store is None
            or self.segment_store is None
        ):
            raise ConfigurationError(
                "BTD requires key, clock, nonce, session, and segment providers"
            )
        if options.account is not None:
            raise ConfigurationError(
                "H005 defines no portable BTD account-selector parameter"
            )
        key_provider = self.key_provider
        session_store = self.session_store
        segment_store = self.segment_store
        authentication_der = key_provider.certificate_der(KeyPurpose.AUTHENTICATION)
        encryption_der = key_provider.certificate_der(KeyPurpose.ENCRYPTION)
        requested_at = self.clock.now()
        _validate_subscriber_transport_certificates(
            authentication_der, encryption_der, requested_at
        )
        request_identity = _download_request_identity(
            bank,
            subscriber,
            protocol,
            trusted_bank_keys,
            descriptor,
            options,
            self.protocol_limits,
            self.xml_limits,
            authentication_der,
            encryption_der,
        )
        owner_token = self.nonce_source.random_bytes(32)
        if type(owner_token) is not bytes or len(owner_token) != 32:
            raise ConfigurationError("BTD lease nonce source must return 32 bytes")
        control.raise_if_cancelled()
        lease = session_store.acquire_lease(session_id, owner_token, control.deadline)
        state: DownloadSession | None = None
        try:
            state = session_store.load(lease)
            if state is not None and state.phase is DownloadPhase.FAILED:
                segment_store.discard(lease)
                raise SessionConflictError("BTD receive phase cannot be resumed")
            entries = segment_store.list_segments(lease)
            if state is None:
                if entries:
                    raise SessionConflictError("BTD spool exists without session state")
                state = DownloadSession.start(
                    session_id, request_identity, self.protocol_limits
                )
                if not session_store.compare_and_swap(lease, None, state):
                    raise SessionConflictError("BTD session initialization raced")
            elif state.request_identity != request_identity:
                raise SessionConflictError("BTD session belongs to another request")
            index = _btd_spool_index(state, entries)
            if state.phase is DownloadPhase.SIGNATURES_AND_DIGESTS_VERIFIED:
                self._verify_btd_spool(
                    state,
                    index,
                    lease,
                    trusted_bank_keys,
                    encryption_der,
                    key_provider,
                    segment_store,
                )
                return state

            if state.phase is DownloadPhase.NEW:
                initialization = None
                bootstrap_body: bytes | None = None
                if 1 in index:
                    initialization = _parse_btd_initial_response(
                        self._read_btd_response(segment_store, lease, index[1]),
                        trusted_bank_keys,
                        encryption_der,
                        key_provider,
                        self.xml_limits,
                        self.protocol_limits,
                    )
                else:
                    nonce = self.nonce_source.random_bytes(16)
                    if type(nonce) is not bytes or len(nonce) != 16:
                        raise ConfigurationError(
                            "BTD nonce source must return exactly 16 bytes"
                        )
                    request = _PreparedTransportRequest._for_btd_initialization(
                        bank,
                        subscriber,
                        protocol,
                        trusted_bank_keys,
                        descriptor,
                        options,
                        nonce,
                        requested_at,
                        key_provider,
                        authentication_der,
                    )
                    try:
                        response = self.transport.exchange(request, control)
                    except TransientTransportError:
                        raise
                    except TransportError as exc:
                        failed = state.fail()
                        if not session_store.compare_and_swap(
                            lease, state.revision, failed
                        ):
                            raise SessionConflictError(
                                "BTD failure transition raced"
                            ) from exc
                        state = failed
                        segment_store.discard(lease)
                        raise
                    initialization = _parse_btd_initial_response(
                        response.body,
                        trusted_bank_keys,
                        encryption_der,
                        key_provider,
                        self.xml_limits,
                        self.protocol_limits,
                    )
                    bootstrap_body = response.body
                _validate_btd_first_fragment(initialization, self.protocol_limits)
                if bootstrap_body is not None:
                    segment_store.put_segment(lease, 1, (bootstrap_body,))
                initialized = state.initialize(
                    transaction_id=initialization.transaction_id,
                    total_segments=initialization.total_segments,
                )
                if not session_store.initialize_transaction(
                    lease, state.revision, initialized
                ):
                    raise SessionConflictError("BTD transaction initialization raced")
                state = initialized
                recorded = state.record_segment(1)
                if not session_store.compare_and_swap(lease, state.revision, recorded):
                    raise SessionConflictError("BTD first-segment transition raced")
                state = recorded

            index = _btd_spool_index(state, segment_store.list_segments(lease))
            if state.phase is DownloadPhase.INITIALIZED:
                initialization = _parse_btd_initial_response(
                    self._read_btd_response(segment_store, lease, index[1]),
                    trusted_bank_keys,
                    encryption_der,
                    key_provider,
                    self.xml_limits,
                    self.protocol_limits,
                )
                if (
                    initialization.transaction_id != state.transaction_id
                    or initialization.total_segments != state.total_segments
                ):
                    raise SecurityError(
                        "BTD bootstrap and session metadata disagree"
                    )
                _validate_btd_first_fragment(initialization, self.protocol_limits)
                recorded = state.record_segment(1)
                if not session_store.compare_and_swap(
                    lease, state.revision, recorded
                ):
                    raise SessionConflictError("BTD first-segment recovery raced")
                state = recorded
                index = _btd_spool_index(
                    state, segment_store.list_segments(lease)
                )
            if (
                state.phase is DownloadPhase.RECEIVING_SEGMENTS
                and state.next_segment in index
            ):
                self._validate_btd_transfer_spool_entry(
                    state,
                    state.next_segment,
                    index[state.next_segment],
                    lease,
                    trusted_bank_keys,
                    segment_store,
                )
                recorded = state.record_segment(state.next_segment)
                if not session_store.compare_and_swap(lease, state.revision, recorded):
                    raise SessionConflictError("BTD segment recovery raced")
                state = recorded

            while state.phase in {
                DownloadPhase.INITIALIZED,
                DownloadPhase.RECEIVING_SEGMENTS,
            }:
                if state.transaction_id is None or state.total_segments is None:
                    raise SessionConflictError("BTD session lost transaction metadata")
                transaction_id = state.transaction_id
                total_segments = state.total_segments
                segment_number = state.next_segment
                request = _PreparedTransportRequest._for_btd_transfer(
                    bank,
                    protocol,
                    transaction_id,
                    segment_number,
                    key_provider,
                    authentication_der,
                )
                try:
                    response = self.transport.exchange(request, control)
                except TransientTransportError:
                    raise
                except TransportError as exc:
                    failed = state.fail()
                    if not session_store.compare_and_swap(
                        lease, state.revision, failed
                    ):
                        raise SessionConflictError(
                            "BTD failure transition raced"
                        ) from exc
                    state = failed
                    segment_store.discard(lease)
                    raise
                fragment = _parse_btd_transfer_response(
                    response.body,
                    trusted_bank_keys,
                    transaction_id,
                    segment_number,
                    total_segments,
                    self.xml_limits,
                )
                _validate_order_data_fragment(
                    fragment, last=segment_number == total_segments
                )
                segment_store.put_segment(lease, segment_number, (response.body,))
                recorded = state.record_segment(segment_number)
                if not session_store.compare_and_swap(lease, state.revision, recorded):
                    raise SessionConflictError("BTD segment transition raced")
                state = recorded

            index = _btd_spool_index(state, segment_store.list_segments(lease))
            self._verify_btd_spool(
                state,
                index,
                lease,
                trusted_bank_keys,
                encryption_der,
                key_provider,
                segment_store,
            )
            verified = state.mark_signatures_and_digests_verified()
            if not session_store.compare_and_swap(lease, state.revision, verified):
                raise SessionConflictError("BTD verification transition raced")
            return verified
        except SessionConflictError:
            raise
        except ProtocolError as exc:
            if state is not None and state.phase is not DownloadPhase.FAILED:
                failed = state.fail()
                if not session_store.compare_and_swap(lease, state.revision, failed):
                    raise SessionConflictError(
                        "BTD terminal failure transition raced"
                    ) from exc
                segment_store.discard(lease)
            raise
        finally:
            session_store.release_lease(lease)

    def _verify_btd_spool(
        self,
        state: DownloadSession,
        index: dict[int, SegmentReference],
        lease: SessionLease,
        trusted_bank_keys: TrustedBankKeys,
        encryption_der: bytes,
        key_provider: KeyProvider,
        segment_store: SegmentStore,
    ) -> None:
        if state.transaction_id is None or state.total_segments is None:
            raise SessionConflictError("BTD session lost transaction metadata")
        initialization = _parse_btd_initial_response(
            self._read_btd_response(segment_store, lease, index[1]),
            trusted_bank_keys,
            encryption_der,
            key_provider,
            self.xml_limits,
            self.protocol_limits,
        )
        if (
            initialization.transaction_id != state.transaction_id
            or initialization.total_segments != state.total_segments
        ):
            raise SecurityError("BTD bootstrap and session metadata disagree")
        _validate_btd_first_fragment(initialization, self.protocol_limits)
        encoded_size = len(
            _validate_order_data_fragment(
                initialization.first_fragment, last=state.total_segments == 1
            )
        )
        for segment_number in range(2, state.total_segments + 1):
            fragment = _parse_btd_transfer_response(
                self._read_btd_response(segment_store, lease, index[segment_number]),
                trusted_bank_keys,
                state.transaction_id,
                segment_number,
                state.total_segments,
                self.xml_limits,
            )
            encoded_size += len(
                _validate_order_data_fragment(
                    fragment, last=segment_number == state.total_segments
                )
            )
            if encoded_size > _encoded_order_data_limit(self.protocol_limits):
                raise ResponseLimitError(
                    "BTD encoded order data exceeds the configured limit"
                )

    def _validate_btd_transfer_spool_entry(
        self,
        state: DownloadSession,
        segment_number: int,
        reference: SegmentReference,
        lease: SessionLease,
        trusted_bank_keys: TrustedBankKeys,
        segment_store: SegmentStore,
    ) -> None:
        if state.transaction_id is None or state.total_segments is None:
            raise SessionConflictError("BTD session lost transaction metadata")
        fragment = _parse_btd_transfer_response(
            self._read_btd_response(segment_store, lease, reference),
            trusted_bank_keys,
            state.transaction_id,
            segment_number,
            state.total_segments,
            self.xml_limits,
        )
        _validate_order_data_fragment(
            fragment, last=segment_number == state.total_segments
        )

    def _read_btd_response(
        self,
        segment_store: SegmentStore,
        lease: SessionLease,
        reference: SegmentReference,
    ) -> bytes:
        chunks: list[bytes] = []
        size = 0
        for chunk in segment_store.iter_segment(lease, reference):
            if type(chunk) is not bytes:
                raise SecurityError("BTD spool yielded a non-byte chunk")
            size += len(chunk)
            if size > self.xml_limits.max_input_bytes:
                raise ResponseLimitError("BTD spooled response exceeds the XML limit")
            chunks.append(chunk)
        if not chunks:
            raise SecurityError("BTD spool response is empty")
        return b"".join(chunks)

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
