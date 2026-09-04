from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from ebics_read import (
    NegotiatedProtocol,
    ProtocolVersion,
    ReadOnlyClient,
    VersionDiscovery,
)


@dataclass
class _CountingBackend:
    """Counts HEV probes and records the protocol each operation received."""

    probes: int = 0
    received: list[NegotiatedProtocol] = field(default_factory=list)

    def probe_versions(self, bank: object, control: object) -> VersionDiscovery:
        self.probes += 1
        return VersionDiscovery((ProtocolVersion("H005", "03.00"),))

    def fetch_bank_keys(
        self,
        bank: object,
        subscriber: object,
        protocol: NegotiatedProtocol,
        control: object,
    ) -> str:
        self.received.append(protocol)
        return "keys"


def _client(backend: _CountingBackend) -> ReadOnlyClient:
    return ReadOnlyClient(
        object(),  # type: ignore[arg-type]
        object(),  # type: ignore[arg-type]
        backend,  # type: ignore[arg-type]
        object(),  # type: ignore[arg-type]
    )


def test_operations_renegotiate_hev_by_default() -> None:
    backend = _CountingBackend()
    client = _client(backend)

    client.fetch_bank_keys(object())  # type: ignore[arg-type]
    client.fetch_bank_keys(object())  # type: ignore[arg-type]

    assert backend.probes == 2
    assert backend.received == [NegotiatedProtocol(), NegotiatedProtocol()]


def test_a_supplied_protocol_reuses_one_hev_probe() -> None:
    backend = _CountingBackend()
    client = _client(backend)

    protocol = client.probe_versions(object())  # type: ignore[arg-type]
    client.fetch_bank_keys(object(), protocol)  # type: ignore[arg-type]
    client.fetch_bank_keys(object(), protocol)  # type: ignore[arg-type]

    assert backend.probes == 1
    assert backend.received == [protocol, protocol]


def test_a_supplied_protocol_must_be_the_negotiated_type() -> None:
    client = _client(_CountingBackend())

    with pytest.raises(TypeError, match="NegotiatedProtocol"):
        client.fetch_bank_keys(object(), "H005")  # type: ignore[arg-type]
