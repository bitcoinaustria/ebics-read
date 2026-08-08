import inspect

import pytest

from ebics_read import ConfigurationError, EbicsBackend, OperationNotImplementedError


class _UnusedTransport:
    def exchange(self, request: object, control: object) -> object:
        raise AssertionError("unimplemented operations must not reach transport")


def test_unimplemented_allowlisted_operations_fail_before_transport() -> None:
    backend = EbicsBackend(_UnusedTransport())  # type: ignore[arg-type]
    value = object()
    for initialize in (
        backend.initialize_signature_key,
        backend.initialize_auth_encryption_keys,
    ):
        with pytest.raises(ConfigurationError, match="key provider and clock"):
            initialize(value, value, value, value)  # type: ignore[arg-type]
    with pytest.raises(ConfigurationError, match="session store"):
        backend.discover_capabilities(value, value, value, value, value)  # type: ignore[arg-type]
    with pytest.raises(OperationNotImplementedError):
        backend.download(  # type: ignore[arg-type]
            value, value, value, value, value, value, value, value, value
        )

    with pytest.raises(ConfigurationError, match="key provider, clock, and nonce"):
        backend.fetch_bank_keys(value, value, value, value)  # type: ignore[arg-type]


def test_new_haa_dependencies_do_not_rebind_existing_positional_configuration() -> None:
    assert tuple(inspect.signature(EbicsBackend).parameters)[:6] == (
        "transport",
        "xml_limits",
        "key_provider",
        "clock",
        "nonce_source",
        "bank_certificate_profile",
    )
