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
    calls = (
        lambda: backend.fetch_bank_keys(value, value, value, value),
        lambda: backend.discover_capabilities(value, value, value, value, value),
        lambda: backend.download(
            value, value, value, value, value, value, value, value, value
        ),
    )

    for call in calls:
        with pytest.raises(OperationNotImplementedError):
            call()  # type: ignore[no-untyped-call]
