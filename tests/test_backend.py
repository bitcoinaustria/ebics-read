import pytest

from ebics_read import EbicsBackend, OperationNotImplementedError


class _UnusedTransport:
    def exchange(self, request: object, control: object) -> object:
        raise AssertionError("unimplemented operations must not reach transport")


def test_unimplemented_allowlisted_operations_fail_before_transport() -> None:
    backend = EbicsBackend(_UnusedTransport())  # type: ignore[arg-type]
    value = object()
    calls = (
        lambda: backend.initialize_signature_key(value, value, value, value),
        lambda: backend.initialize_auth_encryption_keys(value, value, value, value),
        lambda: backend.fetch_bank_keys(value, value, value, value),
        lambda: backend.discover_capabilities(value, value, value, value, value),
        lambda: backend.download(
            value, value, value, value, value, value, value, value
        ),
    )

    for call in calls:
        with pytest.raises(OperationNotImplementedError):
            call()  # type: ignore[no-untyped-call]
