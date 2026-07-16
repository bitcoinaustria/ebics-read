from ebics_read import (
    AmbiguousTransportError,
    CertificateValidationError,
    ProtocolError,
    RetryClassification,
    TransientTransportError,
    classify_retry,
)


def test_only_explicit_transport_interruption_is_retryable() -> None:
    assert (
        classify_retry(TransientTransportError("interrupted"))
        is RetryClassification.TRANSIENT
    )
    assert (
        classify_retry(AmbiguousTransportError("unknown delivery"))
        is RetryClassification.AMBIGUOUS
    )
    assert classify_retry(ProtocolError("invalid")) is RetryClassification.TERMINAL
    assert (
        classify_retry(CertificateValidationError("invalid"))
        is RetryClassification.SECURITY
    )
