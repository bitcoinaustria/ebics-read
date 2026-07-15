from datetime import datetime, timezone

import pytest

from ebicsmit import (
    AcceptedBankKeyIdentity,
    Bank,
    BankKeyMismatchError,
    BankKeyNotTrustedError,
    TrustedBankKeys,
)
from ebicsmit.testing import (
    InMemoryBankKeyTrustStore,
    generate_synthetic_bank_keys,
    synthetic_out_of_band_identity,
)


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 7, 15, tzinfo=timezone.utc)


def test_wrong_ebics_digest_does_not_pin_bank_keys(now: datetime) -> None:
    bank = Bank("https://bank.invalid/ebics", "HOST")
    store = InMemoryBankKeyTrustStore()
    candidate = generate_synthetic_bank_keys(now)
    wrong = AcceptedBankKeyIdentity.from_out_of_band(
        "0" * 64,
        candidate.encryption.ebics_public_key_digest.sha256_hex,
    )

    with pytest.raises(BankKeyMismatchError):
        store.accept(bank, candidate, wrong)
    with pytest.raises(BankKeyNotTrustedError):
        store.require_trusted(bank)


def test_trusted_bank_keys_cannot_be_constructed_from_hpb_candidate(
    now: datetime,
) -> None:
    candidate = generate_synthetic_bank_keys(now)
    expected = synthetic_out_of_band_identity(candidate)
    with pytest.raises(TypeError):
        TrustedBankKeys(
            candidate.authentication,
            candidate.encryption,
            expected,
        )


def test_rotation_requires_explicit_new_oob_key_digests(now: datetime) -> None:
    bank = Bank("https://bank.invalid/ebics", "HOST")
    store = InMemoryBankKeyTrustStore()
    original = generate_synthetic_bank_keys(now)
    rotated = generate_synthetic_bank_keys(now)
    original_oob = synthetic_out_of_band_identity(original)
    rotated_oob = synthetic_out_of_band_identity(rotated)
    store.accept(bank, original, original_oob)

    with pytest.raises(BankKeyMismatchError):
        store.accept(bank, rotated, original_oob)
    assert store.require_trusted(bank).accepted_identity == original_oob

    store.accept(bank, rotated, rotated_oob)
    assert store.require_trusted(bank).accepted_identity == rotated_oob


def test_certificate_fingerprint_and_ebics_digest_are_distinct_types(
    now: datetime,
) -> None:
    candidate = generate_synthetic_bank_keys(now)
    certificate = candidate.authentication
    assert type(certificate.certificate_fingerprint) is not type(
        certificate.ebics_public_key_digest
    )
    assert (
        certificate.certificate_fingerprint.sha256_hex
        == certificate.ebics_public_key_digest.sha256_hex
    )


def test_accepted_identity_requires_explicit_oob_entry(now: datetime) -> None:
    candidate = generate_synthetic_bank_keys(now)
    with pytest.raises(TypeError):
        AcceptedBankKeyIdentity(  # type: ignore[call-arg]
            candidate.authentication.ebics_public_key_digest,
            candidate.encryption.ebics_public_key_digest,
        )
    assert not hasattr(candidate, "identity")
