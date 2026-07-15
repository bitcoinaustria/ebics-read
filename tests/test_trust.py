import pytest

from ebicsmit import (
    Bank,
    BankKeyFingerprints,
    BankKeyMismatchError,
    BankKeyNotTrustedError,
    KeyFingerprint,
    TrustedBankKeys,
    UntrustedBankKeys,
)
from ebicsmit.testing import InMemoryBankKeyTrustStore


def test_wrong_fingerprint_does_not_pin_bank_keys() -> None:
    bank = Bank("https://bank.invalid/ebics", "HOST")
    store = InMemoryBankKeyTrustStore()
    candidate = UntrustedBankKeys(b"auth-cert", b"enc-cert")
    wrong = BankKeyFingerprints(
        KeyFingerprint("0" * 64), candidate.fingerprints.encryption
    )

    with pytest.raises(BankKeyMismatchError):
        store.accept(bank, candidate, wrong)
    with pytest.raises(BankKeyNotTrustedError):
        store.require_trusted(bank)


def test_trusted_bank_keys_cannot_be_constructed_from_hpb_candidate() -> None:
    candidate = UntrustedBankKeys(b"auth-cert", b"enc-cert")
    with pytest.raises(TypeError):
        TrustedBankKeys(
            candidate.authentication_certificate_der,
            candidate.encryption_certificate_der,
            candidate.fingerprints,
        )


def test_rotation_requires_explicit_new_oob_fingerprints() -> None:
    bank = Bank("https://bank.invalid/ebics", "HOST")
    store = InMemoryBankKeyTrustStore()
    original = UntrustedBankKeys(b"auth-1", b"enc-1")
    rotated = UntrustedBankKeys(b"auth-2", b"enc-2")
    store.accept(bank, original, original.fingerprints)

    with pytest.raises(BankKeyMismatchError):
        store.accept(bank, rotated, original.fingerprints)
    assert store.require_trusted(bank).fingerprints == original.fingerprints

    store.accept(bank, rotated, rotated.fingerprints)
    assert store.require_trusted(bank).fingerprints == rotated.fingerprints
