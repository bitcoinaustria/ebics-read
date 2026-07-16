from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ebics_read import (
    CertificateValidationError,
    SelfSignedH005BankCertificateProfile,
    UntrustedBankKeys,
    ValidatedBankCertificate,
)
from ebics_read.testing import generate_synthetic_bank_keys


def certificate(
    now: datetime,
    *,
    encryption: bool = False,
    key: rsa.RSAPrivateKey | None = None,
    common_name: bool = True,
    self_issued: bool = True,
    include_aki: bool = True,
    matching_aki: bool = True,
    include_key_usage: bool = True,
    digital_signature: bool = True,
    key_encipherment: bool | None = None,
    forbidden_key_usage: bool = False,
    extended_key_usage: bool = False,
    unknown_critical: bool = False,
    freshest_crl: bool = False,
    signature_hash: hashes.HashAlgorithm | None = None,
    validity_days: int = 365,
    ca: bool | None = None,
) -> bytes:
    private_key = key or rsa.generate_private_key(public_exponent=65_537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(
                NameOID.COMMON_NAME if common_name else NameOID.ORGANIZATION_NAME,
                "Synthetic profile test",
            )
        ]
    )
    issuer = (
        subject
        if self_issued
        else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Other issuer")])
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=validity_days))
    )
    if include_aki:
        authority_key = (
            private_key.public_key()
            if matching_aki
            else rsa.generate_private_key(
                public_exponent=65_537, key_size=2048
            ).public_key()
        )
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(authority_key),
            critical=False,
        )
    if include_key_usage:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=digital_signature,
                content_commitment=forbidden_key_usage,
                key_encipherment=(
                    encryption if key_encipherment is None else key_encipherment
                ),
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    if extended_key_usage:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
    if unknown_critical:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4"), b"test"),
            critical=True,
        )
    if freshest_crl:
        builder = builder.add_extension(
            x509.FreshestCRL(
                [
                    x509.DistributionPoint(
                        full_name=[
                            x509.UniformResourceIdentifier(
                                "https://synthetic.invalid/crl"
                            )
                        ],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
    if ca is not None:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=None), critical=True
        )
    signed = builder.sign(private_key, signature_hash or hashes.SHA256())
    return signed.public_bytes(serialization.Encoding.DER)


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 7, 15, tzinfo=timezone.utc)


def test_validates_strict_distinct_self_signed_h005_pair(now: datetime) -> None:
    candidate = generate_synthetic_bank_keys(now)
    assert candidate.authentication.rsa_key_size == 2048
    assert candidate.encryption.rsa_key_size == 2048
    assert (
        candidate.authentication.certificate_der != candidate.encryption.certificate_der
    )


def test_rejects_malformed_trailing_expired_and_reused_certificates(
    now: datetime,
) -> None:
    candidate = generate_synthetic_bank_keys(now)
    profile = SelfSignedH005BankCertificateProfile()
    authentication = candidate.authentication.certificate_der
    encryption = candidate.encryption.certificate_der

    with pytest.raises(CertificateValidationError):
        profile.validate_pair(authentication + b"trailing", encryption, now)
    with pytest.raises(CertificateValidationError):
        profile.validate_pair(b"not-der", encryption, now)
    with pytest.raises(CertificateValidationError):
        profile.validate_pair(authentication, encryption, now + timedelta(days=367))
    with pytest.raises(CertificateValidationError):
        profile.validate_pair(encryption, encryption, now)


def test_validated_types_cannot_be_constructed_without_profile(now: datetime) -> None:
    candidate = generate_synthetic_bank_keys(now)
    with pytest.raises(TypeError):
        ValidatedBankCertificate(  # type: ignore[call-arg]
            candidate.authentication.role,
            candidate.authentication.certificate_der,
            2048,
        )
    with pytest.raises(TypeError):
        UntrustedBankKeys(candidate.authentication, candidate.encryption)


def test_profile_rejects_weak_config_and_naive_time(now: datetime) -> None:
    with pytest.raises(TypeError):
        SelfSignedH005BankCertificateProfile(minimum_rsa_bits=2048.0)  # type: ignore[arg-type]
    with pytest.raises(CertificateValidationError):
        SelfSignedH005BankCertificateProfile(minimum_rsa_bits=1024)
    with pytest.raises(CertificateValidationError):
        SelfSignedH005BankCertificateProfile(
            minimum_rsa_bits=4096, maximum_rsa_bits=2048
        )
    with pytest.raises(CertificateValidationError):
        SelfSignedH005BankCertificateProfile(maximum_rsa_bits=16_385)
    candidate = generate_synthetic_bank_keys(now)
    with pytest.raises(CertificateValidationError):
        SelfSignedH005BankCertificateProfile().validate_pair(
            candidate.authentication.certificate_der,
            candidate.encryption.certificate_der,
            datetime(2026, 7, 15),  # noqa: DTZ001 - deliberate invalid input
        )


def test_rejects_empty_weak_and_invalid_self_signature(now: datetime) -> None:
    candidate = generate_synthetic_bank_keys(now)
    profile = SelfSignedH005BankCertificateProfile()
    with pytest.raises(CertificateValidationError):
        profile.validate_pair(b"", candidate.encryption.certificate_der, now)
    weak = rsa.generate_private_key(public_exponent=65_537, key_size=1024)
    with pytest.raises(CertificateValidationError, match="key size"):
        profile.validate_pair(
            certificate(now, key=weak), candidate.encryption.certificate_der, now
        )
    authentication = candidate.authentication.certificate_der
    damaged = authentication[:-1] + bytes([authentication[-1] ^ 1])
    with pytest.raises(CertificateValidationError, match="self-signature"):
        profile.validate_pair(damaged, candidate.encryption.certificate_der, now)


def test_rejects_certificate_profile_and_extension_violations(now: datetime) -> None:
    encryption = generate_synthetic_bank_keys(now).encryption.certificate_der
    invalid_authentication_certificates = (
        certificate(now, common_name=False),
        certificate(now, self_issued=False),
        certificate(now, include_aki=False),
        certificate(now, matching_aki=False),
        certificate(now, include_key_usage=False),
        certificate(now, digital_signature=False),
        certificate(now, forbidden_key_usage=True),
        certificate(now, extended_key_usage=True),
        certificate(now, unknown_critical=True),
        certificate(now, freshest_crl=True),
        certificate(now, signature_hash=hashes.SHA384()),
        certificate(now, validity_days=6 * 366),
        certificate(now, ca=True),
    )
    profile = SelfSignedH005BankCertificateProfile()
    for authentication in invalid_authentication_certificates:
        with pytest.raises(CertificateValidationError):
            profile.validate_pair(authentication, encryption, now)


def test_rejects_encryption_usage_and_cross_role_rsa_key_reuse(now: datetime) -> None:
    authentication = generate_synthetic_bank_keys(now).authentication.certificate_der
    with pytest.raises(CertificateValidationError, match="keyEncipherment"):
        SelfSignedH005BankCertificateProfile().validate_pair(
            authentication,
            certificate(now, encryption=True, key_encipherment=False),
            now,
        )

    shared_key = rsa.generate_private_key(public_exponent=65_537, key_size=2048)
    with pytest.raises(CertificateValidationError, match="RSA key reused"):
        SelfSignedH005BankCertificateProfile().validate_pair(
            certificate(now, key=shared_key),
            certificate(now, encryption=True, key=shared_key),
            now,
        )
