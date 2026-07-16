"""Strict H005 X.509 validation, separate from out-of-band trust acceptance."""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtensionOID, NameOID, SignatureAlgorithmOID

from .errors import CertificateValidationError
from .models import (
    _CERTIFICATE_VALIDATION_TOKEN,
    BankKeyRole,
    UntrustedBankKeys,
    ValidatedBankCertificate,
)

_RSA_ENCRYPTION_OID = x509.ObjectIdentifier("1.2.840.113549.1.1.1")


@dataclass(frozen=True, slots=True)
class SelfSignedH005BankCertificateProfile:
    """V1 Austrian/German-style self-signed bank certificate policy."""

    minimum_rsa_bits: int = 2048
    maximum_rsa_bits: int = 16_384

    def __post_init__(self) -> None:
        if (
            type(self.minimum_rsa_bits) is not int
            or type(self.maximum_rsa_bits) is not int
        ):
            raise TypeError("RSA key-size limits must be integers")
        if self.minimum_rsa_bits < 2048:
            raise CertificateValidationError(
                "H005 RSA minimum cannot be below 2048 bits"
            )
        if self.maximum_rsa_bits < self.minimum_rsa_bits:
            raise CertificateValidationError("RSA key-size range is inverted")
        if self.maximum_rsa_bits > 16_384:
            raise CertificateValidationError(
                "H005 RSA maximum cannot exceed 16384 bits"
            )

    def validate_pair(
        self,
        authentication_certificate_der: bytes,
        encryption_certificate_der: bytes,
        now: datetime,
    ) -> UntrustedBankKeys:
        """Validate both roles and reject certificate or RSA-key reuse."""

        authentication, authentication_key = self._validate_one(
            authentication_certificate_der, BankKeyRole.AUTHENTICATION, now
        )
        encryption, encryption_key = self._validate_one(
            encryption_certificate_der, BankKeyRole.ENCRYPTION, now
        )
        if authentication.certificate_der == encryption.certificate_der:
            raise CertificateValidationError("bank certificate reused across key roles")
        if authentication_key.public_numbers() == encryption_key.public_numbers():
            raise CertificateValidationError("bank RSA key reused across key roles")
        return UntrustedBankKeys(
            authentication,
            encryption,
            _validation_token=_CERTIFICATE_VALIDATION_TOKEN,
        )

    def _validate_one(
        self,
        certificate_der: bytes,
        role: BankKeyRole,
        now: datetime,
    ) -> tuple[ValidatedBankCertificate, rsa.RSAPublicKey]:
        if not isinstance(certificate_der, bytes) or not certificate_der:
            raise CertificateValidationError("certificate must be non-empty DER bytes")
        if now.tzinfo is None or now.utcoffset() is None:
            raise CertificateValidationError(
                "certificate validation time must be aware"
            )
        try:
            certificate = x509.load_der_x509_certificate(certificate_der)
        except ValueError as exc:
            raise CertificateValidationError("malformed DER certificate") from exc
        if certificate.public_bytes(serialization.Encoding.DER) != certificate_der:
            raise CertificateValidationError("certificate is not one exact DER object")
        if certificate.version is not x509.Version.v3:
            raise CertificateValidationError("bank certificate must be X.509v3")
        if certificate.issuer != certificate.subject:
            raise CertificateValidationError(
                "v1 profile requires a self-signed certificate"
            )
        if not certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            raise CertificateValidationError("bank certificate requires a common name")
        if certificate.signature_algorithm_oid != SignatureAlgorithmOID.RSA_WITH_SHA256:
            raise CertificateValidationError(
                "bank certificate must use RSA with SHA-256"
            )
        if certificate.public_key_algorithm_oid != _RSA_ENCRYPTION_OID:
            raise CertificateValidationError(
                "bank SubjectPublicKeyInfo must use rsaEncryption"
            )
        if certificate.serial_number.bit_length() > 160:
            raise CertificateValidationError(
                "self-signed bank certificate serial exceeds 20 bytes"
            )
        public_key = certificate.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise CertificateValidationError("bank certificate public key must be RSA")
        if not self.minimum_rsa_bits <= public_key.key_size <= self.maximum_rsa_bits:
            raise CertificateValidationError("bank RSA key size is outside H005 limits")
        if (
            not certificate.not_valid_before_utc
            <= now
            <= certificate.not_valid_after_utc
        ):
            raise CertificateValidationError("bank certificate is not currently valid")
        validity = certificate.not_valid_after_utc - certificate.not_valid_before_utc
        if certificate.not_valid_after_utc.year != 9999 and validity > timedelta(
            days=5 * 366
        ):
            raise CertificateValidationError(
                "self-signed bank certificate validity exceeds five years"
            )
        self._validate_critical_extensions(certificate)
        self._validate_basic_constraints(certificate)
        self._validate_authority_key_identifier(certificate, public_key)
        key_usage = self._key_usage(certificate)
        if not key_usage.digital_signature:
            raise CertificateValidationError("bank certificate lacks digitalSignature")
        if role is BankKeyRole.ENCRYPTION and not key_usage.key_encipherment:
            raise CertificateValidationError(
                "bank encryption certificate lacks keyEncipherment"
            )
        if any(
            (
                key_usage.content_commitment,
                key_usage.data_encipherment,
                key_usage.key_agreement,
                key_usage.key_cert_sign,
                key_usage.crl_sign,
            )
        ):
            raise CertificateValidationError(
                "bank certificate contains forbidden KeyUsage bits"
            )
        try:
            certificate.extensions.get_extension_for_oid(
                ExtensionOID.EXTENDED_KEY_USAGE
            )
        except x509.ExtensionNotFound:
            pass
        else:
            raise CertificateValidationError(
                "extendedKeyUsage is forbidden by this profile"
            )
        try:
            certificate.extensions.get_extension_for_oid(ExtensionOID.FRESHEST_CRL)
        except x509.ExtensionNotFound:
            pass
        else:
            raise CertificateValidationError("freshestCRL is forbidden by this profile")
        try:
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except InvalidSignature as exc:
            raise CertificateValidationError(
                "self-signature validation failed"
            ) from exc
        return (
            ValidatedBankCertificate(
                role,
                certificate_der,
                public_key.key_size,
                _validation_token=_CERTIFICATE_VALIDATION_TOKEN,
            ),
            public_key,
        )

    @staticmethod
    def _require_extension(
        certificate: x509.Certificate, oid: x509.ObjectIdentifier
    ) -> x509.Extension[x509.ExtensionType]:
        try:
            return certificate.extensions.get_extension_for_oid(oid)
        except x509.ExtensionNotFound as exc:
            raise CertificateValidationError(
                "required certificate extension is missing"
            ) from exc

    @staticmethod
    def _key_usage(certificate: x509.Certificate) -> x509.KeyUsage:
        extension = SelfSignedH005BankCertificateProfile._require_extension(
            certificate, ExtensionOID.KEY_USAGE
        )
        if not isinstance(extension.value, x509.KeyUsage):
            raise CertificateValidationError("invalid KeyUsage extension")
        return extension.value

    @staticmethod
    def _validate_critical_extensions(certificate: x509.Certificate) -> None:
        if any(
            extension.critical
            and isinstance(extension.value, x509.UnrecognizedExtension)
            for extension in certificate.extensions
        ):
            raise CertificateValidationError(
                "unknown critical certificate extension is forbidden"
            )

    @staticmethod
    def _validate_authority_key_identifier(
        certificate: x509.Certificate, public_key: rsa.RSAPublicKey
    ) -> None:
        extension = SelfSignedH005BankCertificateProfile._require_extension(
            certificate, ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        )
        if not isinstance(extension.value, x509.AuthorityKeyIdentifier):
            raise CertificateValidationError("invalid AuthorityKeyIdentifier")
        expected = x509.SubjectKeyIdentifier.from_public_key(public_key).digest
        value = extension.value
        if (
            value.key_identifier is None
            or not hmac.compare_digest(value.key_identifier, expected)
            or value.authority_cert_issuer is not None
            or value.authority_cert_serial_number is not None
        ):
            raise CertificateValidationError(
                "AuthorityKeyIdentifier does not identify the self-signed key"
            )

    @staticmethod
    def _validate_basic_constraints(certificate: x509.Certificate) -> None:
        try:
            extension = certificate.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            )
        except x509.ExtensionNotFound:
            return
        if not isinstance(extension.value, x509.BasicConstraints):
            raise CertificateValidationError("invalid BasicConstraints extension")
        if extension.value.ca or extension.value.path_length is not None:
            raise CertificateValidationError(
                "bank endpoint certificate must not be a CA certificate"
            )
