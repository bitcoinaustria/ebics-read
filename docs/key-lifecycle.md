# Key lifecycle

## Subscriber keys

The host provides three independent keys through `KeyProvider`: signature,
authentication, and encryption. H005 represents their public material as X.509
certificates. The core requests only certificates and fixed X002/E002
operations. It uses the signature role only to obtain the INI certificate. The
structurally
read-only operation set never asks the provider to create an A006 business
signature. X002 signing and E002 transaction-key decryption remain fixed
provider operations; private keys are never exported.

INI initializes the signature certificate. HIA initializes authentication and
encryption certificates. Both operations produce initialization-letter data for
the bank's out-of-band activation process. They are not business uploads.
The implemented INI path accepts only the fixed self-signed A006 subscriber
profile: exact DER X.509v3, RSA/SHA-256 with a 2048–4096-bit `rsaEncryption`
key, current bounded validity, matching AKI/SKI, content-commitment key usage,
and no CA, EKU, CRL, or unknown-critical-extension capability. Additional
KeyUsage bits are retained when content-commitment is present, as required by
the return-code annex. `Bank.institution_name` supplies the letter recipient and
does not affect bank identity. The letter prints the exact transmitted
certificate as PEM and hashes the original DER bytes.

Production storage is a host decision. SQLCipher, an OS credential store,
PKCS#11, or an HSM integration belongs outside this package. The March 2026
EBICS TLS/KMS guidance recommends suitably certified or protected key operation;
the test-only memory helpers do not satisfy that recommendation.

## Bank keys

1. HPB returns authentication and encryption certificates as
   `UntrustedBankKeys`.
2. A selected certificate profile strictly parses DER, validates the RSA key,
   validity period, key role, certificate profile, and role separation. This
   produces a candidate, not trust.
3. The host obtains both normative H005 EBICS public-key digests through a
   genuinely independent channel such as a signed bank letter or authenticated
   bank portal.
4. The host transcribes those strings through
   `AcceptedBankKeyIdentity.from_out_of_band()` and calls
   `accept_bank_keys(candidate, expected_out_of_band)`.
5. The trust store compares both digests in constant time and persists the
   resulting `TrustedBankKeys` according to host policy.
6. Discovery and BTD fail before backend invocation if no trusted keys exist.

`CertificateFingerprint`, `EbicsPublicKeyDigest`, and
`AcceptedBankKeyIdentity` are deliberately different types. Under H005 the
normative SHA-256 input is the complete DER certificate, so the first two can
currently contain the same hexadecimal value. Their semantics and future use
remain distinct and cannot be interchanged in the public API.
`UntrustedBankKeys` deliberately exposes no `AcceptedBankKeyIdentity`; the
candidate certificate digests cannot be passed back as an already accepted OOB
value.

This is an explicit trust-ceremony boundary, not proof of physical provenance.
Python cannot determine whether a host copied a candidate digest into
`from_out_of_band()`. A host must obtain and collect the expected values through
a separate interaction, must not prefill them from HPB, should show candidate
and independently entered values side by side, and should record confirmation
method and time in its own protected storage. EBICS Read performs the typed,
constant-time comparison but deliberately owns no UI or persistence policy.

There is no trust-on-first-use mode. A newly downloaded or rotated certificate
never replaces a pin silently. Rotation repeats the same out-of-band comparison.

## Expiry, suspension, and renewal

HCA/HCS renewal and SPR suspension are out of v1 scope. Expired or suspended
subscribers must follow the bank's INI/HIA initialization-letter process again.
The v1 self-signed bank profile checks certificate time validity, RSA/SHA-256
with `rsaEncryption` SPKI, 2048–16384-bit RSA, bounded validity and serial
number, exact role key usage, self-key authority identifier, unknown critical
extensions, forbidden EKU/freshest-CRL, self-signature, and separate
authentication and encryption keys. CA-issued profiles, including CFONB
deployments, remain a separate future profile rather than a validation bypass.

## Memory limitations

Python `bytes` objects may be copied and cannot be reliably zeroized. Provider
implementations requiring stronger guarantees must keep private material and
operations outside the Python process. EBICS Read never logs or intentionally
persists keys or certificates.
