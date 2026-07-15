# Key lifecycle

## Subscriber keys

The host provides three independent keys through `KeyProvider`: signature,
authentication, and encryption. H005 represents their public material as X.509
certificates. The core requests only fixed A006, X002, and E002 operations; it
does not ask providers to execute arbitrary algorithms or export private keys.

INI initializes the signature certificate. HIA initializes authentication and
encryption certificates. Both operations produce initialization-letter data for
the bank's out-of-band activation process. They are not business uploads.

Production storage is a host decision. SQLCipher, an OS credential store,
PKCS#11, or an HSM integration belongs outside this package. The March 2026
EBICS TLS/KMS guidance recommends suitably certified or protected key operation;
the test-only memory helpers do not satisfy that recommendation.

## Bank keys

1. HPB returns authentication and encryption certificates as
   `UntrustedBankKeys`.
2. The host obtains both SHA-256 fingerprints through a genuinely independent
   channel such as a signed bank letter or authenticated bank portal.
3. The host calls `accept_bank_keys(candidate, expected_out_of_band)`.
4. The trust store compares both fingerprints in constant time and persists the
   resulting `TrustedBankKeys` according to host policy.
5. Discovery and BTD fail before backend invocation if no trusted keys exist.

There is no trust-on-first-use mode. A newly downloaded or rotated certificate
never replaces a pin silently. Rotation repeats the same out-of-band comparison.

## Expiry, suspension, and renewal

HCA/HCS renewal and SPR suspension are out of v1 scope. Expired or suspended
subscribers must follow the bank's INI/HIA initialization-letter process again.
Certificate time validity, key strength, role separation, and bank-specific
profile checks must fail closed when implemented.

## Memory limitations

Python `bytes` objects may be copied and cannot be reliably zeroized. Provider
implementations requiring stronger guarantees must keep private material and
operations outside the Python process. EBICSMIT never logs or intentionally
persists keys or certificates.
