# Architecture

## Objective

EBICSMIT implements protocol mechanics between one caller and its bank while
streaming opaque, verified document bytes into a caller-owned atomic sink. It
returns compact trustworthy metadata and references. It does not own business policy,
credentials, persistence, scheduling, document interpretation, or UI.

The high-level API is intentionally small and unstable until live
interoperability has been demonstrated.

## Package layout

| Module | Responsibility |
| --- | --- |
| `client` | Explicit HEV, INI, HIA, HPB, discovery, trust acceptance, and BTD facade |
| `models` | Immutable, bounded configuration, descriptor, capability, key, and result values |
| `orders` | Complete fixed allowlist; no generic order constructor |
| `interfaces` | Injected keys, bank trust, clock, nonce, leased state, segment spool, streaming sink, and operation-control boundaries |
| `transport` | HTTPS-only verified transport with no redirects and bounded responses |
| `xml` | Hardened untrusted-XML boundary; no protocol-specific interpretation |
| `hev` | Exact H000 response parsing and H005/03.00 selection input |
| `certificates` | Strict selectable X.509 profile validation, separate from OOB trust |
| `testing` | Deterministic synthetic helpers, never production secrets |

Future protocol-specific envelope, signature, crypto, compression, and state
modules must remain internal. They may compose audited dependencies but may not
expose generic XML or order execution through `ReadOnlyClient`.

## Dependency direction

`ReadOnlyClient` depends on the typed `ReadOnlyBackend` contract and a
`BankKeyTrustStore`. A backend may depend on `EbicsTransport`, `KeyProvider`,
`Clock`, `NonceSource`, and `SessionStore`. Hosts implement or adapt those
protocols. The protocol core never reaches into host storage.

`lxml` is selected because it exposes the
libxml2 controls needed to disable entity resolution, DTD loading, network
resolution, recovery, and huge-tree parsing. A streaming parse target applies
explicit input, depth, element, text, XInclude, comment, processing-instruction,
and duplicate-ID limits before accepting more structure. Python's standard XML
APIs do not expose the same complete parser control surface.

`cryptography` is selected for strict X.509 parsing, certificate construction in
synthetic tests, RSA, hashes, and future A006/X002/E002 composition. It delegates
to audited native cryptographic implementations; EBICSMIT implements no
primitive. These are the only runtime dependencies.

The transport protocol receives only a read-only request view plus the
whole-operation control. The default transport accepts only the protocol core's
private prepared request type. There is no factory that accepts caller XML or an
order argument: the sole current builder constructs the exact HEV/H000 request.
Future operations require equally specific fixed-shape builders.

## Operation state

Initialization and downloads are separate workflows:

1. `probe_versions()` performs HEV/H000 and needs only TLS-authenticated
   transport.
2. `initialize_signature_key()` performs INI and produces letter data.
3. `initialize_auth_encryption_keys()` performs HIA and produces letter data.
4. `fetch_bank_keys()` performs HPB and returns `UntrustedBankKeys`.
5. The host obtains both H005 public-key digests out of band and calls
   `accept_bank_keys()`.
6. `discover_capabilities()` defensively tries supported HPD/HAA/HKD/HTD paths.
7. `download()` performs BTD only after the trust store yields `TrustedBankKeys`.

Downloaded HPB keys never become trusted as a side effect of network activity.
Every operation after HEV receives an exact immutable `NegotiatedProtocol` from
a fresh H005/03.00 negotiation; a backend cannot select H004 through the client
contract.
The client obtains trusted keys before invoking discovery or download backend
methods, so an unpinned request cannot cross that boundary.

## BTD transaction state machine

The immutable `DownloadSession` implements these states without a public
constructor or generic transition:

`new -> initialized -> receiving_segments -> segments_received ->`
`signatures_and_digests_verified -> decrypted -> container_verified ->`
`positive_receipt_sent -> receipt_response_verified -> complete`

A positive receipt is unreachable until all payload acceptance steps complete.
After all segments arrive, a processing failure may take the explicit negative
receipt path to `negative_complete`. An uncertain network outcome after sending
either receipt becomes `receipt_ambiguous`; it must not be treated as success or
blindly replayed. Only an explicitly classified transient transport interruption
known to have sent no request bytes is retryable. The default urllib transport
cannot prove that and classifies network interruption as ambiguous. Protocol,
authentication, and security failures are terminal.

`total_segments` is checked against `ProtocolLimits.max_segments` before a
session is initialized. `SessionStore` requires an exclusive `SessionLease` and
compare-and-swap revision for every update. `SegmentStore` keeps sensitive
partial ciphertext in caller-controlled protected storage and exposes an
ordered number/reference index so a restarted worker can recover it. `DocumentSink`
streams into an unpublished atomic writer and returns only a small committed
result with content SHA-256, sanitized ZIP-member identities, and verified
retrieval provenance. `OperationControl` supplies a whole-operation deadline
and cancellation check. Each transport call is bounded by the lesser of its
per-request timeout and remaining operation deadline, with cancellation checks
before and after blocking I/O. These interfaces are design boundaries; BTD
execution is not yet implemented.

## Data minimization

Identifiers, endpoints, account selectors, certificates, key material, lease
tokens, transaction references, and documents are excluded from dataclass
representations where practical. Transaction IDs and partial ciphertext are
sensitive even though they are not private keys. The
protocol core has no logger. Exceptions identify a failure class without
including remote content or identifiers.

Python cannot guarantee memory locking or zeroization of immutable `bytes`.
Production hosts needing stronger key guarantees must use a provider that keeps
private operations inside an OS credential service, PKCS#11 device, or HSM.
