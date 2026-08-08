# Architecture

## Objective

EBICS Read implements protocol mechanics between one caller and its bank while
streaming opaque, verified document bytes into a caller-owned atomic sink. It
returns compact trustworthy metadata and references. It does not own business policy,
credentials, persistence, scheduling, document interpretation, or UI.

The high-level API is intentionally small and unstable until live
interoperability has been demonstrated.

## Package layout

| Module | Responsibility |
| --- | --- |
| `client` | Explicit HEV, INI, HIA, HPB, discovery, trust acceptance, and BTD facade |
| `backend` | Concrete fixed-operation engine for the complete fixed operation set |
| `models` | Immutable, bounded configuration, descriptor, capability, key, and result values |
| `orders` | Complete fixed allowlist; no generic order constructor |
| `interfaces` | Injected keys, bank trust, clock, nonce, leased state, segment spool, streaming sink, and operation-control boundaries |
| `transport` | HTTPS-only verified transport with no redirects and bounded responses |
| `xml` | Hardened untrusted-XML boundary; no protocol-specific interpretation |
| `hev` | Exact H000 response parsing and H005/03.00 selection input |
| `h005` | Fixed common response shapes and contextual return-code allowlists |
| `hia` | Exact unsecured HIA request data and two-certificate letter rendering |
| `hpb` | Exact signed HPB request and bounded untrusted bank-key extraction |
| `hpd` | Exact segmented HPD transaction and strict bank-parameter discovery |
| `hkd` | Exact segmented HKD transaction and BTD-only customer/permission discovery |
| `htd` | Exact segmented HTD transaction and account/subscriber discovery |
| `haa` | Exact segmented HAA transaction and strict service discovery |
| `btd` | Exact BTD envelopes, request identity, bounded payload decoding, and container extraction |
| `x002` | Exact authenticated-node digest and pinned-bank RSA verification |
| `e002` | Fixed incremental AES-128-CBC order-data decryption |
| `ini` | Exact unsecured INI request data, response checks, and letter rendering |
| `certificates` | Strict selectable X.509 profile validation, separate from OOB trust |
| `testing` | Deterministic synthetic helpers, never production secrets |
| `runtime` | Production system clock, CSPRNG nonce source, deadline, and cancellation defaults |

Future protocol-specific request, electronic-signature, crypto, compression, and state
modules must remain internal. They may compose audited dependencies but may not
expose generic XML or order execution through `ReadOnlyClient`.

## Dependency direction

`ReadOnlyClient` depends on the typed `ReadOnlyBackend` contract and a
`BankKeyTrustStore`. A backend may depend on `EbicsTransport`, `KeyProvider`,
`Clock`, `NonceSource`, `SessionStore`, and `SegmentStore`. Hosts implement or
adapt those protocols. The protocol core never reaches into host storage.

`lxml` is selected because it exposes the
libxml2 controls needed to disable entity resolution, DTD loading, network
resolution, recovery, and huge-tree parsing. A first pass over the immutable
input bytes applies explicit depth, element, text, attribute, namespace,
XInclude, comment, processing-instruction, and duplicate-ID limits. A second
hardened parse of those same bytes constructs the tree while preserving the
source namespace prefixes required by Canonical XML. The bounded scan never
rebuilds the signed tree. Python's standard XML APIs do not expose the same
complete parser control surface.

`cryptography` is selected for strict X.509 parsing, certificate construction in
synthetic tests, RSA, hashes, exact X002 verification, and E002 composition. It delegates
to audited native cryptographic implementations; EBICS Read implements no
primitive. These are the only runtime dependencies.

The transport protocol receives only a read-only request view plus the
whole-operation control. The default transport accepts only the protocol core's
private prepared request type. There is no factory that accepts caller XML or an
order argument: the current builders construct only exact HEV/H000, INI/H005,
HIA/H005, HPB/H005, and fixed-phase HPD/HAA/HKD/HTD/BTD H005 requests.

`EbicsBackend` completes the fixed operation set as fixed vertical slices. INI and HIA
request only fixed provider certificate roles, validate their self-signed
profiles, emit exact compressed unsecured requests, accept deliberately unsigned
responses only through verified TLS, and return deterministic letter data.
HPB creates a fresh nonce and timestamp, locally verifies the provider's X002
signature, bounds E002 decryption and decompression, validates the returned bank
certificates, and leaves them unusable until explicit out-of-band acceptance.
HPD runs first, keeps advertised URLs informational, and independently gates
HAA/HKD/HTD through DownloadableOrderData and ClientDataDownload. Discovery downloads authenticate
response control and encryption metadata with the pinned X002 bank key, reject
replayed transaction IDs, enforce base64-conformant 1 MiB segments and aggregate
limits, and acknowledge only coherent complete data. H005 does not
X002-authenticate `OrderData`; discovery payload integrity therefore also
depends on verified TLS, and no bank electronic signature is claimed.
The client performs mandatory HEV negotiation first; missing operation
dependencies are rejected before the corresponding request is sent.

## Operation state

Initialization and downloads are separate workflows:

1. `probe_versions(control)` performs HEV/H000 and needs only TLS-authenticated
   transport.
2. `initialize_signature_key()` performs INI and produces letter data.
3. `initialize_auth_encryption_keys()` performs HIA and produces letter data.
4. `fetch_bank_keys()` performs HPB and returns `UntrustedBankKeys`.
5. The host obtains both H005 public-key digests out of band and calls
   `accept_bank_keys()`.
6. `discover_capabilities()` defensively tries supported HPD/HAA/HKD/HTD paths.
7. `download()` performs BTD only after the trust store yields `TrustedBankKeys`.

An authenticated 128-bit bank transaction ID is represented by `TransactionId`
and globally claimed through `SessionStore`. BTD combines that claim with its
initial state transition; discovery transactions claim the ID directly. Every duplicate fails as a
replay, and claims remain after terminal or completed transactions.

Downloaded HPB keys never become trusted as a side effect of network activity.
Every operation after HEV receives an exact immutable `NegotiatedProtocol` from
a fresh H005/03.00 negotiation; a backend cannot select H004 through the client
contract.
Every network-facing client and backend method receives an `OperationControl`.
The same control instance covers the preliminary HEV negotiation and the
requested H005 operation, so a backend cannot silently reset the whole-operation
deadline between those steps.
The client obtains trusted keys before invoking discovery or download backend
methods, so an unpinned request cannot cross that boundary.

## BTD transaction state machine

The immutable `DownloadSession` implements these states without a public
constructor or generic transition:

`new -> initialized -> receiving_segments -> segments_received ->`
`signatures_and_digests_verified -> decrypted -> container_verified ->`
`documents_staged -> receipt_pending -> receipt_response_verified ->`
`documents_published -> complete`

A positive receipt is unreachable until all payload acceptance steps complete.
After all segments arrive, a processing failure may take the explicit negative
receipt path to `negative_complete`. An uncertain network outcome after sending
either receipt becomes `receipt_ambiguous`; it must not be treated as success or
blindly replayed. Only an explicitly classified transient transport interruption
known to have sent no request bytes is retryable. The default urllib transport
cannot prove that and classifies network interruption as ambiguous. Protocol,
authentication, and security failures are terminal.

`total_segments` is checked against `ProtocolLimits.max_segments` before a
session is initialized. Every caller-supplied session ID is bound to a hidden
`DownloadRequestIdentity`; resumption under different bank, subscriber, key,
descriptor, or option inputs must produce a different identity and fail.
`SessionStore` requires an exclusive `SessionLease` and compare-and-swap
revision for every update. `SegmentStore` keeps sensitive protected response
fragments in caller-controlled storage and exposes an
ordered number/reference index so a restarted worker can recover it. `DocumentSink`
streams into an unpublished writer. The writer durably stages accepted
plaintext; the sink publishes it idempotently only after the positive receipt
response is authenticated. Each stage has a deterministic ID derived from the
request identity, authenticated transaction ID, and document position before
writing, so a crash before its session CAS retries the same idempotent sink
operation. If staging cannot be persisted, the core discards that ID before a
terminal failure; after a crash it recomputes and discards the same ID. The sink
returns only an opaque published-document reference; the
protocol core remains authoritative for verified provenance, hashes, sizes,
and ZIP metadata. Receipt intent is persisted in `receipt_pending` before any
receipt request bytes are sent. Staged and published result records persist in
the session so either side of publication can resume after a crash. Generic
session CAS accepts only an exact operation-specific successor state. Results
contain only a content SHA-256, sanitized ZIP-member identities, and verified
retrieval provenance. `OperationControl` supplies a whole-operation deadline and
cancellation check. Each transport call is bounded by the lesser of its
per-request timeout and remaining operation deadline, with cancellation checks
before and after blocking I/O. Raw (`NONE`) and bounded ZIP containers are
implemented. XML and SVC framing and portable account selection fail closed
because no recorded public H005 definition supports them.

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
