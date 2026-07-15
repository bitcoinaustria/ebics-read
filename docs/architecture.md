# Architecture

## Objective

EBICSMIT implements protocol mechanics between one caller and its bank while
returning opaque, verified document bytes. It does not own business policy,
credentials, persistence, scheduling, document interpretation, or UI.

The high-level API is intentionally small and unstable until live
interoperability has been demonstrated.

## Package layout

| Module | Responsibility |
| --- | --- |
| `client` | Explicit HEV, INI, HIA, HPB, discovery, trust acceptance, and BTD facade |
| `models` | Immutable, bounded configuration, descriptor, capability, key, and result values |
| `orders` | Complete fixed allowlist; no generic order constructor |
| `interfaces` | Injected keys, bank trust, clock, nonce, and session boundaries |
| `transport` | HTTPS-only verified transport with no redirects and bounded responses |
| `xml` | Hardened untrusted-XML boundary; no protocol-specific interpretation |
| `testing` | Deterministic synthetic helpers, never production secrets |

Future protocol-specific envelope, signature, crypto, compression, and state
modules must remain internal. They may compose audited dependencies but may not
expose generic XML or order execution through `ReadOnlyClient`.

## Dependency direction

`ReadOnlyClient` depends on the typed `ReadOnlyBackend` contract and a
`BankKeyTrustStore`. A backend may depend on `EbicsTransport`, `KeyProvider`,
`Clock`, `NonceSource`, and `SessionStore`. Hosts implement or adapt those
protocols. The protocol core never reaches into host storage.

The only current runtime dependency is `lxml`, selected because it exposes the
libxml2 controls needed to disable entity resolution, DTD loading, network
resolution, recovery, and huge-tree parsing. A streaming parse target applies
explicit input, depth, element, text, XInclude, comment, processing-instruction,
and duplicate-ID limits before accepting more structure. Python's standard XML
APIs do not expose the same complete parser control surface.

`cryptography` will be added only when A006, X002, E002, and X.509 composition
is implemented and verified against official vectors. No primitive will be
implemented by this project.

The transport protocol receives only a read-only request view. The default
transport additionally accepts only the protocol core's private prepared
request type, so application code cannot use it as a public arbitrary-XML POST
facility. Future envelope builders must remain internal and may call the
private request factory only after selecting an allowlisted operation.

## Operation state

Initialization and downloads are separate workflows:

1. `probe_versions()` performs HEV/H000 and needs only TLS-authenticated
   transport.
2. `initialize_signature_key()` performs INI and produces letter data.
3. `initialize_auth_encryption_keys()` performs HIA and produces letter data.
4. `fetch_bank_keys()` performs HPB and returns `UntrustedBankKeys`.
5. The host obtains both bank fingerprints out of band and calls
   `accept_bank_keys()`.
6. `discover_capabilities()` defensively tries supported HPD/HAA/HKD/HTD paths.
7. `download()` performs BTD only after the trust store yields `TrustedBankKeys`.

Downloaded HPB keys never become trusted as a side effect of network activity.
The client obtains trusted keys before invoking discovery or download backend
methods, so an unpinned request cannot cross that boundary.

## BTD transaction state machine

The immutable `DownloadSession` implements these states without a public
constructor or generic transition:

`new -> initialized -> transferring -> complete -> receipt_sent -> verified`

Any authentication failure, unknown return code, replay, segment gap,
duplication, reordering, size violation, decryption failure, decompression
failure, or receipt ambiguity moves the transaction to terminal `failed` state.
Only explicitly classified transport interruption may resume from caller-owned
non-secret state. Protocol or authentication failures are never retried as if
they were transient.

## Data minimization

Identifiers, endpoints, account selectors, certificates, key material, and
documents are excluded from dataclass representations where practical. The
protocol core has no logger. Exceptions identify a failure class without
including remote content or identifiers.

Python cannot guarantee memory locking or zeroization of immutable `bytes`.
Production hosts needing stronger key guarantees must use a provider that keeps
private operations inside an OS credential service, PKCS#11 device, or HSM.
