# Threat model

## Assets

- subscriber private keys and certificates;
- bank authentication and encryption certificates, their certificate
  fingerprints, and separately typed accepted H005 public-key digests;
- participant, host, account, nonce, request, and transaction identifiers;
- authenticated response metadata and opaque downloaded documents;
- resumable transaction state.

## Trust boundaries

1. Host application to immutable public models.
2. Protocol core to caller-controlled key, trust, clock, nonce, leased session,
   protected segment-spool, atomic document-sink, and operation-control
   providers.
3. Protocol core to HTTPS transport.
4. Untrusted bank/network XML to the hardened parser.
5. Authenticated response nodes to metadata, ciphertext, decompression, and
   document extraction.

TLS authenticates an endpoint but does not replace EBICS AuthSignature and
digest verification. HPB is key distribution, not proof that the received keys
match the bank's out-of-band values.

## Adversaries and failures

- active network attacker, compromised proxy, or malicious redirect;
- compromised or misconfigured bank endpoint;
- malicious XML with DTDs, entities, external resources, XInclude, namespace
  confusion, duplicate IDs, signature wrapping, or resource exhaustion;
- modified signed nodes, digests, encrypted data, segments, or receipts;
- replayed responses, nonces, transaction IDs, or stale bank keys;
- ZIP traversal, excessive members, nested archives, and compression bombs;
- caller mistakes such as wrong endpoint, scope, OOB digest, date, or account;
- backend bugs that classify unknown codes or algorithms as success;
- accidental disclosure through logs, exceptions, representations, fixtures,
  command arguments, or CI artifacts.

## Structural controls already present

- Exact operation enum: HEV, INI, HIA, HPB, HPD, HAA, HKD, HTD, BTD.
- No client method accepts an order type, XML, URL, or arbitrary parameter map.
- HPB returns an untrusted type; discovery and BTD require a trusted type
  obtained only from the named explicit OOB acceptance constructor.
- Default HTTPS requires certificate verification and TLS 1.2+, refuses
  redirects, disables implicit environment/system proxies, bounds response
  bytes, and rejects caller-constructed requests. Proxy use requires an explicit
  typed configuration. There is no insecure public flag or public arbitrary-body
  exchange.
- XML parsing disables DTD loading, entity resolution, network access,
  recovery, and huge trees. A bounded parse target rejects depth, element,
  text, attribute, namespace, XInclude, duplicate-ID, comment, and
  processing-instruction violations as events arrive, including document-level
  nodes outside the root. Non-UTF-8 declarations and undecodable bytes fail.
- HEV accepts only the exact H000 root/shape and selects only H005/03.00. It
  rejects mixed content, conflicting or duplicate advertisements, and never
  falls back to H004. Every subsequent backend call receives that exact
  negotiated protocol value.
- Strict DER X.509 profile validation checks RSA algorithm/strength, validity,
  self-signature, SPKI OID, serial/validity bounds, authority-key identity,
  required and forbidden extensions/key usage, and cross-role key reuse before
  a candidate can be displayed for OOB comparison.
  Certificate validity still does not imply trust.
- Download state can be created or restored only through invariant-checking
  methods. Segment receipt accepts exactly the next expected segment and makes
  completed and receipt states unreachable while segments are missing. A
  positive receipt is unreachable until authentication, decryption, and bounded
  container validation have completed; negative and ambiguous receipt outcomes
  have distinct states.
- Session revisions require lease/CAS storage, partial ciphertext has a protected
  caller-spool contract with a recoverable number/reference index, documents
  stream to an atomic sink, and results carry a content hash plus sanitized
  provenance rather than large in-memory byte tuples. Transport timeouts are
  capped by the operation deadline and cancellation is checked around I/O.
- Retry classification treats only explicit transient transport interruptions as
  retryable when the transport proves no bytes were sent. Default network
  interruptions are ambiguous; security and protocol failures are terminal.
- Core modules contain no logging calls or event payloads.
- Sensitive model fields are omitted from representations.

## Required controls before protocol completion

- Verify X002 AuthSignature and all authenticated digests before reading
  response metadata or order data.
- Select exactly the authenticated nodes required by the normative XPointer;
  reject wrapping, namespace substitution, missing nodes, and duplicates.
- Reject unknown algorithms and return codes.
- Track nonces, request IDs, timestamps, transaction IDs, and completed receipts
  to detect replay.
- Enforce segment count/order/completeness, compressed and decompressed sizes,
  ZIP members, member paths, member sizes, and compression ratios.
- Apply phase-specific handling of ambiguous transport outcomes in the future
  executable BTD state machine; never blindly replay them.
- Add deterministic official crypto vectors before any live use.

## Residual risks

- Python cannot guarantee zeroization, constant-time object handling, process
  isolation, or protection from a compromised host interpreter.
- TLS and X.509 behavior ultimately depends on the platform trust store and
  linked cryptographic libraries.
- Caller-supplied providers may violate their contracts.
- Bank profiles and national BTF mappings vary and may be incompletely
  discoverable.
- Agent review does not replace an external human security audit.

## Adversarial agent review log

No protocol-crypto review has occurred because XML signature verification is
not implemented.

On 2026-07-15, a separate fresh-context agent session that did not write the
foundation was instructed to find breaks and not fix them. This was agent-only
adversarial review, not an external human security audit. Its findings and
resolutions were:

| Severity | Finding | Resolution and regression evidence |
| --- | --- | --- |
| High | Public `HttpsTransport.exchange(bank, bytes)` was an arbitrary XML POST escape hatch and could carry a prohibited BTU envelope. | Exchange now accepts only a protocol-core-prepared private request implementation; caller-created request objects fail closed. `test_default_transport_rejects_caller_constructed_raw_requests` proves the boundary. |
| High | `TrustedBankKeys` could be constructed directly from an HPB candidate, bypassing explicit acceptance. | Its public constructor now rejects creation; `accept_out_of_band` is the sole supported factory and compares both expected typed H005 public-key digests in constant time. Trust tests cover direct construction, mismatch, initial pinning, and rotation. |
| Medium | Comments and processing instructions before or after the document root escaped tree-only validation. | The streaming target rejects both event types anywhere in the document. Tests cover before-root, in-root, and after-root cases. |
| Medium | Depth, element, and text limits were checked only after lxml allocated the complete tree. | Limits are now enforced during parser callbacks before accepting further nodes or text. Boundary tests cover each configured limit. |
| Medium | Tuple annotations accepted mutable lists, while generic session construction and phase transitions allowed incoherent BTD state. | Collection models defensively copy inputs to tuples and validate element types. `DownloadSession` has invariant-checked start/restore and operation-specific transitions only; tests cover mutation, forged completed state, reordered segments, skipped states, and terminal reuse. |

The first verification pass confirmed those five dispositions and found three
additional edge cases:

| Severity | Follow-up finding | Resolution and regression evidence |
| --- | --- | --- |
| High | A restored `INITIALIZED` session could set `next_segment=2`, then accept segment 2 without ever recording segment 1. | Restored `INITIALIZED` state must begin at segment 1; `TRANSFERRING` state must prove prior progress. The incoherent restore is covered by `test_download_state_cannot_be_forged_or_restored_incoherently`. |
| Medium | `ServiceCapability` and `InitializationLetter` accepted string enum lookalikes and an invalid nested descriptor. | Both models now require exact typed nested values before checking allowlist membership. `test_nested_models_reject_enum_lookalikes_and_wrong_values` covers the rejected forms. |
| Medium | Fractional byte/count limits and infinite transport timeouts passed configuration validation and could cause an uncaught runtime type error. | Protocol/XML byte and count limits require positive integers; transport timeout requires a finite positive number and response limit a positive integer. Model, XML, and transport tests cover the malformed configurations. |

The same reviewer then performed a final verification: all 25 targeted invalid
cases were rejected, the valid session path still reached `VERIFIED`, all 34
tests passed, and no actionable foundation finding remained.
XML signature verification remains the highest-risk unimplemented component;
it requires a new adversarial review by a session that did not implement it
before the Experimental release gate can pass.

### Foundation-correction review

On 2026-07-15, another fresh-context, review-only agent examined the normative
foundation correction and HEV slice. It initially rejected the tree with seven
findings. This was agent-only adversarial review, not an external human audit.

| Severity | Finding | Resolution and regression evidence |
| --- | --- | --- |
| Critical | A private generic request factory still accepted arbitrary bytes, so underscore imports could construct and send BTU/payment XML. | The generic factory was deleted. The only prepared-request builder accepts only `Bank` and emits fixed HEV/H000 XML with `OrderType.HEV`; direct construction always raises and no callable accepts body bytes. Transport tests prove BTU bytes cannot enter either path. |
| High | H005 was selected by `probe_versions()` but not pinned into later backend operations. | Every INI/HIA/HPB/discovery/BTD backend call now receives an exact `NegotiatedProtocol` produced by a fresh H005/03.00 selection. Boundary tests assert the value at every call. |
| High | `UntrustedBankKeys.identity` mislabeled network-derived digests as `AcceptedBankKeyIdentity`, enabling a TOFU-shaped call. | Candidates no longer expose an accepted identity. `AcceptedBankKeyIdentity` is constructible only through `from_out_of_band()` from independently transcribed strings. Trust tests reject direct construction and candidate identity reuse. |
| High | Default network interruptions were labeled transient without proof that no bytes were sent. | The default transport raises `AmbiguousTransportError`; only injected transports with positive no-send knowledge may use `TransientTransportError`. Retry-classification tests keep ambiguous outcomes non-retryable. |
| High | Segment references were not recoverable after restart, and transport calls were not bounded by the whole-operation control. | `SegmentStore.list_segments()` recovers the ordered index. A test spool proves restart lookup. `exchange()` requires `OperationControl`, checks cancellation, and caps both opening and every response-stream read to the remaining deadline using the injected clock. |
| High | HEV accepted schema-invalid mixed character content between element-only children. | The parser rejects non-whitespace root/child text and tails. Mutation tests cover root, return-code, and version boundaries. |
| High | X.509 validation omitted several profile constraints. | Validation now checks `rsaEncryption` SPKI, serial and validity bounds, self-key AKI contents, forbidden KeyUsage bits, unknown critical extensions, non-CA BasicConstraints, EKU/freshest-CRL absence, role separation, and self-signature. Synthetic negative certificates cover each constructible violation. |

The reviewer also noted weak coverage policy. CI now requires 85% aggregate
branch coverage plus individual gates of 90% for XML, HEV, and certificates and
85% for transport, so one file cannot hide behind another. Requiring literal
100% for these whole modules is risk-accepted at this pre-alpha stage because
they contain defensive branches that current dependency types cannot construct.
New XML signature and crypto modules will require their own complete
branch/vector gates before release.

The same non-author reviewer performed focused verification after both rounds
of fixes and reported no remaining blocker. Its final evidence was 58 passing
tests, 85.36% aggregate branch coverage, and per-file coverage of 91% for
certificates, 91% for HEV, 88% for transport, and 91% for XML. It also confirmed
that CA-marked certificates fail and every streamed response read refreshes its
deadline-bounded socket timeout. No reviewer edited the tree.
