# Threat model

## Assets

- subscriber private keys and certificates;
- bank authentication and encryption keys and their accepted fingerprints;
- participant, host, account, nonce, request, and transaction identifiers;
- authenticated response metadata and opaque downloaded documents;
- resumable transaction state.

## Trust boundaries

1. Host application to immutable public models.
2. Protocol core to caller-controlled key, trust, clock, nonce, and session
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
- caller mistakes such as wrong endpoint, scope, fingerprint, date, or account;
- backend bugs that classify unknown codes or algorithms as success;
- accidental disclosure through logs, exceptions, representations, fixtures,
  command arguments, or CI artifacts.

## Structural controls already present

- Exact operation enum: HEV, INI, HIA, HPB, HPD, HAA, HKD, HTD, BTD.
- No client method accepts an order type, XML, URL, or arbitrary parameter map.
- HPB returns an untrusted type; discovery and BTD require a trusted type
  obtained only from the named explicit OOB acceptance constructor.
- Default HTTPS requires certificate verification and TLS 1.2+, refuses
  redirects, bounds response bytes, and rejects caller-constructed requests.
  There is no insecure public flag or public arbitrary-body exchange.
- XML parsing disables DTD loading, entity resolution, network access,
  recovery, and huge trees. A bounded parse target rejects depth, element,
  text, XInclude, duplicate-ID, comment, and processing-instruction violations
  as events arrive, including document-level nodes outside the root.
- Download state can be created or restored only through invariant-checking
  methods. Segment receipt accepts exactly the next expected segment and makes
  completed and receipt states unreachable while segments are missing.
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
- Separate transient transport retry from terminal protocol/security failure.
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
| High | `TrustedBankKeys` could be constructed directly from an HPB candidate, bypassing explicit acceptance. | Its public constructor now rejects creation; `accept_out_of_band` is the sole supported factory and compares both expected SHA-256 fingerprints in constant time. Trust tests cover direct construction, mismatch, initial pinning, and rotation. |
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
