# Changelog

All notable changes will be recorded here. The project has made no release.

## Unreleased

### Changed

- Renamed the pre-release project, repository, and distribution from `ebicsmit`
  to `ebics-read`, the Python package to `ebics_read`, and the base exception
  to `EbicsReadError` so the brand describes the structural read-only boundary
  rather than embedding the license name.
- Raised the `cryptography` dependency floor to 50.0.0 so supported installs
  cannot resolve to a release affected by
  [GHSA-g6cj-pr64-35w5](https://github.com/pyca/cryptography/security/advisories/GHSA-g6cj-pr64-35w5)
  (CVE-2026-69247, introduced in 44.0.0, fixed in 50.0.0). EBICS Read does not
  call the affected PKCS#7 `EnvelopedData` decryption helpers, so the floor is
  defence in depth rather than a fix for a reachable path here.
- Enforced BTD deadlines and cancellation throughout protected-spool reading,
  base64/AES/zlib processing, ZIP extraction, staging, and publication.
- Emitted the X002 request `SignatureValue` padded to exactly one modulus width.
  A key provider that returns the signature as a bignum, dropping leading zero
  octets, previously passed local verification but put a short value on the wire
  for roughly one signature in 256.
- Allowed every client operation to accept an already-negotiated
  `NegotiatedProtocol`, removing one HEV round trip per call. Omitting it keeps
  the previous re-negotiating behaviour, and a supplied value cannot widen the
  accepted versions because it has already passed `select_h005`.

### Added

- `ReadOnlyClient.resolve_ambiguous_receipt`, an explicit operator decision point
  for a positive receipt whose outcome the transport could not establish. Such a
  session previously dead-ended: verified documents stayed staged forever, never
  published and never discarded, while the spool and session state leaked.
- `DownloadSession.to_mapping` and `DownloadSession.from_mapping`, so a
  caller-owned `SessionStore` can persist resumable state at all. Sessions are
  constructible only through validated transitions, which left no supported way
  to survive a restart; reloading re-runs every construction invariant.
- `examples/local_provider.py`, a tested filesystem reference implementation of
  the five caller-supplied seams that previously shipped no implementation at
  all, plus `examples/README.md` as the end-to-end runbook. The examples are not
  part of the distribution.
- Per-module branch-coverage floors in CI, so the new protocol modules cannot
  regress behind the aggregate gate.

- Typed read-only operation and trust boundaries.
- Hardened XML and HTTPS foundations using synthetic tests.
- Exact H000 HEV parsing with H005/03.00-only negotiation.
- Concrete end-to-end HEV backend, production clock/nonce/control defaults,
  namespace-preserving bounded parsing, official-H000-schema opt-in validation,
  and a verified local-TLS integration test.
- Strict self-signed H005 bank-certificate candidate validation and separately
  typed certificate fingerprints, EBICS public-key digests, and OOB identities.
- Explicit BTD receipt states plus leased resumable-state, protected-segment,
  streaming document-sink, provenance, deadline, cancellation, and retry seams.
- Exact typed 128-bit transaction IDs and a persistent atomic replay-claim seam.
- Typed HPD parameters and BTD-only HKD/HTD account and subscriber permissions.
- Request-bound resumable BTD state and deferred, idempotent document publication.
- Strict common H005 response envelopes and contextual Annex 1 return-code parsing.
- Exact X002 response authentication using only explicitly pinned bank keys.
- A key-provider surface without A006 business signing or generic crypto escape hatches.
- Incremental fixed E002 decryption with validated transaction keys and padding.
- Exact end-to-end H005 INI with strict A006 subscriber-certificate validation,
  official-schema evidence, and deterministic initialization-letter data.
- Exact end-to-end H005 HIA with strict X002/E002 subscriber-certificate
  validation and two-certificate initialization-letter data.
- Exact H005 HPB with fresh replay protection, verified X002 request signing,
  bounded E002 response processing, and untrusted bank-key candidates.
- Exact segmented H005 HAA with X002-authenticated control metadata, bounded
  E002 processing, durable transaction replay claims, strict BTF services, and
  verified positive or negative receipts.
- Exact segmented HPD, HKD, and HTD discovery with strict typed projection of
  bank parameters, BTF services, accounts, subscribers, and permissions.
- Exact H005 BTD initialization, transfer, and receipt envelopes with protected
  crash recovery, bounded E002/zlib/ZIP processing, negative-receipt failure
  handling, and idempotent receipt-before-publication delivery.
- Default-CI synthetic BTD over verified local TLS plus an explicitly gated
  live-bank smoke contract that isolates relative provider writes and requires
  protected persistent state outside the repository.
- Architecture, threat-model, protocol-scope, key-lifecycle, interoperability,
  and clean-room source documentation.
