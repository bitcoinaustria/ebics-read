# Changelog

All notable changes will be recorded here. The project has made no release.

## Unreleased

### Changed

- Renamed the pre-release project, repository, and distribution from `ebicsmit`
  to `ebics-read`, the Python package to `ebics_read`, and the base exception
  to `EbicsReadError` so the brand describes the structural read-only boundary
  rather than embedding the license name.

### Added

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
- Architecture, threat-model, protocol-scope, key-lifecycle, interoperability,
  and clean-room source documentation.
