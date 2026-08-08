# Interoperability evidence

## Evidence classes

- **Synthetic:** original fixtures generated for this repository.
- **Schema:** validated against separately downloaded official schemas with
  recorded hashes; an opt-in H000 test validates the HEV request and response
  when `EBICS_READ_H000_XSD` names the separately supplied official file. An
  opt-in H005 bundle tests validate generated INI/HIA/HPB/HPD/HAA/HKD/HTD/BTD envelopes and their
  decompressed S002/H005 order data.
- **Mock:** verified local-TLS synthetic endpoints exercise HEV and a complete
  BTD initialization, segmented transfer, positive receipt, and publication
  through the production HTTPS transport in the default CI matrix.
- **Live:** exercised with a consenting user's ordinary bank-issued read-only
  credentials; no such evidence exists yet.

Current evidence is normative-document review, synthetic tests for every fixed
operation, external official H000/H005/S002 schema validation, and local-TLS HEV
and BTD transactions. It proves neither EBICS conformance nor bank compatibility.

## Live harness rules

The live BTD smoke contract is opt-in and disabled in default CI. Set
`EBICS_READ_LIVE=I_ACCEPT_LIVE_READ_ONLY_BANK_IO` and name an external, untracked
Python provider module with `EBICS_READ_LIVE_PROVIDER`. That module supplies
`make_live_btd_case()`, returning `(client, session_id, descriptor, sink,
control, options)`; `options` may be `None`. The test runs the provider and
transaction from a fresh temporary working directory and redirects Python-level
stdout and stderr. The provider must use protected absolute paths outside the
repository for persistent keys, stores, and sink output, emit no sensitive
output through any channel, and retain secrets no longer than needed.
Credentials never enter command arguments, chat, committed files, example
configuration, public CI, or fixtures. The repository and fixtures record no
real certificates, XML, identifiers, or financial documents.

The smoke performs HEV then one read-only BTD through `ReadOnlyClient`.
Initialization and OOB trust setup remain provider-owned prerequisites.
Validation must never be weakened to accommodate a bank. Bank-specific
differences are documented as sanitized behavior, not copied messages.

## Release gates

“Experimental” requires resolved or explicitly risk-accepted adversarial agent
review of XML signature verification, successful INI/HIA/HPB/HPD/HAA/HKD/HTD against one real
bank with verified pinning, successful statement BTD with receipt completion,
and passing security-negative tests.

1.0 additionally requires read-only initialization and downloads against at
least two Austrian banks and one non-Austrian H005 bank, fresh-context
adversarial agent review of key lifecycle and BTD state machine, no unresolved
high-severity findings, and documented bank differences.

No mock result may be described as conformance. No external human security audit
has been performed.
