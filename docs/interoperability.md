# Interoperability evidence

## Evidence classes

- **Synthetic:** original fixtures generated for this repository.
- **Schema:** validated against separately downloaded official schemas with
  recorded hashes; an opt-in H000 test validates the HEV request and response
  when `EBICSMIT_H000_XSD` names the separately supplied official file.
- **Mock:** a verified local-TLS synthetic endpoint exercises fixed HEV request
  construction, HTTPS transport, bounded parsing, and H005 selection; the test
  is enabled in the default supported Python/OS CI matrix.
- **Live:** exercised with a consenting user's ordinary bank-issued read-only
  credentials; no such evidence exists yet.

Current evidence is normative-document review, synthetic foundation tests,
external official-H000-schema validation, and a local-TLS HEV transaction. It
proves neither EBICS conformance nor bank compatibility.

## Live harness rules

The future harness is opt-in and disabled in default CI. Credentials enter only
through stdin, inherited file descriptors, or caller-controlled providers—never
command arguments, chat, committed files, example configuration, public CI, or
test fixtures. The harness retains no real identifiers, certificates, XML, or
financial documents.

Live work begins with HEV and initialization, then a statement BTD. Validation
must never be weakened to accommodate a bank. Bank-specific differences are
documented as sanitized behavior, not copied messages.

## Release gates

“Experimental” requires resolved or explicitly risk-accepted adversarial agent
review of XML signature verification, successful INI/HIA/HPB against one real
bank with verified pinning, successful statement BTD with receipt completion,
and passing security-negative tests.

1.0 additionally requires read-only initialization and downloads against at
least two Austrian banks and one non-Austrian H005 bank, fresh-context
adversarial agent review of key lifecycle and BTD state machine, no unresolved
high-severity findings, and documented bank differences.

No mock result may be described as conformance. No external human security audit
has been performed.
