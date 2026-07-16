# Coding-agent rules

These rules apply to the entire repository.

## Clean room

- Use only public standards, public bank documentation, normative security and
  cryptography standards, and original synthetic fixtures.
- Never inspect, copy, port, paraphrase, or AI-rewrite code, tests, fixtures, or
  internal documentation from proprietary, PolyForm, source-available, leaked,
  or otherwise nonfree EBICS implementations.
- Record every protocol source in `docs/clean-room-sources.md` before using it.
- Do not vendor EBICS SC documents, schemas, or code lists unless their
  redistribution and sublicensing terms are explicitly cleared in writing.

## Structurally read-only

- The only EBICS operations are HEV, INI, HIA, HPB, HPD, HAA, HKD, HTD, and BTD.
- Never add BTU, payment initiation, pain.001, direct debit, upload, EDS/VEU,
  arbitrary order execution, or raw-request escape hatches.
- INI and HIA are key initialization, not business-data uploads.
- Tests must prove prohibited orders cannot be constructed or sent.

## Security

- Never weaken validation to accommodate a fixture or bank.
- Bank keys remain unusable until their typed EBICS public-key digests are
  explicitly pinned against values obtained out of band. Rotation requires
  another explicit comparison. A generic certificate fingerprint is not an
  EBICS public-key digest.
- Unknown algorithms and return codes fail closed.
- Do not log protocol XML, documents, certificates, keys, identifiers, nonces,
  transaction IDs, account data, or credentials.
- Keep test data synthetic. Live credentials and bank data never enter the
  repository, command arguments, chat, fixtures, or public CI.
- Compose audited cryptographic primitives; never implement them.

## Evidence

- Distinguish synthetic, schema, mock, and live evidence.
- Never claim conformance, certification, bank support, production readiness,
  human review, or an independent security audit without the required evidence.
- Adversarial agent review is not an external human security audit.
