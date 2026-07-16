# EBICS Read

An independent, MIT-licensed, read-only Python client for EBICS 3.0/H005.

> [!WARNING]
> EBICS Read is pre-alpha foundation work, not a usable or production-ready EBICS
> client. It has not completed cryptographic implementation or bank
> interoperability testing.

EBICS Read is an independent open-source project. It is not affiliated with or
endorsed by EBICS SC or any financial institution.

EBICS is a registered trademark of EBICS SC. The name is used descriptively to
identify the published protocol. This project uses no EBICS, “Ready for EBICS”,
or bank logos and makes no certification or conformance claim.

## Boundary

The library is direct user-to-bank and application-neutral. It has no hosted
proxy, API keys, registration, license service, telemetry, credential cloud,
database, scheduler, persistent keyring, UI, accounting policy, or ISO 20022
document interpretation.

The fixed operation set is HEV, INI, HIA, HPB, HPD, HAA, HKD, HTD, and BTD.
There is no BTU, business upload, payment initiation, pain.001, direct debit,
EDS/VEU, or generic raw-order method. INI and HIA initialize subscriber keys;
they cannot carry business documents.

Current foundation APIs provide:

- immutable bank, subscriber, BTF, date, account, capability, and result models;
- injected key, bank-key trust, transport, clock, nonce, session, segment-spool,
  streaming document-sink, deadline, and cancellation protocols;
- separate certificate fingerprints and normative H005 public-key digests, with
  explicit out-of-band bank-key acceptance only after strict X.509 validation;
- exact H000 HEV parsing and H005/03.00 selection without H004 fallback;
- a concrete HEV backend joining fixed request construction, bounded HTTPS,
  namespace-preserving XML parsing, and H005 selection;
- production system-clock, CSPRNG nonce, deadline, and cancellation defaults;
- HTTPS-only TLS 1.2+ transport with certificate verification, no redirects,
  no implicit environment proxy, and bounded responses;
- an XML parser boundary that rejects DTDs, entities, XInclude, recovery,
  duplicate IDs, and configured resource-limit violations;
- synthetic deterministic testing helpers that must never hold production
  secrets.

HEV is the only complete protocol transaction: fixed request construction,
verified HTTPS exchange, bounded response parsing, and H005 selection. H005
envelopes, signatures, encryption, initialization, discovery, and segmented
BTD execution remain unimplemented. Synthetic local-TLS and separately supplied
official-schema evidence does not establish bank interoperability or conformance.

## Development

Python 3.10 or newer is supported.

Packaging uses the distribution name `ebics-read`; Python code imports the
underscore package:

```python
import ebics_read
```

For development:

```console
python -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m ruff format --check .
.venv/bin/python -m ruff check .
.venv/bin/python -m mypy
.venv/bin/python -m pytest
.venv/bin/python -m build
```

Read [Architecture](docs/architecture.md), [Threat model](docs/threat-model.md),
[Protocol scope](docs/protocol-scope.md), and
[Clean-room sources](docs/clean-room-sources.md) before contributing.

## Security evidence

All current protocol fixtures are original and synthetic. No live-bank evidence
exists. No external human security audit has been performed. Agent review is
recorded as agent review and is not described as an independent security audit.

## License

EBICS Read is licensed under the [MIT License](LICENSE). Official EBICS
specifications, schemas, implementation guides, annexes, and code lists are not
included and are not covered by this license.
