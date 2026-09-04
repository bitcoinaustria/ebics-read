# EBICS Read

An independent, MIT-licensed, read-only Python client for EBICS 3.0/H005.

> [!WARNING]
> EBICS Read is pre-alpha and not production-ready. Its fixed read-only protocol
> paths have synthetic evidence only; bank interoperability has not been tested.

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

- immutable bank, subscriber, BTF, date, account, HPD/HKD/HTD capability, and
  result models;
- injected key, bank-key trust, transport, clock, nonce, request-bound replay-safe
  session, segment-spool, deferred-publication document-sink, deadline, and
  cancellation protocols;
- separate certificate fingerprints and normative H005 public-key digests, with
  explicit out-of-band bank-key acceptance only after strict X.509 validation;
- exact H000 HEV parsing and H005/03.00 selection without H004 fallback;
- fixed standard/key-management H005 response envelopes with contextual,
  fail-closed technical and business return-code parsing;
- exact X002 response digest/signature verification against the explicitly
  pinned bank authentication certificate;
- fixed E002 transaction-key and incremental order-data decryption;
- concrete HEV, INI, HIA, HPB, HPD, HAA, HKD, HTD, and BTD backends, including
  strict certificate validation, printable initialization letters, bounded
  segmented downloads, replay rejection, exact receipts, crash recovery, and
  receipt-before-publication document delivery;
- explicit operator resolution of an unknown positive-receipt outcome, which
  publishes or discards the already-verified stages instead of dead-ending;
- JSON-safe session-state projection so a caller-owned store can persist and
  re-validate resumable state across a restart;
- production system-clock, CSPRNG nonce, deadline, and cancellation defaults;
- HTTPS-only TLS 1.2+ transport with certificate verification, no redirects,
  no implicit environment proxy, and bounded responses;
- an XML parser boundary that rejects DTDs, entities, XInclude, recovery,
  duplicate IDs, and configured resource-limit violations;
- synthetic deterministic testing helpers that must never hold production
  secrets.

Every fixed operation has a complete synthetic protocol path. BTD accepts raw
(`NONE`) and bounded ZIP containers; XML and SVC container framing fails closed
until a public specification is recorded. Synthetic local-TLS and separately
supplied official-schema evidence does not establish bank interoperability or
conformance.

## Getting started

Before requesting access, use the [bank-pilot guide](docs/bank-pilot.md) to agree
on the supported protocol, certificate profile, statement service and test
procedure. It includes a draft inquiry and distinguishes implemented paths from
the live evidence still needed.

Six seams are deliberately not implemented here, because keys, durable state and
document storage are application decisions: `KeyProvider`, `BankKeyTrustStore`,
`SessionStore`, `SegmentStore`, `DocumentSink`, and `OperationControl`. Only the
last has a shipped default (`DeadlineControl`).

[`examples/local_provider.py`](examples/local_provider.py) is a complete,
tested, filesystem-backed reference implementation of the other five, and
[`examples/README.md`](examples/README.md) is the runbook: generate subscriber
keys, produce the INI and HIA letters, pin the bank keys against out-of-band
digests, download, and resolve an unknown receipt outcome. The examples are not
part of the distribution; copy them rather than import them.

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
