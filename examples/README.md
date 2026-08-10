# Examples

These files are not part of the `ebics-read` distribution. They are reference
implementations to read and copy, with no compatibility promise.

[`local_provider.py`](local_provider.py) implements all six protocols a caller
must supply before any download can run, backed by files under one `0o700`
directory:

| Protocol | Reference implementation | What it owns |
| --- | --- | --- |
| `KeyProvider` | `FileKeyProvider` | The three subscriber private keys and their certificates |
| `BankKeyTrustStore` | `FileBankKeyTrustStore` | Bank keys pinned against out-of-band digests |
| `SessionStore` | `FileSessionStore` | Resumable state, leases, durable replay claims |
| `SegmentStore` | `FileSegmentStore` | The encrypted response spool for one transaction |
| `DocumentSink` | `FileDocumentSink` | Staging, then publication after receipt |
| `OperationControl` | `DeadlineControl` (shipped) | The whole-operation deadline and cancellation |

Confidentiality is filesystem permissions only. On a shared host, or on a disk
that is not already encrypted, wrap the spool and the key loader in an AEAD or a
KMS/HSM client before using any of this.

## First run

```python
from pathlib import Path

from ebics_read import (
    AcceptedBankKeyIdentity,
    Bank,
    BtfDescriptor,
    ContainerType,
    DeadlineControl,
    EbicsBackend,
    HttpsTransport,
    ProtocolLimits,
    ReadOnlyClient,
    SecureNonceSource,
    Subscriber,
    SystemClock,
)
from local_provider import (
    FileBankKeyTrustStore,
    FileDocumentSink,
    FileKeyProvider,
    FileSegmentStore,
    FileSessionStore,
    generate_subscriber_keys,
)

state = Path("~/.ebics-read").expanduser()
generate_subscriber_keys(state / "keys")  # once, then back this up

clock = SystemClock()
client = ReadOnlyClient(
    Bank("https://ebics.example-bank.invalid/ebics", "BANKHOSTID"),
    Subscriber("PARTNERID", "USERID", None),
    EbicsBackend(
        HttpsTransport(clock=clock),
        key_provider=FileKeyProvider(state / "keys"),
        clock=clock,
        nonce_source=SecureNonceSource(),
        session_store=FileSessionStore(state / "sessions"),
        segment_store=FileSegmentStore(state / "spool"),
        protocol_limits=ProtocolLimits(),
    ),
    FileBankKeyTrustStore(state / "trust"),
)
```

## Initialization, once per subscriber

```python
control = DeadlineControl.after(60, clock)
protocol = client.probe_versions(control)  # HEV; reuse it below

ini = client.initialize_signature_key(control, protocol)
hia = client.initialize_auth_encryption_keys(control, protocol)
Path("ini-letter.txt").write_bytes(ini.content)
Path("hia-letter.txt").write_bytes(hia.content)
```

Print, sign and post both letters. Wait for the bank to activate the subscriber.
Passing `protocol` into each call is optional; without it every operation pays
for another HEV round trip.

## Pinning the bank keys

`fetch_bank_keys` runs HPB and returns keys that are deliberately unusable.
Nothing works until you compare the digests against values the bank published
through a channel that is not this connection — a letter, or its published
security document. Typing the digests the same connection served you pins an
attacker's keys just as happily as the bank's.

```python
candidate = client.fetch_bank_keys(control, protocol)
client.accept_bank_keys(
    candidate,
    AcceptedBankKeyIdentity.from_out_of_band(
        "…64 hex characters transcribed from the bank…",
        "…64 hex characters transcribed from the bank…",
    ),
)
```

Rotation requires the same explicit comparison again.

## Downloading

```python
documents = client.download(
    "2026-08-statements",  # your own resumable session ID
    BtfDescriptor("EOP", "camt.053", "08", None, None, None, ContainerType.ZIP),
    FileDocumentSink(state / "staging", state / "documents"),
    DeadlineControl.after(600, clock),
    protocol=protocol,
)
```

Reuse the same session ID to resume an interrupted download. Everything is
idempotent: a completed session returns its documents without contacting the
bank. Ask the bank which BTF service parameters it expects, or read them from
`client.discover_capabilities(control, protocol)`.

## When a receipt outcome is unknown

If the connection breaks while the positive receipt is in flight, EBICS Read
cannot know whether the bank recorded it, and refuses to guess: the documents
stay staged and unpublished, and `AmbiguousTransportError` is raised on every
retry. Only you can resolve it, by asking the bank whether the transaction was
acknowledged:

```python
documents = client.resolve_ambiguous_receipt(
    "2026-08-statements",
    descriptor,
    sink,
    control,
    bank_confirmed_acceptance=True,  # the bank recorded it: publish
    protocol=protocol,
)
```

With `bank_confirmed_acceptance=False` the staged documents and the spool are
discarded and the session is deleted, so the data the bank still holds can be
downloaded again. Every other argument must match the original download.

## Running the tests for these adapters

```bash
python -m pytest tests/test_examples_local_provider.py
```
