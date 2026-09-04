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

Use a local filesystem. The session adapter holds an OS lock for the whole
lease; an expired deadline never allows another worker to steal a live lock.
Process exit releases the lock, so a restarted worker can recover safely. The
`locks` directory intentionally keeps empty lock records permanently: never
delete these while workers may be running. State, replay claims, document data
and directory entries are synchronized before progressing on POSIX. Windows
directory durability and access control need host-specific provision; mode bits
alone do not configure Windows ACLs. Network filesystems and power-loss recovery
on Windows have not been validated. Staging and publication must be on the same
filesystem for atomic rename.

Existing POSIX storage directories must already belong to the current user and
exclude group/other permissions. Previously stored example bank pins keyed only
by HostID are not migrated: repeat the independent digest comparison to accept
pins for the exact endpoint and HostID.

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
state.mkdir(mode=0o700, parents=True, exist_ok=True)
# Run only during first enrollment, then back up the protected directory.
# Existing directories, including partial setup, are deliberately rejected.
generate_subscriber_keys(state / "keys")

clock = SystemClock()
client = ReadOnlyClient(
    Bank(
        "https://ebics.example-bank.invalid/ebics",
        "BANKHOSTID",
        institution_name="Example Bank",
    ),
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
# These contain participant identifiers and certificates. Keep them in the
# protected state directory outside the repository, never in logs or chat.
with (state / "ini-letter.txt").open("xb") as letter:
    letter.write(ini.content)
hia = client.initialize_auth_encryption_keys(control, protocol)
with (state / "hia-letter.txt").open("xb") as letter:
    letter.write(hia.content)
```

Deliver both signed letters using the procedure agreed with the bank. Wait for
the bank to activate the subscriber. Do not generate new keys or repeat INI/HIA
when reopening the application. If initialization raises
`AmbiguousInitializationError`, its `pending_letter` preserves the submitted
key's letter; retain it privately and clarify acceptance with the bank before
submitting the letter or retrying.
Passing `protocol` into each call is optional; without it every operation pays
for another HEV round trip.

## Pinning the bank keys

`fetch_bank_keys` runs HPB and returns keys that are deliberately unusable.
Nothing works until you compare the digests against values the bank published
through a channel that is not this connection — a letter, or its published
security document. Typing the digests the same connection served you pins an
attacker's keys just as happily as the bank's.

```python
# Activation may take days: start a fresh deadline and negotiate again.
control = DeadlineControl.after(60, clock)
protocol = client.probe_versions(control)
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
descriptor = BtfDescriptor(
    service_name="EOP",
    message_name="camt.053",
    message_version="08",
    variant=None,
    format=None,
    service_option=None,
    container_type=ContainerType.ZIP,
    scope=None,
)
sink = FileDocumentSink(state / "staging", state / "documents")
documents = client.download(
    "2026-08-statements",  # your own resumable session ID
    descriptor,
    sink,
    DeadlineControl.after(600, clock),
    protocol=protocol,
)
```

The descriptor above is illustrative, not a bank-specific service mapping. Ask
the bank for its exact BTF parameters (including scope and container), or inspect
`client.discover_capabilities(DeadlineControl.after(60, clock), protocol)`.
`NONE` and `ZIP` are supported; XML/SVC framing is not implemented. The downloaded
bytes remain opaque: parsing statements and importing payments belongs to your app.

Reuse the same session ID and arguments to resume an interrupted download. With
`protocol` supplied, a completed session returns its documents without network
I/O; otherwise the client first performs HEV. Use a **new session ID for every
new retrieval**, even for the same account and BTF descriptor, or you will keep
getting the earlier result. Reconcile overlapping statement periods in your app.

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
    DeadlineControl.after(60, clock),
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
