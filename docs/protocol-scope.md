# Protocol scope

## Target

EBICS 3.0 using H005, incorporating the textual clarifications in 3.0.1 and
3.0.2. Those revisions introduced no schema change. H000 is used for HEV and
S002 for electronic-signature structures. There is no normative H006 target.

## Fixed operation set

| Operation | Purpose | Direction |
| --- | --- | --- |
| HEV | Version discovery | administrative request |
| INI | Initialize signature certificate | key initialization |
| HIA | Initialize authentication and encryption certificates | key initialization |
| HPB | Fetch bank certificates as untrusted candidates | key initialization |
| HPD | Bank parameter discovery, when supported | read |
| HAA | Available order/service discovery, when supported | read |
| HKD | Customer/subscriber discovery, when supported | read |
| HTD | Account/subscriber discovery, when supported | read |
| BTD | BTF-described bank-to-customer download and receipt | read |

INI and HIA cannot contain caller business documents and are not general upload
APIs. BTU, pain.001, payment initiation, direct debit, EDS/VEU, arbitrary order
execution, HCA/HCS renewal, and SPR suspension are absent. Expired or suspended
v1 subscribers must repeat the bank's INI/HIA letter process.

## Certificates

H005 transports subscriber and bank key material as X.509 certificates. The v1
subscriber profile is self-signed certificates as used in documented Austrian
and German practice. CA-issued French CFONB-profile certificates remain out of
scope until requested and independently specified. No claim is made that every
bank accepts the same self-signed profile.

## Legacy-but-normative crypto

The implementation must not “modernize” protocol algorithms. The project
charter pins the following expected parameters so later work cannot substitute
newer algorithms for interoperability. They are not yet implementation evidence:
each detail must be independently checked against the accepted official 3.0.2
artifact and a recorded vector before code is written:

- E002 uses RSA PKCS#1 v1.5 transaction-key transport, a 16-byte AES key,
  AES-128-CBC, an all-zero IV/ICV, and the specified ANSI X9.23/ISO 10126-2
  block padding.
- A006 uses the EBICS-specific prehash construction, SHA-256, MGF1/SHA-256,
  exactly 32 bytes of PSS salt, and trailer byte `0xBC`; generic PSS defaults are
  not acceptable.
- X002 uses Canonical XML 1.0, RSA/SHA-256 PKCS#1 v1.5, SHA-256 digests, and the
  exact authenticated-node XPointer semantics. A general XMLDSig verifier may
  not choose references on EBICSMIT's behalf.

Unknown algorithm identifiers fail closed.

## BTF/BTD

A `BtfDescriptor` always represents ServiceName, optional Scope, MsgName,
message version, Variant, Format, ServiceOption, and container type. Scope is
never hard-coded: callers may supply `AT`, `GLB`, `BIL`, another bank-specific
token, or omit it.

BTD is not complete until initialization, transaction-ID validation, ordered
segment transfer, authenticated response validation, decryption,
decompression/container extraction, return-code validation, and receipt
completion all succeed. Partial bytes are never returned as a document.

## Official artifact policy

EBICS SC download terms do not clearly grant downstream MIT-compatible
sublicensing. Official specifications, XSDs, guides, annexes, and BTF lists are
therefore not vendored. A developer may supply a separately downloaded
conformance bundle whose files match reviewed hashes. The bundle path and
contents must remain untracked.
