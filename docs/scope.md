# Scope

EBICSMIT is intended to become a small Python library for read-only EBICS
workflows.

## In scope

- Retrieval of account information and bank metadata.
- Local validation and parsing required for those retrieval workflows.
- Authentication, signing, encryption, and transport only where required to
  perform approved downloads.
- Explicit, auditable order policy with fail-closed defaults.
- Original interoperability tests built from redistributable sources.

## Permanently out of scope

- Payment initiation or authorization.
- Uploading files or customer-to-bank business orders.
- BTU.
- Generic raw-order or arbitrary-request escape hatches that bypass policy.

## Deferred pending rights clarification

- Vendoring official EBICS schemas.
- Vendoring official EBICS order code lists.

The current repository is only a scaffold. Network transport, cryptography,
XML processing, key lifecycle, and concrete download order support have not
yet been implemented.
