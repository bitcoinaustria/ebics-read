# EBICSMIT

EBICSMIT is an early, clean-room Python scaffold for structurally read-only
EBICS access. Its intended scope is retrieving account information and bank
metadata. It does not provide payment initiation, file upload, or BTU support.

> [!WARNING]
> This repository is a design scaffold, not a production-ready EBICS client.
> It currently performs no network or cryptographic operations.

## Safety boundary

The public API is deliberately narrow:

- `ReadOnlyClient` exposes only `download()`.
- Requests can represent only account-information or bank-metadata retrieval.
- A caller-provided policy must explicitly approve every retrieval capability.
- The default policy approves nothing.
- Raw EBICS order types are not part of the public API.
- The transport protocol has no upload, submit, or payment method.

This is defense in depth, not a claim that the scaffold already implements the
EBICS protocol. See [Scope](docs/scope.md) and
[Clean-room policy](docs/clean-room.md) before contributing.

## Development

The scaffold has no runtime dependencies. Run its checks with Python 3.11 or
newer:

```console
PYTHONPATH=src python -m unittest discover -s tests -v
python -m compileall -q src tests
```

## Licensing and affiliation

EBICSMIT is licensed under the [MIT License](LICENSE). It is an independent
project and is not affiliated with or endorsed by the EBICS SCRL or its
members. EBICS names and marks belong to their respective owners.

Official EBICS schemas and code lists are intentionally not vendored. They
will remain absent until their redistribution terms have been clarified.
