# Clean-room policy

EBICSMIT must be independently designed from lawful, documented sources.

## Allowed inputs

- Public protocol documentation whose use is compatible with independent
  implementation.
- Publicly observable interoperability behavior, provided tests contain no
  confidential customer or bank data.
- Original design work created for this repository.

Every protocol source used for implementation must be recorded in
`docs/clean-room-sources.md`, including its title and version, URL or publication
identity, access date, SHA-256 where an artifact was retrieved, license or terms
assessment, and the exact EBICSMIT requirement it informed.

## Prohibited inputs

- Source code from proprietary, source-available-but-nonfree, leaked, or
  otherwise nonfree EBICS implementations.
- Copied implementation structure, tests, fixtures, comments, or generated
  artifacts from those implementations.
- Confidential bank documentation or production customer data.

Knowledge gained from routine use of an implementation does not authorize
copying its internals. When provenance is uncertain, stop and open a public
design issue before writing code.

## Schemas and code lists

Do not vendor official EBICS XML schemas, order-type catalogs, or code lists
until their redistribution rights are clarified and documented. Tests should
use small, original fixtures that exercise only the behavior under test.
