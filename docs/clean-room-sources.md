# Clean-room source manifest

Retrieved snapshots are used for provenance checking outside the repository.
Their hashes do not license or vendor the underlying works. Dynamic web pages
may produce different bytes on later retrieval.

No proprietary, PolyForm, source-available, leaked, or otherwise nonfree EBICS
implementation code, tests, fixtures, or internal documentation was inspected.

## Normative and official protocol sources

### EBICS Specification index — EBICS 3.0.2

- Publisher: EBICS SC / SIZ GmbH
- URL: https://www.ebics.org/en/technical-information/ebics-specification
- Retrieved: 2026-07-15
- Retrieved-page SHA-256: `213bea8914a084386c5bf91ce0432208d2322df82f6ea84345092dea2ec44e0d`
- Status: normative index and download terms; specification artifact not
  downloaded because accepting the click-through terms requires explicit user
  approval
- Learned: 3.0.2 validity date; BTF and TLS/KMS annex independence; trademark,
  reproduction, no-derivative, and no-sublicensing constraints
- Redistribution: not vendored; terms are not clearly MIT-sublicensable

### EBICS Schema index — H000/H005/S002

- Publisher: EBICS SC / SIZ GmbH
- URL: https://www.ebics.org/en/technical-information/ebics-schema
- Retrieved: 2026-07-15
- Retrieved-page SHA-256: `f5053e3c0c44fc399b90bee77b45c91cbd8f43a12b7383c49dab391b8b3bdd16`
- Status: normative artifact index; XSD archive not downloaded
- Learned: official H000 HEV, H005 envelope/order/type/key-management, S002,
  and W3C XMLDSig schema file set
- Redistribution: not vendored for the same no-sublicensing ambiguity

### Common EBICS Implementation Guide index — version 03

- Publisher: EBICS SC
- URL: https://www.ebics.org/en/technical-information/implementation-guide
- Retrieved: 2026-07-15
- Retrieved-page SHA-256: `548c5f39d8e99fccb7cfd22f5e9c81d95036a8705b9963c4c4f2aa4ba4f5c797`
- Status: official informative/interoperability guide index; artifact not
  downloaded
- Learned: common guide applies across EBICS countries and version 03 includes
  implementation experience
- Redistribution: not vendored

### EBICS BTF mapping hub

- Publisher: EBICS SC
- URL: https://www.ebics.org/en/technical-information/btf-mapping
- Retrieved: 2026-07-15
- Retrieved-page SHA-256: `ccc1861e081b3a31911fd0dc29028d4ffb01bf10b029047aeb48eaafd212fe7a`
- Status: official informative mapping directory
- Learned: national mappings are separately maintained for Austria, Germany,
  France, and Switzerland; BTF policy must not be hard-coded in core
- Redistribution: linked mapping artifacts are not vendored pending individual
  rights review

### EBICS Technical News — TLS and KMS update

- Publisher: EBICS SC
- URL: https://www.ebics.org/en/current-topics/technical-news
- Retrieved: 2026-07-15
- Retrieved-page SHA-256: `45fe2bae6f695d239bb8bbb43298cea3bff694ab1a38dee2f62d6693a778b831`
- Status: official informative/current security notice
- Learned: March 2026 TLS/KMS storage recommendations for existing EBICS 2.x/3.0
  and planned EBICS 4.0 requirement
- Redistribution: page not vendored

### EBICS versioning rules and 3.0.1/3.0.2 change-request index

- Publisher: EBICS SC / SIZ GmbH
- URLs:
  - https://www.ebics.org/en/technical-information/maintain-advance/versioning-rules
  - https://www.ebics.org/en/technical-information/archive-ebics/change-requests
- Retrieved: 2026-07-15
- Retrieved-page SHA-256:
  - `1ba1758f3b94d5ba01d6e4871e8a033faec106542967ab6c3d88acbf05162bbf`
  - `153c07dd2859fd6f0167fe6e899252ab399e426939be13e8ce7a45601d6f510f`
- Status: official normative process and revision index
- Learned: revision versions contain clarifications and do not change schemas;
  3.0.1/3.0.2 had no schema change
- Redistribution: change-request archive not vendored

## Normative artifact gate

Before protocol envelope or crypto implementation, a developer must separately
accept the official terms, download the 3.0.2 specification, H000/H005/S002
schemas, current TLS/KMS annex, implementation guide, and BTF list outside the
repository, then record exact titles, versions, filenames, retrieval date, and
SHA-256 values here. The project must not automate acceptance on the user's
behalf.

## Known implementations excluded as protocol sources

Only public landing-page/package metadata retrieved on 2026-07-15 was used for
this informative, non-normative ecosystem check:

- `fintech`: https://pypi.org/project/fintech/ — pure-Python EBICS/SEPA package
  under a commercially restricted license; its unlicensed EBICS mode limits
  uploads and prevents statement retrieval for the most recent three days.
- `ebicsclient`: https://pypi.org/project/ebicsclient/ — pure-Python H005 client
  under PolyForm Noncommercial 1.0.0; its public description includes BTU
  payment upload and reports live validation against Zürcher Kantonalbank.
- `ebics-api-client`: https://pypi.org/project/ebics-api-client/ — a Python
  client for a separately deployed EBICS API service, not a direct protocol
  implementation with the project's no-vendor-component philosophy.
- LibEuFin and publicly listed PHP/Java/Kotlin/Node clients confirm that EBICS
  implementations exist in other runtime and deployment models; they do not
  fill the narrow MIT-licensed, direct-to-bank, pure-Python, read-only position.

These entries are informative ecosystem metadata, not protocol sources. No
source distribution, repository tree, code, tests, fixtures, or implementation
documentation from any of them was opened. Nonfree/source-available projects,
including `fintech` and `ebicsclient`, remain explicitly excluded from all
implementation research.
