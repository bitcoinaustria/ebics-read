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
- Artifact: `2022-06-27-EBICS_V_3.0.2_FinalVersion.pdf`
- Artifact SHA-256: `f12bd46e3afefef66d64838d221e96ebabd1bf579ef15d3a92e8524d43636b3c`
- Annex 1 artifact: `2022-06-27-EBICS_V_3.0.2_Annex1_ReturnCodes-Final.pdf`
- Annex 1 SHA-256: `5f6e4b2f273f4626f4222cef903abffa30e1fd64beb2acd820d4244c9cda008a`
- Status: normative artifacts downloaded outside the repository after the user
  personally authorized acceptance of the published terms on 2026-07-15
- Learned: exact H005 public-key-digest input, H005 version identifiers,
  receipt semantics, return-code source, and fixed A006/X002/E002 parameters
- Redistribution: not vendored; terms are not clearly MIT-sublicensable

### EBICS Schema index — H000/H005/S002

- Publisher: EBICS SC / SIZ GmbH
- URL: https://www.ebics.org/en/technical-information/ebics-schema
- Retrieved: 2026-07-15
- Retrieved-page SHA-256: `f5053e3c0c44fc399b90bee77b45c91cbd8f43a12b7383c49dab391b8b3bdd16`
- Artifact: `EBICS_3.0_schema_H005FinalVersion07-08-2017.zip`
- Artifact SHA-256: `e2cec4c8b0a43c325e0e6a84f969834ac47f921cdfa1fd59f9784eb46599863d`
- Archive member: `ebics_hev.xsd`
- Archive-member SHA-256: `0f529a5220181ef8d99876daddafecd70a53717a2826ff13581147d769ec5056`
- Status: normative archive downloaded and inspected outside the repository;
  no schema file is vendored
- Learned: official H000 HEV, H005 envelope/order/type/key-management, S002,
  and W3C XMLDSig schema file set; exact namespaces are
  `http://www.ebics.org/H000` and `urn:org:ebics:H005`; the H000 schema makes
  `xsi:schemaLocation` an optional instance hint rather than constraining it to
  a particular local filename
- Verification: the unmodified external `ebics_hev.xsd` validated EBICS Read's
  generated request and synthetic response on 2026-07-15; the opt-in test does
  not redistribute or resolve the schema over the network and rejects any leaf
  file that does not match the recorded archive-member digest
- Redistribution: not vendored for the same no-sublicensing ambiguity

### Common EBICS Implementation Guide index — version 03

- Publisher: EBICS SC
- URL: https://www.ebics.org/en/technical-information/implementation-guide
- Retrieved: 2026-07-15
- Retrieved-page SHA-256: `548c5f39d8e99fccb7cfd22f5e9c81d95036a8705b9963c4c4f2aa4ba4f5c797`
- Artifact: `2022-06-27-EBICS_Common_IG_based_EBICS_3.0-ExtVersion03-FinalVersion.pdf`
- Artifact SHA-256: `c8715987e78329bf2babf128d74ae7b8dea5559cee84b4a5d21212c19dd8e43f`
- Status: official informative/interoperability guide downloaded outside the
  repository after acceptance of the published terms
- Learned: self-signed bank certificate profile details, RSA key-size bounds,
  role-specific key usage, validity checks, and interoperability guidance
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

### EBICS BTF external code list

- Publisher: EBICS SC / SIZ GmbH
- Source URL: https://www.ebics.org/en/technical-information/ebics-specification
- Retrieved: 2026-07-15
- Artifact: `2024-10-23-EBICS_Annex_BTF-ExternalCodeList.7z`
- Artifact SHA-256: `33e4fe2cb75f2c6182d9e8c46c9b8252b37f8f91d46cde8e1a64845292d4dee9`
- Status: official annex downloaded outside the repository after acceptance of
  the published terms
- Learned: descriptor values are external policy/code-list data and must remain
  caller supplied or independently mapped rather than hard-coded in core
- Redistribution: not vendored

### EBICS TLS and key-management security annex

- Publisher: EBICS SC / SIZ GmbH
- Source URL: https://www.ebics.org/en/technical-information/ebics-specification
- Retrieved: 2026-07-15
- Artifact: `2026-03-20-EBICS_Annex_TLS_and_KMS-final.pdf`
- Artifact SHA-256: `d8537a567a87500db476865929dfc086b0a47662462a91869fedaf0ed58b7cb3`
- Status: normative security annex downloaded outside the repository after
  acceptance of the published terms
- Learned: current TLS and protected-key-operation/storage recommendations;
  these do not weaken the TLS 1.2 minimum or caller-controlled key boundary
- Redistribution: not vendored

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

## Normative artifact status

The foundation gate was satisfied on 2026-07-15: the user personally authorized
acceptance of the published download terms; the artifacts above were downloaded
to an untracked temporary directory, hashed, and reviewed there. They are not
committed, redistributed, or covered by this repository's MIT license. Future
contributors must independently obtain matching artifacts under the publisher's
terms. National AT/DE/FR/CH mapping artifacts still require individual rights
review before use or redistribution.

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
