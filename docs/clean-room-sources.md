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
- Rechecked: 2026-09-05, the official 3.0.2 artifact matched the recorded hash;
  section 12.1.2 was used to distinguish optional EBICS transaction recovery
  synchronization from local restart support. Container codes alone do not
  specify XML/SVC framing.

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
- Rechecked: 2026-09-05, the official archive matched the recorded hash; all
  12 opt-in H000/H005/S002 compilation and generated-message tests passed.
- Archive-member SHA-256 values independently rechecked on 2026-08-08:
  - `ebics_H005.xsd`: `cf9d5d29fac0950f810c2a0018312fe476ab3415d804f5fc00cd4e3aa216136e`
  - `ebics_hev.xsd`: `0f529a5220181ef8d99876daddafecd70a53717a2826ff13581147d769ec5056`
  - `ebics_keymgmt_request_H005.xsd`: `7165cd441a0c68f6e93c384de743f97d0d768ac444d1adc6daf89d0e1edb0505`
  - `ebics_keymgmt_response_H005.xsd`: `9671ccf4282df1a4089f5d61a86378fa78e38d80292550a34422e15aa802ef3f`
  - `ebics_orders_H005.xsd`: `ce19f0e0b8cdfa05678a9e2123e09634f131107e08552e7a1371e6dbbf82e2f1`
  - `ebics_request_H005.xsd`: `48838ffd60275549849a7054223085154746b920e5f438cd16878fc62004d874`
  - `ebics_response_H005.xsd`: `19226688cd598581b37a7b32cb1df874c525aac710f68dbcc10e11b820eabd4d`
  - `ebics_signature_S002.xsd`: `6fcee44bdb80d656e05f11da86303bb25de2cf545203eef30dffbd6c662f8d93`
  - `ebics_types_H005.xsd`: `0c94813782e725b7698449f117a8f2e6e47d6560b3df83ca53a720d6f6fc4351`
  - `xmldsig-core-schema.xsd`: `43f97eddd32ca6df482ff1757cd55d784054fa36cb35d882ddc1e52669a37af6`

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

The recorded EBICS 3.0.2 specification, return-code annex, H005 schema archive,
and Common Implementation Guide were downloaded again to an untracked temporary
directory on 2026-08-08. Their SHA-256 values matched the entries above. No
artifact is committed or redistributed.

## Independent public security and encoding standards

The following publisher-hosted standards were retrieved on 2026-08-08. They
define only general primitives and encodings; EBICS-specific profiles and
message semantics continue to come exclusively from the recorded EBICS SC
artifacts.

### W3C XML standards

Terms assessment: public W3C Recommendations used as normative references;
their text is not vendored or relicensed.

- Canonical XML Version 1.0, W3C Recommendation 15 March 2001
  - URL: https://www.w3.org/TR/2001/REC-xml-c14n-20010315
  - Retrieved artifact SHA-256: `09c02ef3bc0f8364b00b16fb06092637c08e8f38cf223d47a5862eacc2956bc0`
  - Learned: inclusive Canonical XML 1.0 serialization rules
- XML Signature Syntax and Processing, Second Edition, W3C Recommendation
  10 June 2008
  - URL: https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/
  - Retrieved artifact SHA-256: `be7abe6228142da3d187415a84380a85ec74b5c2fd60e41e7db731647a4a9b21`
  - Learned: XMLDSig `SignedInfo`, reference digest, signature, and algorithm
    processing model
- XML Path Language (XPath) Version 1.0, W3C Recommendation 16 November 1999
  - URL: https://www.w3.org/TR/1999/REC-xpath-19991116/
  - Retrieved artifact SHA-256: `bf0d586e06b83cfcd60da4c6fe4c3841d3ecb10d3381e98b83b9e582cd0e9384`
  - Learned: XPath 1.0 data model and expression semantics used by the
    EBICS-specific authenticated-node selection profile

### IETF RFCs

Terms assessment: public RFC Editor publications used as normative references
under the IETF Trust legal provisions; their text is not vendored.

- RFC 8017, PKCS #1 v2.2
  - URL: https://www.rfc-editor.org/rfc/rfc8017.txt
  - Retrieved artifact SHA-256: `1e72dc473d18df3fc5598cdc12795a9f18f36f1aef15abc23a55eb0d58151d11`
  - Learned: RSAES-PKCS1-v1_5, RSASSA-PSS, RSASSA-PKCS1-v1_5, and MGF1
- RFC 5280, Internet X.509 Public Key Infrastructure Certificate and CRL Profile
  - URL: https://www.rfc-editor.org/rfc/rfc5280.txt
  - Retrieved artifact SHA-256: `a2f2628c0a83b873fc4786abd921f9b2c02395954b655d190bf16b831633345d`
  - Learned: general X.509 certificate and extension validation semantics
- RFC 4648, Base-N Encodings
  - URL: https://www.rfc-editor.org/rfc/rfc4648.txt
  - Retrieved artifact SHA-256: `84e14418f795d503be5f34bf23ce4ebaa119e9ec7c9f667d8caeb111385b178f`
  - Learned: strict base64 encoding and decoding
- RFC 1950, ZLIB Compressed Data Format Specification version 3.3
  - URL: https://www.rfc-editor.org/rfc/rfc1950.txt
  - Retrieved artifact SHA-256: `8f0475a5c984657bf26277f73df9456c9b97f175084f0c1748f1eb1f0b9b10b9`
  - Learned: zlib framing and checksum requirements
- RFC 1951, DEFLATE Compressed Data Format Specification version 1.3
  - URL: https://www.rfc-editor.org/rfc/rfc1951.txt
  - Retrieved artifact SHA-256: `5ebf4b5b7fe1c3a0c0ab9aa3ac8c0f3853a7dc484905e76e03b0b0f301350009`
  - Learned: DEFLATE format and decoding semantics
- RFC 3339, Date and Time on the Internet: Timestamps
  - URL: https://www.rfc-editor.org/rfc/rfc3339.txt
  - Retrieved artifact SHA-256: `9ab2b8864a85dca73a88f49b0927bc7bc85f596926e4fd1890905777924e700a`
  - Learned: UTC timestamp syntax used at the typed protocol boundary

### NIST cryptographic standards

Terms assessment: public NIST standards used as normative references; their
text is not vendored.

- FIPS PUB 180-4, Secure Hash Standard
  - URL: https://csrc.nist.gov/files/pubs/fips/180-4/final/docs/fips180-4.pdf
  - Retrieved artifact SHA-256: `5b88d70308c95106e713221c7085cbb8e89dc2eb6214d75c885af2f07ffc6b8a`
  - Learned: SHA-256
- FIPS PUB 197, Advanced Encryption Standard, updated 9 May 2023
  - URL: https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf
  - Retrieved artifact SHA-256: `89c6da9e6cb81ffb7c115752b789ff3dc205acb2b13d6a36ff55acc79e87f61e`
  - Learned: AES-128
- NIST SP 800-38A, Recommendation for Block Cipher Modes of Operation
  - URL: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
  - Retrieved artifact SHA-256: `66821162de1e7130c5fb5eedb22140d8d6d013ec51af4550bb095c2a9481a00e`
  - Learned: CBC mode processing

### ZIP format and standard-library processing

Terms assessment: public format documentation and Python standard-library
documentation used as references; neither artifact is vendored.

- PKWARE `.ZIP File Format Specification`, APPNOTE 6.3.10
  - URL: https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
  - Retrieved: 2026-08-08
  - Retrieved artifact SHA-256: `0b993022a7d320a0bf704e6980bea36fafd17a6066ab994db0a0c16278a50cd6`
  - Learned: central-directory metadata, general-purpose encryption flag,
    compression sizes, uncompressed sizes, and external file attributes
- Python 3 `zipfile` documentation
  - URL: https://docs.python.org/3/library/zipfile.html
  - Retrieved: 2026-08-08
  - Retrieved artifact SHA-256: `17990f5ebeafab1311f6d7b0d874a4f3bea6ae9fabfb38fa307ff6abbfa87095`
  - Learned: standard-library archive/member inspection, bounded member reads,
    CRC validation, directory detection, and unsupported/encrypted-member errors

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
