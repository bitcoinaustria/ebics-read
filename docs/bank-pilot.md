# Preparing a read-only bank pilot

EBICS Read is an implementation for a supervised interoperability pilot, not a
production-ready or universally feature-complete EBICS client. There is no
live-bank evidence yet. A bank's agreement to test is the next evidence gate;
the repository's tests cannot substitute for that agreement or a successful
bank transaction.

## What the pilot can exercise

| Area | Implemented boundary |
| --- | --- |
| Protocol | EBICS 3.0/H005; HEV uses H000; no H004 fallback |
| Enrollment | INI, HIA, printable letters, HPB and explicit out-of-band bank-key pinning |
| Certificate profile | Documented self-signed subscriber and bank profiles; bank acceptance must be confirmed |
| Discovery | HPD, HAA, HKD, HTD; account and BTD service information |
| Statements | BTD with bank-supplied BTF parameters; raw (`NONE`) or ZIP containers |
| Delivery | Bounded processing, durable caller-owned state, receipts before document publication |
| Payments | No BTU, payment initiation, direct debit, business uploads, EDS/VEU or raw-request API |

Statement contents are opaque bytes. The integrating application must parse its
agreed format, associate accounts, reconcile periods, and deduplicate imported
payments. The core has no scheduler or accounting engine. Account selection is
not a portable BTD parameter: use bank permissions and the agreed service scope,
then separate returned accounts in the application.

XML/SVC container framing, H004, CA-issued French subscriber profiles, HCA/HCS
renewal and SPR suspension are outside the current implementation. Optional
EBICS transaction recovery synchronization is also absent. Local restart support
does not mean every interrupted bank transaction can be retried: ambiguous
outcomes require operator resolution. Raw and ZIP are container choices, not
restrictions on whether an individual statement document contains XML.

## Information to request from the bank

- A test endpoint or an agreed supervised pilot, H005 support, HostID, PartnerID
  and UserID, and any required SystemID.
- A subscriber with **download-only permissions** for the intended accounts;
  payment and signature authorization must not be granted.
- Acceptance of the documented certificate profile, the INI/HIA activation and
  letter procedure, and both X002/E002 H005 public-key digests through an
  independent trusted channel.
- Exact BTF service, scope, message name/version, variant, format, service option
  and raw/ZIP container for statements; available history, date-range behavior,
  retention and whether a positive receipt affects subsequent retrieval.
- Whether discovery orders are available, plus a contact for key rotation and
  resolving uncertain initialization or receipt outcomes.

Send the repository link and the intended profile, never keys or credentials.
EBICS enrollment includes subscriber key generation and activation; it is not
just obtaining a password. The [example runbook](../examples/README.md) explains
the application-owned adapters and enrollment sequence.

## Acceptance sequence

1. Confirm the protocol, certificate profile, service parameters and read-only
   account permissions with the bank before enrollment.
2. Generate and back up keys in protected storage outside the repository. Execute
   HEV, INI and HIA; retain letters privately and complete the bank's activation.
3. Retrieve HPB candidates and compare both typed digests with the bank's
   independently supplied values. A mismatch blocks the pilot.
4. Discover the enabled services/accounts, then retrieve one agreed statement
   through BTD and verify receipt completion and publication.
5. Privately compare the document's period, balances and entries with the bank's
   reference. Test a fresh retrieval with a new local session ID; a completed
   session ID intentionally returns the original result.
6. Validate application import and duplicate handling before scheduling regular
   downloads. Test interruption/restart with synthetic data first.

Keep only sanitized evidence: date, reviewed commit, protocol/profile, successful
operation names, document format and resolved behavior differences. Do not put
bank XML, identifiers, transaction IDs, certificates, account data or credentials
in issues, chat or CI. Follow the [release gates](interoperability.md) before
changing the project's readiness label.

## Example inquiry (German; draft, not sent)

> Wir entwickeln eine quelloffene, ausschließlich lesende EBICS-Anbindung und
> möchten mit Ihnen einen begleiteten Interoperabilitätstest vereinbaren.
> Ziel ist der Abruf von Kontoinformationen und Kontoauszügen, ohne Zahlungs-,
> Upload- oder Unterschriftsberechtigung. Die Implementierung unterstützt
> EBICS 3.0/H005, INI/HIA/HPB, HPD/HAA/HKD/HTD sowie BTD mit Rohdaten oder ZIP.
> Sie ist noch nicht gegen eine reale Bank validiert.
>
> Können Sie dafür einen Testzugang oder einen eingeschränkten Teilnehmer
> bereitstellen und uns Ihr Zertifikatsprofil, das Aktivierungsverfahren,
> die verfügbaren Kontoauszugsformate samt BTF-Parametern und den unabhängigen
> Bezugsweg für die Bank-Key-Digests nennen?
>
> Repository: https://github.com/bitcoinaustria/ebics-read
