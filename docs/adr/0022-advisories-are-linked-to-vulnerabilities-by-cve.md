---
status: proposed
---

# Advisories are linked to the Vulnerabilities they name, by CVE

The AWS Security Bulletins Feed emits one STIX `report` per bulletin, and only for bulletins that name at least one CVE: its `object_refs` are the STIX ids of those Vulnerabilities (ADR 0010). Nothing reads them yet. This ADR decides which of them barbattack keeps, what it ties them to, and who reads them. It is the first part of threat filtering; ADR 0023 covers ATT&CK.

An Advisory says something about a Vulnerability, not about a Customer: the same bulletin is true for every Asset the Vulnerability affects. So it is tied to the Vulnerability, and reaches each Finding through it.

## What is kept

- An Advisory is stored only when at least one CVE it names is in `vulnerabilities`, that is, when that Vulnerability has opened a Finding (ADR 0015, ADR 0020). It is linked to those CVEs only; a CVE it names that is not stored is ignored.
- An Advisory that names no stored CVE is discarded, as an unmatched NVD object is. This covers old CVEs, which are out of scope (ADR 0015), and CVEs NVD has not published yet. There is no backfill and no queue. The RSS Feed keeps recent bulletins for a while and is pulled every 6 hours, so a bulletin that arrives before NVD stores its CVE is linked by a later pull while it is still in the Feed, and lost after that.
- A bulletin published again keeps its STIX id, which comes from its `guid` (ADR 0010). Its row is replaced with the new object and new links are added. A link is never removed, even when the new text no longer names that CVE, so an Advisory the dashboard has shown does not silently disappear.

## Tables

| Table | Holds |
|---|---|
| `advisories` | One row per Advisory: the STIX id as key, the Feed name (`aws`), `published_at`, the STIX `report` as `jsonb`, `modified_at`, `stored_at` |
| `vulnerability_advisories` | `(cve_id, advisory_id)` as key, foreign keys to `vulnerabilities (cve_id)` and `advisories (id)`, `linked_at` |

Advisories are shared by every Customer, like Vulnerabilities: they are public (TLP:CLEAR). A Customer sees an Advisory only through one of its Findings, so tenancy is enforced where it already is, on Findings.

The Findings of a Vulnerability get its Advisories by a join on `cve_id`. A Finding opened later for the same CVE gets the Advisories already linked, with nothing to copy.

## Who reads them

- **The dashboard** shows a Finding's Advisories: title, publication date, link, Feed. Text from a Feed is shown as plain text (GLOSSARY: Feed).
- **The Prioritizer** gets them in each Dossier as untrusted data beside the Finding (ADR 0016): title, publication date and Feed, never as instructions. How it weighs them is the Agents' decision; the `docs/agents-pending.md` item that hands stored Findings to the Agents adds them.
- **The Score does not change.** No Scoring Model reads Advisories (ADR 0009).

## How it runs

A `HandleAWS` handler plugs into `ingest.Feed.Handle`, as `HandleNVD`, `HandleKEV` and `HandleEPSS` do (ADR 0020). For each batch it looks up which `object_refs` are stored Vulnerabilities, in one query, and stores the matched Advisories and their links in one transaction.

## Out of scope

- **Threats that reach an Asset without a CVE**, such as indicators of compromise matched to an Asset's address, or advisories that name a Product but no CVE: no Feed gives them today. The AWS adapter already drops bulletins without a CVE.
- **News about attacks on a Customer's industry**: a separate Feed, built by the Agents' owner, that weighs news against the Customer's Business Context.
- **Alerts**: whether a new Advisory on an open Finding notifies anyone, for example on Slack, is not decided here.

## Considered Options

- **Link an Advisory to each Finding**: rejected. One bulletin would be copied into every Finding of every Customer it touches. A Finding opened later would need its own backfill, and every Advisory row would be tenant data when the content is public.
- **Store every bulletin on receipt**: rejected. It breaks the rule that Feed objects are kept only when they match (ADR 0015), for bulletins about Products no Customer has.
- **Keep unmatched bulletins and link them when their CVE is stored**: rejected for now. It is a queue that never empties, for a case the team ruled out of scope. The RSS window already gives a few days of retry.
- **Store the Advisory inside the Vulnerability's `jsonb`**, as another extension: rejected. One bulletin names several CVEs, so its text would be copied into each, and replacing it would mean editing every one.
- **Let the Advisory change the Score**: rejected. It would be a new Scoring Model (ADR 0009) on data that says little that NVD, KEV and EPSS do not already measure. The Prioritizer weighs it instead.

## Consequences

- Two migrations and their queries. `vulnerability_advisories` references `vulnerabilities`, which is never deleted (ADR 0020), so no link is orphaned.
- `GLOSSARY.md` gains **Advisory**: a notice a Feed publishes about one or more Vulnerabilities, such as an AWS Security Bulletin.
- The Dossier gains a list of Advisories, which changes what the Prioritizer reads. This has to be agreed with the Agents' owner before the Dossier changes; `docs/agents-pending.md` §6 proposes how.
- A bulletin whose CVE NVD publishes after the bulletin leaves the RSS Feed is never linked. This gap is accepted.
