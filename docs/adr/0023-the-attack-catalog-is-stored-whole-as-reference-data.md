---
status: proposed
---

# The ATT&CK catalog is stored whole, as reference data

barbattack will label Vulnerabilities with the ATT&CK Techniques that exploit them, so the Prioritizer can weigh the phase of an attack and Luna can propose MITRE's own Mitigations instead of inventing them. Where a Vulnerability's Techniques come from is a separate decision (ADR 0024). Every source names Techniques by their ATT&CK id, such as `T1190`, so first barbattack needs the catalog those ids point to. This ADR decides what of ATT&CK is kept, how, and how an id is read across ATT&CK versions.

## What is kept

The ATT&CK Feed pulls the whole Enterprise bundle every 12 hours (version 20.1 when this was written, 26,699 objects). The adapter emits only these, and drops the rest (groups, malware, tools, campaigns, detections, `uses` and every other relationship):

| STIX object | ATT&CK term | Kept when | Count in 20.1 |
|---|---|---|---|
| `attack-pattern` | Technique or sub-technique | it has an ATT&CK id (`T…`), revoked and deprecated ones included | 867: 706 current, 149 revoked, 12 deprecated |
| `course-of-action` | Mitigation | its ATT&CK id starts with `M` | 44 |
| `relationship` `mitigates` | how a Mitigation applies to a Technique | always | 1,477 |
| `relationship` `revoked-by` | which Technique replaced a revoked one | its source and target are `attack-pattern` | 149 |

The 224 `course-of-action` objects whose ATT&CK id starts with `T` are an old form of ATT&CK, all deprecated, and are dropped. A `mitigates` relationship carries its own description: the advice for that Mitigation on that Technique, which is what Luna reads.

## An exception to storing only what matches

ADR 0015 keeps a Feed object only when it matches a Customer. The ATT&CK catalog is kept whole instead. It is reference data that a label points into, not a threat that arrives: it is small (about 2,500 rows), it changes a few times a year, and a label arriving for any Technique must find it already stored.

## Tables

| Table | Holds |
|---|---|
| `attack_techniques` | STIX id as key; `attack_id` (`T1190`, `T1059.001`); name; tactics (the `mitre-attack` kill chain phases, such as `initial-access`); `revoked`; `deprecated`; the STIX object as `jsonb`; `modified_at` |
| `attack_mitigations` | STIX id as key; `attack_id` (`M1051`); name; the STIX object as `jsonb`; `modified_at` |
| `attack_relationships` | STIX id as key; type (`mitigates` or `revoked-by`); source and target STIX ids; description; `modified_at` |

- `attack_relationships` has no foreign keys. The Feed hands the bundle over in batches, each its own transaction, and a relationship can arrive before its Technique. Reads join on the STIX ids.
- Nothing is deleted. ATT&CK revokes or deprecates instead of removing, so a Technique a label once named is always there.
- One current version per object (ADR 0010): a row is replaced only by an object with a later `modified`.
- The catalog is public and shared by every Customer, like Vulnerabilities.

## Reading a Technique across versions

A label stores the ATT&CK id its source gave, which may be from an older ATT&CK version than the stored catalog (CTID maps against ATT&CK 16.1, for example). Reading a Technique by that id:

- **Current**: returned as it is.
- **Revoked**: `revoked-by` is followed to the current Technique, for at most 5 steps, since a revoked Technique can be replaced by one that was revoked later. The current one is returned along with the id that was asked for, so a reader can tell that a replacement happened.
- **Deprecated, or revoked with no current replacement**: returned with its `deprecated` or `revoked` mark, never dropped, as a Match Flag keeps an uncertain match (ADR 0015).
- **Unknown id**: not found. The label stays, and a later pull may bring the Technique.

Each Technique is read with its Mitigations and the description of each `mitigates` relationship.

## How it runs

A `HandleATTACK` handler in a new use-case package, `internal/techniques`, plugs into `ingest.Feed.Handle`, as the AWS Feed's does (ADR 0022). Each batch is one transaction.

## Considered Options

- **Store only the Techniques some label names**: rejected. A label would have to wait for the next ATT&CK pull, and a Technique would have to be fetched for every new label.
- **One table for every ATT&CK object**: rejected. Techniques and Mitigations are read by their own columns (`attack_id`, tactics, the revoked and deprecated marks), which a generic table would hide in `jsonb`.
- **Foreign keys from relationships to Techniques and Mitigations**: rejected. Batches arrive in any order, each in its own transaction.
- **Keep detections, groups and software**: rejected for now. Nothing reads them. They are a later decision if the dashboard wants them.
- **Drop revoked and deprecated Techniques**: rejected. A label from an older ATT&CK version would lose its Technique instead of reaching its replacement.

## Consequences

- The ATT&CK adapter emits three more kinds of object. Its tests cover each.
- Three migrations and their queries.
- `GLOSSARY.md` gains **Technique** and **Mitigation**.
- Until ADR 0024 decides where labels come from, the catalog is stored but nothing reads it.
