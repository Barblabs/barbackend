---
status: proposed
---

# An Asset's Lifecycle Stage is imported from iTop and scored

An Asset in production carries the Customer's real data and traffic; one in implementation is being built and will carry them soon; one in stock is not running at all. Exposure (ADR 0021) says who can reach an Asset, not whether it is live, so the two are independent: a staging server can be internet-facing. This ADR imports the Lifecycle Stage from the iTop `status` field and adds it to the Score as a third Asset multiplier, in Scoring Model 2.

## Mapping

| iTop `status` | Lifecycle Stage | Multiplier in Scoring Model 2 |
|---|---|---|
| `production` | Production | 1.0 |
| `implementation` | Implementation | 0.8 |
| `stock` | Stock | 0.3 |
| `obsolete` | none: Retired (ADR 0005) | not scored: the Asset is Inactive |
| blank, or any other value | Unknown | 1.0, with the `lifecycle_unknown` Data Gap |

- **Obsolete does not change.** It still marks the Asset Retired, the Sync makes it Inactive and its Findings close with `asset_inactive` (ADR 0005, ADR 0020). A retired Asset has nothing left to protect, so it is not scored low: it is not scored.
- **Implementation is lowered, not ignored.** Damage in production is worse, but an Asset being built is often less hardened, holds copies of real data and shares networks or credentials with production, so 0.8 moves it down the order without hiding it.
- **Stock is scored, not dropped.** A spare server will be deployed some day, and its Findings should be fixed before it is. 0.3 keeps them visible and keeps them below the alerting Bands.
- An unknown value is Unknown, not an error, as an unknown Location is (ADR 0021), and takes the highest multiplier: missing context never makes a Finding look safer (ADR 0009).
- The Lifecycle Stage is only imported. iTop is where it changes, so there is no Declaration.

## Scoring Model 2

`S_f = S × m_criticality × m_exposure × m_lifecycle`. Every other number is Scoring Model 1's. Model 1 is not edited (ADR 0009). New Scores use Model 2, so every open Finding stores one new Score at its next rescoring, since the Model differs, even when the value does not. `finding_scores` gains `lifecycle_multiplier`, which is 1.0 on the Model 1 rows, since Model 1 had no such factor.

## When a Score changes

Moving an Asset from `stock` to `production` in iTop reaches its Scores at the next Sync, as a Location change does (ADR 0021): `AfterSync` rescores every match.

## The Dossier

The Lifecycle Stage goes into each Finding's Dossier (ADR 0016), so an Agent can give it as a reason ("in implementation: fix before it reaches production"). The Agents read the stored Score and never apply the multiplier again.

## Considered Options

- **Give it to the Agents only**: rejected. Alerts fire on a Score Band (ADR 0009), not on the Prioritizer's order, so a stock server with a KEV CVE would alert its Owner although nobody can exploit it today.
- **Implementation at 1.0**: rejected; the team weighs production higher.
- **Stock opens no Findings, as obsolete**: rejected; its CVEs arrive with it when it is deployed.
- **Score obsolete with a low multiplier**: rejected; it would keep Findings open on an Asset its CMDB says no longer exists.

## Consequences

- iTop `status` becomes meaningful to scoring: an Asset left in `implementation` after it went live keeps a lower Score until someone fixes iTop.
- Other CMDB providers must map their own stages, or leave them Unknown.
- The first rescoring after the deploy stores a Model 2 Score for every open Finding.
