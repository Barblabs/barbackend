---
status: proposed
---

# Scoring Model 4 scores Highly Confidential data

Information Classification has three declared values, Public, Private and Confidential (ADR 0031), and Scoring Model 3 scores them as 0.5 / 0.75 / 1.0, taking the higher of them and Criticality as the impact (ADR 0032). A Customer that handles regulated or secret data, such as health records, card data or credentials, needs a step above Confidential to tell it apart from merely internal sensitive data, as four-level schemes do (Public, Internal, Confidential, Restricted). This ADR adds **Highly Confidential** as a fourth value and Scoring Model 4 to score it.

## The value

- **Catalog.** `information_classifications` gains `(4, 'Highly Confidential')` (ADR 0006); the API code is `highly_confidential`.
- **Declared as the others.** A Customer Admin declares it with `PUT /assets/{id}/information-classification`, under the rules of ADR 0031. It goes into the Dossier and into `GET /prioritizations/{id}` as the others do (ADR 0032).

## Scoring Model 4

Model 4 is Model 3 with one change: the Information Classification multipliers.

| Information Classification | Model 3 | Model 4 |
|---|---|---|
| Highly Confidential | — | **1.0** |
| Confidential | 1.0 | **0.9** |
| Private | 0.75 | 0.75 |
| Public | 0.5 | 0.5 |
| Unclassified | does not count | unchanged |

Everything else is Model 3's: layer 1, Criticality, Exposure, Lifecycle Stage, the impact as `max(m_criticality, m_classification)`, the Data Gaps and the Score Bands.

- **Confidential moves down rather than Highly Confidential above 1.0.** The Score is a number from 0 to 1 and every multiplier lowers it or leaves it, which the `information_classification_multiplier` column checks (`<= 1`). A multiplier above 1 would need the Score capped, would let an Asset count for more than a High one, and would bend the Bands.
- **0.9 moves the fewest Scores.** Private and Public keep their values, which match Criticality's Medium and Low, so an Asset declared Private still counts as a Medium one. Only Confidential moves, by 10%, and only where Criticality is below High, since a High Asset already counts as 1.0. A larger gap (0.85) would drop more Confidential Findings from Critical to High just because a value was added above them.
- **Highly Confidential raises a Score only when Criticality is not High.** That is the high-water mark of ADR 0032: an Asset is worth 1.0 if the business depends on it or if it holds the most sensitive data, and the two do not add up.

Model 3 is not edited and does not score Highly Confidential: changing any number means a new Scoring Model (ADR 0009).

## Examples

| Finding | Model 3 | Model 4 | Band |
|---|---|---|---|
| CVSS 8.8, EPSS 50%, KEV; Low, Highly Confidential, Internal, Production | — | 0.62 | High |
| The same, Confidential | 0.62 | 0.55 | High |
| CVSS 7.5, KEV; Low, Confidential, Internet-facing, Production | 0.75 | 0.68 | Critical → High |
| The same, Highly Confidential | — | 0.75 | Critical |
| CVSS 7.5, EPSS 1%; Medium, Confidential, Internal, Production | 0.29 | 0.26 | Medium |
| CVSS 9.8, EPSS 2%; High, Confidential, Internet-facing, Production | 0.59 | 0.59 | High |

## Switching to it

The backend scores with Model 4 from its deploy. At the next rescore (each Sync rescores every match, ADR 0032), every open Finding stores a Model 4 Score, since a new row is stored whenever the Model differs (ADR 0020). Its value is Model 3's except on Confidential Assets whose Criticality is below High. The Prioritizer places a Finding again only when its Score moved by 0.1 or more or its Band changed (ADR 0026, ADR 0032), so the switch places again only the Confidential Findings that crossed a Band, not the whole order.

## Considered Options

- **Edit Model 3**: rejected; stored Model 3 Scores would mean two scales and could no longer be recomputed (ADR 0009).
- **Highly Confidential at 1.0 and Confidential kept at 1.0**: rejected; the new value would score exactly as Confidential.
- **A multiplier above 1 for Highly Confidential, with the Score capped at 1**: rejected, for the reasons above.
- **Even steps, 1.0 / 0.83 / 0.67 / 0.5**: rejected; it moves Private and Public too, and breaks their match with Criticality's Medium and Low.

## Consequences

- Every open Finding gets one new Score row at the switch, most with the value it had.
- Some Findings on Confidential Assets of Medium or Low Criticality move down, a few from Critical to High.
- The dashboard adds Highly Confidential to the classification selector and the Asset filter.
