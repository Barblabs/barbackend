---
status: proposed
---

# Findings are scored by a versioned, deterministic two-layer model

We score the Finding, not the Vulnerability: the same CVE matters very differently on an internet-facing production server and on an internal lab machine. Threat context (ATT&CK techniques, advisories, news) is not scored in this version: no Feed links a CVE to an ATT&CK technique, so it stays as evidence for people and agents.

A Score is computed in two layers by pure functions, so the same inputs always give the same Score:

1. **Vulnerability**: `S = c1·α + c2·β + c3·γ`, with α = CVSS base score / 10, β = the raw EPSS probability, γ = 1 if the CVE is in the CISA KEV catalog, else 0. Scoring Model 1 uses c = (0.3, 0.3, 0.4). β is the probability, not the percentile, because a percentile only ranks a CVE against all others and moves when they change.
2. **Asset**: `S_f = S × m_criticality × m_exposure`, with Criticality High 1.0, Medium 0.7, Low 0.4 and Exposure Internet-facing 1.0, Internal 0.6. These multipliers are provisional.

Weights, multipliers, the aggregation function and the Data Gap defaults together form a Scoring Model. Scoring Models are immutable and defined in Go, like catalog values (ADR 0006), so a stored Score can always be recomputed. Each Score stores its Scoring Model version, the value of every factor and its Data Gaps. Changing any number means a new Scoring Model, never editing an old one. Like threat matching (ADR 0008), scoring is a pure domain package that imports `inventory`.

## Data Gaps

A Finding always gets a Score. A missing input never lowers it silently: it takes a default and is recorded as a Data Gap.

| Missing input | Default | Data Gap |
|---|---|---|
| CVSS base score | α = 0.7 | `cvss_estimated` |
| EPSS | β = 0 | `epss_pending` |
| KEV catalog older than expected, or never read | γ from the last catalog read (0 if none) | `kev_stale` |
| Criticality is Unknown | m = 1.0 | `criticality_unknown` |
| Exposure is Unknown (not declared) | m = 1.0 | `exposure_undeclared` |

A KEV catalog that failed to download is not the same as a CVE that is not listed. Unknown Criticality and Exposure take the highest multiplier, so missing context never makes a Finding look safer than it is.

CVSS is taken from the first source that has it: the NVD Primary score, then the CNA's Secondary score, then cve.org (including CISA Vulnrichment). Only the base score is stored with the Score, not its source or CVSS version, so the Vulnerability's data stays the single source of truth for them. Since 2026-04-15, NVD leaves most new CVEs without a CVSS score unless the CNA provides one, so `cvss_estimated` is expected to be common.

## Considered Options

- **The professor's `c1^α + c2^β + c3^γ`**: still being clarified. Read literally, it inverts the ranking and peaks at 3: CVSS 9.8, EPSS 0.90 and KEV scores 1.046, while CVSS 5, EPSS 0.002 and no KEV scores 2.545. Read as `α^c1 · β^c2 · γ^c3`, any zero factor collapses the Score, so CVSS 9.8 outside KEV scores 0. Read as `α^c1 + β^c2 + γ^c3`, it ranks correctly but compresses differences, and with weights below 1 a larger weight makes its factor matter *less* (0.5^0.3 = 0.81 but 0.5^0.4 = 0.76). Because the aggregation is part of the Scoring Model, any of these can be added as a new version and compared on the same Findings.
- **EPSS saturated as `min(EPSS / 0.10, 1)`**: open. It would stop the raw probability from flattening most CVEs near 0.

## Consequences

- Exposure is only declared (ADR 0004), and Declarations are not implemented yet, so today every Score has `exposure_undeclared` and an exposure multiplier of 1.0.
- Open Findings are rescored daily, because KEV and EPSS change, and each Score is kept as history. Closed Findings are not rescored.
- The Asset Owner, or the Security Team if there is none, is only alerted when a Finding changes Score Band or its Vulnerability enters the KEV catalog, not on every rescoring. Band thresholds are not decided yet.
