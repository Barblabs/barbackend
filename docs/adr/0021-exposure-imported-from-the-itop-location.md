---
status: proposed
---

# Exposure is imported from the iTop Location and can be declared over it

ADR 0001 and ADR 0004 made Exposure declared only, because iTop has no field for it. Customers can record it in iTop anyway: they keep two Locations, `exposed` and `not exposed`, and set one on every physical device. This ADR imports Exposure from that Location and keeps the Declaration on top of it, as Asset Owner already works (ADR 0004). It supersedes the Exposure parts of ADR 0001 and ADR 0004.

## Mapping

| iTop `location_name` | Exposure | Multiplier in Scoring Model 1 |
|---|---|---|
| `exposed` | Internet-facing | 1.0 |
| `not exposed` | Internal | 0.6 |
| blank, or any other name | Unknown | 1.0, with the `exposure_undeclared` Data Gap |

The names are compared after trimming and lowercasing. An unknown Location name is Unknown, not an error: Location is free text, and one misnamed Location must not fail the Sync of every CI on it, as an unknown `business_criticity` does.

- Only Server, PC and NetworkDevice are asked for `location_name`. VirtualMachine has no Location in iTop, and the adapter fails a Sync when a class lacks a requested field, so its Exposure stays Unknown until declared.
- The effective Exposure is the Declaration when there is one, otherwise the imported value. The `assets` row keeps both, `declared_exposure_id` and `imported_exposure_id`, and every query that feeds scoring reads the effective one.
- The Exposure catalog and Scoring Model 1 do not change: Internet-facing and Internal already exist, with their multipliers.

## When a Score changes

A Location changed in iTop reaches the Scores at the next Sync. `AfterSync` (ADR 0020) matches every Active Asset again and rescores each match, and a new Score is stored only when it differs from the latest one, so moving a server from `not exposed` to `exposed` stores one new Score per open Finding, with the exposure multiplier going from 0.6 to 1.0. There is no scheduled Sync: one runs when the CMDB Source is connected and when a User asks for it.

A Declaration does not rescore by itself; its Findings are rescored at the next Sync or KEV or EPSS pull. This gap predates this ADR.

## Considered Options

- **Keep Exposure declared only**: rejected; Customers already record it in iTop, and every Asset would score as Unknown until someone declares it.
- **A third value for cloud**: rejected; being in the cloud does not say whether an Asset is reachable from the internet, and a new value would need a new Scoring Model.
- **A VirtualMachine takes its host's Location**, through its Hypervisor's Server: rejected for now; a VM on a Farm has no single Server, and an internal host can run a VM published to the internet.

## Consequences

- iTop Locations become meaningful to scoring: renaming the `exposed` Location in iTop turns its Assets Unknown at the next Sync.
- The names `exposed` and `not exposed` are fixed in the iTop adapter. Customers who name their Locations differently need a per-CMDB-Source mapping, which this ADR does not add.
- Virtual Machines always score with the Unknown multiplier unless declared.
