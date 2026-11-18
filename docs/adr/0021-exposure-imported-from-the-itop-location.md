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

A Declaration rescores at once: declaring or clearing it rescores the open Findings of that Asset, as described below.

## Declaring Exposure

A Customer Admin declares an Asset's Exposure, or clears the Declaration to fall back to the imported value. Any User of the Customer sees it. A wrong Declaration of Internal lowers every Score on the Asset by the 0.6 multiplier with no Data Gap left to warn anyone, so stating it is a privileged act, as stating an Area Owner is (ADR 0018). `tenancy.User.DeclareAssetValues` gates it, apart from `ManageAreas`, so the declared Asset Owner can reuse it later.

- **Endpoint.** `PUT /assets/{id}/exposure` with `{"exposure": "internet_facing" | "internal"}` declares; `DELETE /assets/{id}/exposure` clears. `GET /assets` gains each Asset's `id`, the handle the HTTP API uses, as `customer_areas.id` is for Areas. An Asset of another Customer is not found.
- **Only Internet-facing and Internal can be declared.** Unknown is the absence of an answer, not a statement; clearing the Declaration is how a User withdraws one. `inventory.Asset.DeclareExposure` already rejects Unknown, and the Exposure catalog does not change.
- **An Inactive Asset cannot be declared** (409): barbattack does not monitor it. A Sync never touches a Declaration, so one made while the Asset was Active survives its deactivation and reactivation.
- **A Declaration belongs to its Asset.** After a disconnect and a reconnect, the new CMDB Source has new Assets and nothing declared, as its Areas have no Area Owner (ADR 0018). The old Assets keep their Declarations as history.
- **Who and when.** `assets` gains `exposure_declared_by` (a User) and `exposure_declared_at`, set on declaring and cleared with the Declaration. A User who reads Internal on a database needs to know whether the CMDB or a person said so, and which person.
- **The response.** `GET /assets` reports `exposure` as `{value, source, imported, declared_by, declared_at}`: the effective value, whether it is `imported` or `declared`, the imported value beneath a Declaration, and who declared it and when.

### Rescoring

After the Declaration commits, the use case rescores every open Finding of the Asset from its stored Vulnerability and the Asset's effective Criticality and Exposure, storing a Score only when it changed, and then notifies the Prioritizer as a Feed batch does. The rescore runs in its own transaction and reads the effective Exposure afresh, so two Declarations close together end on the Scores of the last one. If it fails, the request fails, but the Declaration stands, and the next Sync rescores every Active Asset anyway.

The use case lives in `internal/assets`, which does not depend on `internal/findings` (ADR 0008). It takes a narrow rescoring interface that `findings.Service` satisfies, wired in `cmd/barbackend`, so the rule "a Declaration rescores its Asset" sits in the use case and the scoring stays in `findings`.

## Considered Options

- **Keep Exposure declared only**: rejected; Customers already record it in iTop, and every Asset would score as Unknown until someone declares it.
- **A third value for cloud**: rejected; being in the cloud does not say whether an Asset is reachable from the internet, and a new value would need a new Scoring Model.
- **A VirtualMachine takes its host's Location**, through its Hypervisor's Server: rejected for now; a VM on a Farm has no single Server, and an internal host can run a VM published to the internet.
- **Any User of the Customer declares**: rejected; whoever triages a Finding could close its Data Gap, but a Declaration of Internal lowers Scores silently, and the audit columns would only say afterwards who did it.
- **A Declaration waits for the next Sync or KEV or EPSS pull**, as first written here: rejected; there is no scheduled Sync, so a User would declare and see the Data Gap and the Score unchanged for an unbounded time.
- **Unknown can be declared**: rejected; it would let a User override a known imported value with no information, and it equals having no Declaration only when nothing is imported.
- **The Asset addressed by its Source Reference** (`/assets/{source_id}/{record_id}/exposure`): rejected; a record id is the provider's free text, and Areas already set the surrogate id as the HTTP handle.

## Consequences

- iTop Locations become meaningful to scoring: renaming the `exposed` Location in iTop turns its Assets Unknown at the next Sync.
- The names `exposed` and `not exposed` are fixed in the iTop adapter. Customers who name their Locations differently need a per-CMDB-Source mapping, which this ADR does not add.
- Virtual Machines always score with the Unknown multiplier unless declared.
- Declarations are lost on a reconnect, so a Customer that reconnects its CMDB Source declares its Virtual Machines again.
- The declared Asset Owner, which has storage but no write path, is left for its own design; it is expected to reuse `DeclareAssetValues`, the `/assets/{id}/...` shape and the audit columns.
