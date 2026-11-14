---
status: proposed
---

# Information Classification is declared only and not scored, yet

An Asset that holds confidential data is worth more to an attacker than one that serves a public page, and a Customer wants to see which is which while triaging. iTop has no field for it, so this ADR adds Information Classification as a value a Customer Admin declares: Public, Private or Confidential, and Unclassified until declared. It is shown and not scored. How it should move a Score is left to its own design.

## Declaring it

It follows the Exposure Declaration (ADR 0021) in everything but the import and the rescore:

- **Who.** A Customer Admin, gated by `tenancy.User.DeclareAssetValues`. Any User of the Customer sees it.
- **Endpoint.** `PUT /assets/{id}/information-classification` with `{"information_classification": "public" | "private" | "confidential"}` declares; `DELETE` on the same path clears it back to Unclassified.
- **Unclassified cannot be declared.** It is the absence of an answer; clearing is how a User withdraws one.
- **An Inactive Asset cannot be declared** (409), and a Declaration made while Active survives deactivation and can be cleared while Inactive. A Sync never touches it, and it is lost on a CMDB reconnect, as an Exposure Declaration is.
- **Who and when.** `assets` gains `declared_information_classification_id`, `information_classification_declared_by` and `information_classification_declared_at`, all null or all set.
- **The response.** `GET /assets` reports `information_classification` as `{value, declared_by, declared_at}`, with `value` null when Unclassified. Nothing is imported, so there is no `source` or `imported` as Exposure has.
- **Catalog.** `information_classifications` holds Public, Private and Confidential (ADR 0006). Unclassified is `NULL`.

## Not scored

Declaring or clearing it stores no Score and does not notify the Prioritizer. Scoring Model 2, the Data Gaps and the Dossier do not change.

## Considered Options

- **Score it now**, as a fourth Asset multiplier: rejected for now; the weights need their own design, and a new Scoring Model would rescore every Finding for a value no Asset has yet.
- **An `information_classification_undeclared` Data Gap**: rejected with scoring; a Data Gap says a Score is missing an input, and this value is not an input yet.
- **"Internal" instead of "Private"**: rejected; Internal is an Exposure value, and the two would be confused in the same sheet.
- **Import it from an iTop custom field**: rejected; iTop has none by default, and Customers do not record it there today.

## Consequences

- When scoring arrives, every stored Declaration feeds it at once, and Unclassified Assets need a decision of their own.
- Exposure and Information Classification share `DeclareAssetValues`, the `/assets/{id}/...` shape and the audit columns, which the declared Asset Owner is expected to reuse.
