---
status: proposed
---

# The Business Context is a versioned document the Customer states, and the Drafter only proposes it

The Agents weigh Findings, and soon threat news, with what an Asset says about itself (ADR 0016), but not with what the Customer knows about its business. A **Business Context** is that knowledge: what the Customer does, its sectors, size and revenue, where it operates, the Critical Services it cannot lose, how much each tolerates losing and the Assets that run them, the data it holds, the regulations it follows, its domains, brands, technologies and third parties, its risk appetite and the risks it worries about. A Customer has one, and a Customer Admin edits it in the dashboard. Every User of the Customer reads it. It is the Customer's statement, never imported from a CMDB Source.

## It is one document, and each save is a new version

`business_contexts` stores one row per save: the Customer, a version counted from 1, the `schema` name (`business_context/1`), the document as `jsonb`, who saved it and when. No row is ever updated. A save sends the version it read, and one on any other version fails with `business.ErrStale` (409 `business_context_stale`); the primary key on `(customer_id, version)` catches two saves on the same version. So a Customer Admin never overwrites another's edit without seeing it, and whatever an Agent derives from a Business Context can name the version it read, as a Run names its prompt (ADR 0016).

This departs from ADR 0006 and the Asset columns: its closed sets are string codes inside `jsonb`, not catalog tables. It is read and written whole, never queried field by field, versions must stay readable as they were, and its codes are meant to be compared with threat intelligence, not joined. `internal/business` checks every rule in Go: the codes, the limits on text and lists, and canonical forms.

## Its vocabularies are threat intelligence's own

- **Sectors are STIX 2.1's `industry-sector-ov`**, as written there (`financial-services`, `government-local`), followed by a few industries it leaves out in the same style (`logistics`, `oil-gas`), and **countries are ISO 3166-1 alpha-2** (`MX`), so a Feed's report targeting a sector or a country matches a Customer without a mapping table (ADR 0010).
- **Domains are canonical**: lowercased, without scheme, path or `www.`, since lookalike domains and leaks are matched against them.
- Organization type, employee and revenue ranges (US dollars), data categories, regulations (Mexico's LFPDPPP, CNBV, Banxico and Ley Fintech among them), technology environments, concerns, risk appetite, impact and downtime are closed sets in `internal/business/vocabulary.go`. A blank code or an empty list is "not stated", never a value.
- **Risk appetite is the Customer's, tolerance each Critical Service's.** Appetite is what leadership sets for the whole organization, on the five levels risk frameworks use, from averse to eager. What the Prioritizer can act on is per service, as a business impact analysis states it: how badly losing it hurts (its impact) and how long it can be down (its maximum tolerable downtime). An Asset inherits them from the services that name it, beside the Criticality its CMDB Source gives it.
- A **Critical Service** names its Assets by the name their CMDB Source gives them, which is how a Dossier names an Asset. The name is free text: it is not checked against the inventory and survives an Asset's renaming as stale text.

## It is read three ways

- **As JSON**: `GET /business-context` returns the newest version with `key_fields` and `gaps`, the key fields not stated. `business.Fields` is the `business_context/1` shape, the same stored and served, for code that filters by sector, country, technology or domain, such as matching news to Customers.
- **As Markdown**: `GET /business-context/brief`, or `Context.Brief` in process, renders every field with its label and says "not stated" for each one missing, so a model reading it never takes a gap for an answer. Its ETag is the version.
- **In process**: a use case such as `agents` reads `Tx.BusinessContext` from `postgres`, never through `businesscontext`, which is a use case too. Its text is the Customer's and reaches a model as data, never as instructions.

## The Drafter proposes, a Customer Admin saves

Filling the document by hand is slow, so the **Drafter**, a fourth Agent beside those of ADR 0016, drafts one from the documents a Customer Admin pastes or uploads, up to 10 and 20 MB together: text, Markdown, CSV, JSON, PDFs, which the model reads natively, or Word documents, whose text barbackend extracts. It reads them together in one structured-output call on `claude-opus-5-5` (`DRAFTER_MODEL`), with the documents in the user message and the vocabularies in the schema, placing each fact in its field. Its answer must pass `business.Problems`, or it gets one retry told what was wrong, as the other Agents do. **Nothing it says is saved**: `POST /business-context/draft` returns the draft and its gaps, the dashboard fills the form with it without overwriting what the Customer Admin typed, and only a save stores it. Only a Customer Admin can ask, since each draft is a paid request.

## Where the code goes

This adds layers to ADR 0008:

```
internal/
  businesscontext/  use case: read and save it       -> business, postgres, tenancy
  agents/           gains the Drafter                -> business too
  business/         pure domain: Business Context    -> nothing internal
```

`postgres` and `httpapi` may import `business`, and `httpapi` serves `businesscontext`.

## Consequences

- **The Prioritizer does not read it yet.** Handing the Brief to it, telling it how to weigh it, and having its verifier check what a reason cites is the rest of item 1 of `docs/agents-pending.md`.
- A new field that a reader of `business_context/1` can ignore keeps the schema name; one that changes the meaning of an existing field takes a new name and a reader of both.
- There is no history endpoint yet, though every version is kept.

## Considered Options

- **A row with a column per field and catalog tables per vocabulary (ADR 0006)**: rejected; a dozen join tables for a document read and written whole, and versions would need a copy of each.
- **Free text instead of vocabularies**: rejected for sectors, countries and the closed sets; a model reads free text well, but matching news by sector and country needs codes. Technologies, brands and third parties stay free text, since no closed list covers them.
- **Business context per Asset, as a Declaration**: deferred; a Critical Service naming its Assets says which Assets matter and why, without a field on every Asset.
- **Letting the Drafter save its draft**: rejected; a model's reading of a brochure would silently change what every Agent weighs.
