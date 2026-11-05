# What the Agents still lack

The Prioritizer, Luna and the Analista work as ADR 0016 describes, but only on what they are handed today, and none has answered with a real model yet. This is what is missing, most important first. Each item is ready to become an issue.

## 1. Business context in the Prioritizer's criterion

The Prioritizer orders a Customer's open Findings by weighing each Score with what the Finding's Asset means to the business. Today all it knows of that is the Asset itself: its Criticality, its Exposure, its kind, its name and the role of its Software Components. What a Customer knows and barbattack does not store never reaches it: that an Asset runs payments or payroll, holds personal or card data, serves customers, falls under a regulation, or matters most at month's end. So two Assets with the same Criticality and Exposure weigh the same, even when one is the payments server. Until this exists, the only way a User can correct the order is Feedback (`should_be_earlier`, `should_be_later`), which changes nothing the Prioritizer reads.

- **Decide what business context is**: what a Customer can say about an Asset, and maybe about itself (its industry, its critical services), as a closed vocabulary or free text, and who enters it: a Customer Admin in the portal, the CMDB Source, or both. Free text from a Customer reaches a model, so the Dossier carries it as data, like Feed text (ADR 0010).
- **Store and serve it** with the Asset, as a Declaration or as an imported field (ADR 0002).
- **Hand it to the Prioritizer**: add it to the Dossier and its Brief, tell the Prioritizer how to weigh it, and have the verifier check that a reason citing it cites what the Customer said.
- **Use Feedback**: decide whether `should_be_earlier` and `should_be_later` on a Finding become context for the next Prioritization of the same Asset.
- **Decide whether the Score weighs any of it**, which would be a new Scoring Model (ADR 0009), or only the Prioritizer does.

Done when an ADR decides the above, a Customer can record the context of an Asset, it reaches that Asset's Dossiers, the Prioritizer's prompt and verifier use it with tests, and GLOSSARY.md defines the term.

## 2. The Findings pipeline hands the Agents its Findings

Until the pipeline exists, a Prioritization is made from a file: `agent finding` builds a Dossier from the live Feeds, `agent prioritize` stores the Prioritization of a list of them, and a Finding is an id nothing references.

- **The pipeline calls `agents.Service.Prioritize(ctx, customer, dossiers)`** with the Customer's open Findings, each built with `assessment.NewDossier` from the Feed records and the Score it already has. A Prioritization holds at most 100 Findings: decide what happens above that.
- **Decide when it runs**: after each pipeline run, only when the open Findings changed, or on a schedule. Each run is one model request.
- **Reference stored Findings**: `action_plans.finding_id` and `prioritization_feedback.finding_id` become foreign keys to Findings, in a new migration.
- **Remove the stand-in**: `agent finding` and its Feed lookups leave `cmd`, or move to a use case if still useful.
- The dashboard shows a Prioritization from `GET /prioritizations/{id}` and renders all Agent text as plain text. Slack (#96) can send its order and reasons.

## 3. A run against Anthropic's API, and an evaluation

Every test runs against a fake Messages API (`claudetest`).

- **Run them**: `agent run --findings docs/examples/findings.json --plans` with `ANTHROPIC_API_KEY`, and record each Agent's status, its violations, the latency, and the tokens and cost of a Prioritization and of an Action Plan.
- **Watch for refusals**: Claude Haiku 5.5 has no server-side fallback, and vulnerability text is close to its cybersecurity classifiers. If an Agent refuses or keeps failing verification, move it to `claude-sonnet-5-5` with `PRIORITIZER_MODEL` or `LUNA_MODEL` and record why.
- **Build a small evaluation**: a few lists of Findings whose order and groups the team agrees on, to compare runs and models. The order can differ between runs; the Score cannot.
- **Talk with the Analista** over HTTP in a real conversation that reads a Prioritization and records Feedback.

## 4. A spending limit per Customer

Every Prioritization, Action Plan and Analista turn is a paid model request, and any signed-in User of a Customer can ask for Action Plans and talk with the Analista without limit. Decide a limit per Customer (requests or tokens per day), enforce it in the `agents` use case before calling the model, answer 429 with a stable code when it is reached, and record usage per Customer so the portal can show it.

## 5. Simpler code, from the review

The review of the Agents found structural changes that were left out to keep the change reviewable:

- **`Run.Status`**: only verified runs are stored, so `Crew.Prioritize` and `Crew.Plan` can return `(Run[T], error)`, with `ErrRefused`, `ErrRejected` (wrapping the violations) or `ErrUnavailable`, and `Run.Output` can stop being a pointer. That removes `Status`, `failure()` and every nil check, and splits stored content from the read model that carries Plans and Feedback.
- **One home for "a Finding is in a Prioritization"**: a `prioritization_findings` table with composite foreign keys from `action_plans` and `prioritization_feedback`, instead of the jsonb containment in `PrioritizationHolds`, which ties SQL to the JSON shape of `agents.Prioritization`.
- **Rename `internal/assessment`**, which is no longer a domain term (for example to `internal/dossier`), updating ADR 0008, ADR 0016 and depguard.
- **`Crew` holds the Analista's client and model**: move them to `Service`, since the Crew is the Prioritizer and Luna.
- **`agent finding` keeps use-case logic in `cmd`**, which ADR 0008 keeps to wiring, and reads the three Feeds one after another.
- **Build test Dossiers literally** in `internal/agents`, so its depguard rule can drop `stixext`.
