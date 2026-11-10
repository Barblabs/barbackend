# What the Agents still lack

The Prioritizer, Luna and the Analista work as ADR 0016 describes, and the Drafter as ADR 0017 does, but only on what they are handed today, and none has answered with a real model yet. This is what is missing, most important first. Each item is ready to become an issue.

## 1. Business context in the Prioritizer's criterion

The Prioritizer orders a Customer's open Findings by weighing each Score with what the Finding's Asset means to the business. Today all it knows of that is the Asset itself: its Criticality, its Exposure, its kind, its name and the role of its Software Components. What a Customer knows and barbattack does not store never reaches it: that an Asset runs payments or payroll, holds personal or card data, serves customers, falls under a regulation, or matters most at month's end. So two Assets with the same Criticality and Exposure weigh the same, even when one is the payments server. Until this exists, the only way a User can correct the order is Feedback (`should_be_earlier`, `should_be_later`), which changes nothing the Prioritizer reads.

- ~~**Decide what business context is**~~ and ~~**store and serve it**~~: done by ADR 0017. A Customer Admin states the Customer's Business Context in the dashboard, or has the Drafter draft it from a document, and each Critical Service names the Assets that run it. `Tx.BusinessContext` reads the newest version and `Context.Brief` renders it.
- **Hand it to the Prioritizer**: put the Brief, or the `business_context/1` JSON, in its user message as data beside the Findings, record its version on the Prioritization, tell the Prioritizer how to weigh it (an Asset that runs a Critical Service and that service's impact and maximum tolerable downtime, the data and regulations it falls under, the Customer's Risk Appetite and constraints), and have the verifier check that a reason citing it cites what the Customer said.
- **Use Feedback**: decide whether `should_be_earlier` and `should_be_later` on a Finding become context for the next Prioritization of the same Asset.
- **Decide whether the Score weighs any of it**, which would be a new Scoring Model (ADR 0009), or only the Prioritizer does.

Done when the Prioritizer's prompt and verifier use the Business Context with tests, and a Prioritization names the version it read.

## 2. The Findings pipeline hands the Agents its Findings

The Findings pipeline now stores its Findings and their Scores (ADR 0020), but the Agents do not read them yet: a Prioritization is still made from a file, where `agent finding` builds a Dossier from the live Feeds, `agent prioritize` stores the Prioritization of a list of them, and a Finding is an id nothing references.

**The Score is the pipeline's.** A Dossier carries the latest stored Score of its Finding, never one computed for it (ADR 0009, ADR 0016). The Score that `assessment.NewDossier` computes is not used once this is done.

What the pipeline already gives, in `internal/postgres` (`findings.go`, `vulnerabilities.go`):

| Dossier field | Where it comes from |
|---|---|
| `finding` | `findings.id`, a UUID that never changes, even when the Finding is closed and reopened |
| `cve`, `description`, `kev`, `epss`, `nvd` | `Tx.Vulnerability(cve)`: the stored STIX object, with the `nvd/1`, `kev/1` and `epss/1` extensions the Feeds set |
| `asset`, `component` | the Finding's Asset, by `cmdb_source_id` and `record_id`, and its `component_name` and `component_version` |
| `score` | `Tx.LatestScore(id)`: the Scoring Model, value, every factor and the Data Gaps, by the same names a Dossier uses |

What is left to do:

- **Read a Customer's open Findings**: a query for the open Findings (`closed_at IS NULL`) of every CMDB Source of a Customer, with what the table above names, in one round trip rather than one query per Finding.
- **Build a Dossier from a stored Finding**: a constructor in `assessment` that takes the stored Score as it is, instead of `NewDossier` computing one. `UnavailableFeeds` follows from the Score's Data Gaps: `kev_stale` means KEV could not be read.
- **The pipeline calls `agents.Service.Prioritize(ctx, customer, dossiers)`** with those Dossiers. A Prioritization holds at most 100 Findings: decide what happens above that, for example the 100 highest Scores.
- **Decide when it runs**: after each pipeline run, only when the open Findings changed, or on a schedule. Each run is one model request.
- **Store each Finding's place in a Prioritization**: a `prioritization_findings` table, `(prioritization_id, finding_id)` with `finding_id` a foreign key to `findings (id)`, holding the Finding's Priority Group position and its rank by Score alone (`Prioritization.GroupOf`, `ScoreRanks`). The dashboard then asks in SQL which group a Finding is in, or how many Findings of group 1 are closed, without reading `content`. `action_plans` and `prioritization_feedback` reference it by a composite foreign key, which replaces their unreferenced `finding_id` text and the jsonb containment of item 5. The order itself never goes in `findings`: it is a recommendation of one moment, while a Finding and its Score are facts kept as history.
- **Remove the stand-in**: `agent finding`, `assessment.NewDossier`'s scoring and their Feed lookups leave, or move to a use case if still useful.
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
- **One home for "a Finding is in a Prioritization"**: the `prioritization_findings` table of item 2, instead of the jsonb containment in `PrioritizationHolds`, which ties SQL to the JSON shape of `agents.Prioritization`.
- **Rename `internal/assessment`**, which is no longer a domain term (for example to `internal/dossier`), updating ADR 0008, ADR 0016 and depguard.
- **`Crew` holds the Analista's client and model**: move them to `Service`, since the Crew is the Prioritizer and Luna.
- **`agent finding` keeps use-case logic in `cmd`**, which ADR 0008 keeps to wiring, and reads the three Feeds one after another.
- **Build test Dossiers literally** in `internal/agents`, so its depguard rule can drop `stixext`.
