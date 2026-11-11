# What the Agents still lack

The Prioritizer, Luna and the Analista work as ADR 0016 describes, and the Drafter as ADR 0017 does, but only on what they are handed today, and none has answered with a real model yet. The Reader and the Editor exist only in ADR 0018. This is what is missing, most important first. Each item is ready to become an issue.

## 1. Business context in the Prioritizer's criterion

The Prioritizer orders a Customer's open Findings by weighing each Score with what the Finding's Asset means to the business. Today all it knows of that is the Asset itself: its Criticality, its Exposure, its kind, its name and the role of its Software Components. What a Customer knows and barbattack does not store never reaches it: that an Asset runs payments or payroll, holds personal or card data, serves customers, falls under a regulation, or matters most at month's end. So two Assets with the same Criticality and Exposure weigh the same, even when one is the payments server. Until this exists, the only way a User can correct the order is Feedback (`should_be_earlier`, `should_be_later`), which changes nothing the Prioritizer reads.

- ~~**Decide what business context is**~~ and ~~**store and serve it**~~: done by ADR 0017. A Customer Admin states the Customer's Business Context in the dashboard, or has the Drafter draft it from a document, and each Critical Service names the Assets that run it. `Tx.BusinessContext` reads the newest version and `Context.Brief` renders it.
- **Hand it to the Prioritizer**: put the Brief, or the `business_context/1` JSON, in its user message as data beside the Findings, record its version on the Prioritization, tell the Prioritizer how to weigh it (an Asset that runs a Critical Service and that service's impact and maximum tolerable downtime, the data and regulations it falls under, the Customer's Risk Appetite and constraints), and have the verifier check that a reason citing it cites what the Customer said.
- **Use Feedback**: decide whether `should_be_earlier` and `should_be_later` on a Finding become context for the next Prioritization of the same Asset.
- **Decide whether the Score weighs any of it**, which would be a new Scoring Model (ADR 0009), or only the Prioritizer does.

Done when the Prioritizer's prompt and verifier use the Business Context with tests, and a Prioritization names the version it read.

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

## 6. News Items reach the Security Team

ADR 0018 is not built: no News Item is stored, the AWS Feed's reports are pulled and dropped, and a report that names no CVE is skipped.

- **Store News Items**: a migration in the shape ADR 0010 intends, with the Feed, published date and CVE IDs extracted; `ingest` stores what news Feeds emit through `Feed.Handle`; `aws` stops skipping items that name no CVE and refers them to the barbattack `identity`.
- **`internal/feeds/rss`**: one adapter configured per text Feed (name, URL, interval, language), with the Feeds of ADR 0018 registered and `aws` as one of them.
- **`internal/feeds/ransomwarelive`**: leak-site victims as `identity` objects with `sectors` and `victim/1`, and the table that maps its sector names to `business.Sectors()`. Check its terms of use and rate limits first.
- **`internal/news`**: the Relevance rules (Named, Finding, Footprint, Peer), tested on fixed Business Contexts and Assets. With ransomware.live alone, Peer relevance works without a model.
- **The Reader**: its prompt, schema and verifier, a loop in `serve` that reads stored News Items it has not read, and its reading stored with its Run.
- **The Editor and the News Digest**: one per Customer and day with news, stored with the Business Context version it read; `GET /news-digests` and `GET /news-digests/{id}`; the dashboard renders it as plain text with the labels code writes.
- **The Dossier gains News Items** that name its Vulnerability, which needs stored Findings (item 2) for Finding relevance.
- **Named notices on Slack**: one `slack_deliveries` row of a news `kind` to the Security Team channel per Named News Item, once #96 and #105 exist.

Done when a Customer with a stated sector gets a stored News Digest whose Peer items come from ransomware.live and the Reader, each labeled as context, with tests.
