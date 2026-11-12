# What the Agents still lack

The Prioritizer, Luna and the Analista work as ADR 0016 describes, and the Drafter as ADR 0017 does. The Prioritizer keeps one lasting order per Customer from the stored Findings, weighing the Business Context and the threats of each Dossier (ADR 0026), but none has answered with a real model yet. This is what is missing, most important first. Each item is ready to become an issue.

## 1. A run against Anthropic's API, and an evaluation

Every test runs against a fake Messages API (`claudetest`).

- **Run them**: `agent run --findings docs/examples/findings.json --plans` with `ANTHROPIC_API_KEY`, then `agent prioritize --as <email>` on a Customer with stored Findings and a Business Context, and record each Agent's status, its violations, the latency, and the tokens and cost of a round and of an Action Plan.
- **Watch for refusals**: Claude Haiku 5.5 has no server-side fallback, and vulnerability text is close to its cybersecurity classifiers. If an Agent refuses or keeps failing verification, move it to `claude-sonnet-5-5` with `PRIORITIZER_MODEL` or `LUNA_MODEL` and record why.
- **Build a small evaluation**: a few lists of Findings whose order and groups the team agrees on, and rounds that place new Findings in an order that stands, to compare runs and models. The order can differ between runs; the Score cannot.
- **Tune what places a Finding again and what a round shows**: `assessment.ScoreShift` (0.1), `ShownPerGroup` (3), `MaxShownReason` (300) and the waits of `serve` (2 minutes quiet, 15 at most) are first guesses; measure how many rounds a day a real Customer costs and how large its requests are.
- **Decide whether the Analista's Feedback on the order may count**: it is left out of rounds because text a Feed wrote can steer a conversation (ADR 0026), so a User who tells the Analista a Finding should go earlier must also say so in the dashboard.
- **Talk with the Analista** over HTTP in a real conversation that reads a Prioritization and records Feedback.

## 2. A spending limit per Customer

Every round, Action Plan and Analista turn is a paid model request. Rounds run on their own whenever a Customer's Findings change (ADR 0026), and any signed-in User of a Customer can ask for Action Plans and talk with the Analista without limit. Decide a limit per Customer (requests or tokens per day), enforce it in the `agents` use case before calling the model, answer 429 with a stable code when it is reached, and record usage per Customer so the portal can show it. A round over the limit should wait for the next day, not drop the Findings it would place.

## 3. The dashboard

`GET /prioritizations/{id}` now answers, beside what it did, `previous_id`, `business_context_version`, each group's `context_evidence`, each Finding's `placed_at` and `closed_at`, and each Action Plan's `attack_mitigations`.

- **Show the newest Prioritization as the order to follow**, with its closed Findings marked or hidden, and which Findings it placed: those whose `placed_at` is later than the `created_at` of its `previous_id`.
- **Show each Finding's Advisories, Techniques and Mitigations** from its `dossier` as plain text, labeling the Techniques as inferred by the Cartógrafo (ADR 0024), and the Business Context a reason cites.
- Slack (#96) can send the order, its reasons, and the Findings each round placed.

## 4. Simpler code, from the review

The review of the Agents found structural changes that were left out to keep the change reviewable:

- **`Run.Status`**: only verified runs are stored, so `Crew.Prioritize` and `Crew.Plan` can return `(Run[T], error)`, with `ErrRefused`, `ErrRejected` (wrapping the violations) or `ErrUnavailable`, and `Run.Output` can stop being a pointer. That removes `Status`, `failure()` and every nil check, and splits stored content from the read model that carries Plans and Feedback.
- **Rename `internal/assessment`**, which is no longer a domain term (for example to `internal/dossier`), updating ADR 0008, ADR 0016 and depguard.
- **`Crew` holds the Analista's client and model**: move them to `Service`, since the Crew is the Prioritizer and Luna.
- **The Feed Lookups of `kev`, `epss` and `nvd`** lost their last caller with `agent finding`: remove them, and the API URL only EPSS's needs, moving the tests that use them to `Pull`, which are the only tests of `kev` and `epss`.
