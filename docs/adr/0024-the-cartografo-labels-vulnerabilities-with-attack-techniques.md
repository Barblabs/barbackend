---
status: proposed
---

# The Cartógrafo labels Vulnerabilities with ATT&CK Techniques

barbattack keeps the ATT&CK catalog (ADR 0023) so that a Vulnerability can show the Techniques that exploit it and what follows, and Luna can propose MITRE's own Mitigations. This ADR decides where those labels come from: a new Agent, the **Cartógrafo**, which reads a stored Vulnerability and picks, from the stored catalog, the Techniques it maps to, each with the words of the Vulnerability that justify it.

No source publishes these labels for new CVEs. The one public mapping, CTID's *Mappings Explorer* for KEV, covered 419 CVEs, only 69 of them from 2025, was last published in July 2025 against ATT&CK 16.1, and has no feed to follow. The team chose an Agent over it, and over keeping it as a reference set: every label comes from the Cartógrafo.

## What a label is

A label belongs to the **Vulnerability**, not to a Finding: the Techniques that exploit a CVE are the same on every Asset and for every Customer, so a Vulnerability is labeled once and every Finding of it shows its labels. A Vulnerability has at most 5 labels, or none when what it says is not enough to tell. Each label has:

| Field | Holds |
|---|---|
| ATT&CK id | A current Technique of the stored catalog, such as `T1190` |
| Role | `exploitation`: how an attacker exploits the Vulnerability; `primary_impact`: what exploiting it gives them directly; `secondary_impact`: what they can do next with that |
| Evidence | An exact quote of what the Cartógrafo read that supports the label |
| Rationale | One sentence, for the dashboard |

A label is an inference, and is shown as one: "inferred by the Cartógrafo", with its evidence, never as MITRE's word. The labels change no Score (ADR 0009).

## What the Cartógrafo reads

One request per Vulnerability, with no tools, as the Prioritizer and Luna (ADR 0016):

- **The Vulnerability**: its CVE ID, its description, its CWEs, its CVSS vector, the products NVD and its numbering authority say are affected, and, when KEV lists it, KEV's name, required action and whether it is known to be used by ransomware.
- **Its Advisories** (ADR 0022): the title and description of each.
- **The current Techniques of the catalog**: the ATT&CK id, name and tactics of each, about 700. Revoked and deprecated ones are not offered.

All of it comes from Feeds, so it travels in the user message as JSON, never in the system prompt (ADR 0010). The catalog goes first and is cached, since it is the same in every request until the next ATT&CK pull. The Cartógrafo reads nothing of a Customer: no Asset, Finding or Business Context reaches it, so its requests carry only public data.

## How it is kept honest

- **The API enforces the answer's shape**: a list of at most 5 labels, each with the four fields, the role one of the three.
- **A verifier without a model** checks each answer against the request: every ATT&CK id is one of the Techniques offered; no Technique is labeled twice; every evidence is an exact quote, ignoring case and spacing, of at least 20 characters of the description, KEV's required action or an Advisory given; no URL appears. An answer that fails gets one retry told what was wrong.
- **It cannot judge whether a label is right.** A label can be wrong and still pass, if its quote is real and its Technique exists. This is why a label shows its evidence, and why it is never more than an input to a person or to another Agent.
- **A Labeling records its model and the hash of its prompt**, as a Run does (ADR 0016), so a label can be traced to what produced it.
- **The model reaches nothing.** It has no tools and no access to the database or to barbattack: the Cartógrafo's code in the backend reads what the model is given, calls it, and stores only what the verifier passed. Text in a Feed that tricked the model can at most make a label wrong.
- **A label is shown as plain text.** Its evidence and rationale are Feed text read by a model, so a client must never render them as HTML (ADR 0016), or they could carry a script or a tracking link.

## When it runs

A job in `serve` runs once a day: 15 minutes after `serve` starts, so the Feeds' first pulls, ATT&CK's among them, have finished, and every 24 hours after. Each run takes the stored Vulnerabilities that have no Labeling, newest first, and labels them one by one. A label is not needed within minutes: Techniques add to what a Finding shows, while the Score and the Finding exist without them.

**At most 50 Labelings a day**, counted from the Labelings stored in the last 24 hours, so restarting `serve` does not start a new budget. Each costs at most two requests, the answer and its retry. What the cap leaves waits for the next day. A request to the model is never made inside a Feed's transaction: the Vulnerability is read, the model is called, and the Labeling is stored in a transaction of its own.

- **Once per Vulnerability.** A stored Labeling, with labels or with none, is final. A later change to the Vulnerability's description or a new ATT&CK version does not label it again; that is a later decision.
- **A failed attempt is retried.** An answer that fails twice, a refusal, or a stored Vulnerability or Advisory that cannot be read stores a failed attempt and no labels, and the run goes on with the next. The Vulnerability is tried again in a later run, at most 3 times; after the third failure it stays without labels. Claude Haiku 5.5 has no server-side fallback for a refusal, and this domain is close to its cybersecurity classifiers.
- **A model that cannot be called spends no attempt.** An API error, such as a missing key or an outage, stops the run and stores nothing, so it cannot leave every waiting Vulnerability without labels. The next run tries again.
- **`serve` runs as one instance**, so one Cartógrafo runs at a time. Were a second to run, a Labeling the other made final would be left as it is, but the same Vulnerability could be paid twice; more than one instance is a later decision, for the Feeds too.
- Only stored Vulnerabilities are labeled, which are those that match some Customer (ADR 0015).

## Tables

| Table | Holds |
|---|---|
| `vulnerability_labelings` | `cve_id` as key, referencing `vulnerabilities`; outcome (`labeled`, `none` or `failed`); attempts; model; prompt hash; `labeled_at` |
| `vulnerability_techniques` | (`cve_id`, `attack_id`) as key; role; evidence; rationale |

`attack_id` is the id the Cartógrafo gave, with no foreign key to `attack_techniques`: it is read with ADR 0023's rules, so a Technique revoked in a later ATT&CK version is read as its replacement.

## The model

The Cartógrafo runs on `claude-haiku-5-5`, overridable with `CARTOGRAFO_MODEL`, as the other Agents are. Picking among a fixed list with a quote is closer to the Prioritizer's work than to the Analista's.

## Where the code goes

The Cartógrafo is an Agent, so it lives in `internal/agents`, which already imports `claude` and `postgres` (ADR 0008, ADR 0016). What it reads, what it answers and its verifier are pure domain, in `internal/assessment` beside the Prioritizer's and Luna's. `internal/claude`'s `Structured` gains a cached block for the catalog. The job is started by `serve`, beside the Feeds (ADR 0011).

## Considered Options

- **CTID's KEV mappings as the source**: rejected. They cover a few hundred CVEs, mostly from before 2025, and have not been published since July 2025.
- **CTID first, the Cartógrafo for the rest**: rejected. Two sources for one label, one of them a year behind, for a few hundred CVEs.
- **Keep CTID's mappings once, to measure the Cartógrafo against**: rejected by the team, which trusts the Agent's mapping. The Cartógrafo's accuracy is therefore not measured; it is judged by reading its labels and their evidence.
- **Rules from CWE to ATT&CK**, such as through CAPEC: rejected. A CWE says what kind of flaw there is, not how it is reached or what it gives, and CAPEC's ATT&CK mappings cover few of them.
- **Labels on Findings**: rejected. The Techniques of a CVE do not depend on the Asset, and labeling per Finding would cost a request per Asset for the same answer.
- **Labeling while a Feed stores the Vulnerability**: rejected. A model call inside a Feed's transaction would hold it open for seconds and make a model outage the Feed's.
- **A tool-using agent that searches the catalog**: rejected, for the reasons of ADR 0016. The catalog fits in one cached request.

## Consequences

- Two migrations and their queries, the Cartógrafo and its verifier, the job, and tests of each with `claudetest`.
- `GLOSSARY.md` gains **Cartógrafo**.
- The Dossier does not carry labels yet. Adding a Vulnerability's Techniques and Advisories to it, so the Prioritizer and Luna read them, is for the owner of the Agents; what to add, from where, and how the Prioritizer and Luna use it is in `docs/agents-pending.md` §6.
- One request per stored Vulnerability, paid once. There is no quota yet.
- Two runs over the same Vulnerability can pick different Techniques. A Labeling is stored once and not rerun, so what a reader sees does not change.
