---
status: proposed
---

# The Prioritizer orders Findings from their Dossiers, and no Agent that weighs a Finding reads a Feed

barbattack has three Agents: the **Prioritizer**, **Luna** (the Advisor) and the **Analista** (the feedback agent). The Prioritizer takes a Customer's open Findings and puts them in **Priority Groups**, in the order to attend them: Findings in one group are attended at the same time, such as those one update fixes together. It starts from each Score (ADR 0009) and weighs it with what the Score leaves out or cannot say: whether the Vulnerability is exploited now, by ransomware too, what kind of Asset it is and what the affected component does, and how sure the Score is. Every Finding goes in exactly one group, however low its Score: being last is still being attended. No Agent outputs a number, changes a Score or closes a Finding. The Score stays the deterministic rank of record, and each Finding of a Prioritization shows where its Score alone would put it, so a reader sees which ones the Prioritizer moved and reads why.

An Agent's name is its role, not its model. The Prioritizer and Luna run on `claude-haiku-5-5` and the Analista on `claude-opus-5-5`, overridable with `PRIORITIZER_MODEL`, `LUNA_MODEL` and `ANALISTA_MODEL`. The Prioritizer was first drawn as TypeSafe AI's Jev, which returns choices and probabilities but no text, so it cannot say why one Finding goes before another. A second model provider is a new adapter beside `internal/claude`, and only then does a seam appear.

## What an Agent reads

**No Agent that weighs a Finding reads a Feed.** The Findings pipeline, which matches Vulnerabilities to Software Components, already holds what each Feed said and the Score it computed. It hands the Agents one **Dossier** per Finding: the Finding's id, its Asset without the Asset Owner and with the Critical Services that run it, the affected Software Component, the Vulnerability as KEV, EPSS and NVD describe it, its Advisories, ATT&CK Techniques and their Mitigations (ADR 0022 to 0024), and the Score. An Agent that read the Feeds itself could explain a Score other than the one the Customer sees, and would make a Feed outage the Agent's. `Dossier.Validate` rejects a Dossier built wrong before any model is paid.

**The Score in a Dossier is the stored one.** It is the latest row of `finding_scores` for that Finding, with its Data Gaps (ADR 0009, ADR 0020), and its `finding` is the Finding's `findings.id`. No Agent, and nothing that builds a Dossier, computes a Score: `assessment.NewDossier` builds one from what the pipeline stored, and takes the latest Score as it is.

**The Cartógrafo and the Reader read what Feeds wrote, and weigh no Finding.** The Cartógrafo labels a stored Vulnerability with Techniques (ADR 0024). The Reader reads a stored News Item, the one text no Feed structures, once for every Customer, and states what it reports with quotes its verifier finds in the text (ADR 0025). Neither reason above applies to them: they explain no Score, and a Feed outage only delays what they read. What they state reaches the Prioritizer and Luna only through the Dossier, which gains the newest News Items that name its Vulnerability (ADR 0025).

The Prioritizer reads, in one request, the Findings it places and the order that stands, because ordering means weighing them against each other, so one round places at most 100 (ADR 0026). It reads a Brief of each, without the affected versions, references, quotes and Mitigations only an Action Plan needs, and the Customer's Business Context beside them. Luna writes the Action Plan of one Finding when someone asks for it, reading its whole Dossier: a plan for every Finding of every Prioritization would cost a request each, most of them never read.

## How an Agent is kept honest

Both are one call each, with no tools, because with raw Feeds a model chose its own method and two runs disagreed, while with a Dossier and fixed rules they agreed (Actividad 6).

- **What they read travels as data.** It comes from Feeds and the CMDB, so it goes in the user message as JSON, never in the system prompt (ADR 0010).
- **A verifier without a model** checks each answer against what the Agent was given. For a Prioritization: each Finding it places is in exactly one group, by its id, and the groups that stand keep their order (ADR 0026); each group cites evidence, as JSON pointers whose exact values are in its own Findings and that resolve in their Dossiers too, and what it cites of the Business Context is what the Customer stated; every CVE ID, ATT&CK id and version in its prose must be one it was given, since a reason may compare its Findings with others, and no URL may appear; and each group's reason names the Data Gaps of its Findings. For an Action Plan: the fixed version must be where NVD says an affected range ends or an unaffected one starts, or a version the description or KEV's required action writes, never a bound that is still vulnerable; any other version in it must be one of those, a vulnerable bound or what the Asset runs, so a CVSS score cannot pass for one; a URL must be one of NVD's references, not one a description mentions. An answer that fails gets one retry told what was wrong; failing again drops it. **It cannot judge whether an order is wise, a command written in a step, or a URL without a scheme**: a Prioritization is a recommendation and an Action Plan advice, both for a person to read, never something to run unattended.
- **A Run records its model and the hash of its prompt**, as a Score records its Scoring Model, so an output can be traced to what produced it.
- **Nothing unverified is stored.** A Prioritizer or Luna without a verified answer stores nothing and the request fails, so the newest stored Prioritization stays the one to follow. Claude Haiku 5.5 has no server-side fallback for a refusal, and this domain is close to its cybersecurity classifiers. The Analista runs with `fallbacks: "default"`.

The Analista is the only one with a loop. Its tools act as the signed-in User, who is not a parameter the model can set, so they reach one Customer. Three only read; `record_feedback` adds a verdict on a Finding marked `via_analista`, stored only if the turn ends with an answer, and changes no Score and no order: a round of the Prioritizer reads only what a User said directly (ADR 0026). Its verdicts include that a Finding should be attended earlier or later, which is what a Customer knows and the Prioritizer cannot. So text in a Feed that tricked the model could add a false label that can be told apart, or make its reply say anything: **a reply is unverified, and a client must render all Agent text as plain text**, or it could smuggle data out through a link or image. A conversation answers one message at a time, claimed before calling the model, so a second message costs nothing, and it is capped in turns because each turn resends all of it. Its history is stored in a `json` column and sent back as the API returned it, because the API rejects replayed thinking blocks that changed.

## Where the code goes

This adds layers to ADR 0008:

```
internal/
  agents/        use case: Prioritizer, Luna, Analista -> assessment, claude, inventory, postgres, tenancy
  claude/        adapter over Anthropic's API          -> nothing internal
    claudetest/  fake API for tests
  assessment/    pure domain: Dossier, outputs, verifier, Verdict -> inventory, scoring, stixext
```

`postgres` may import `assessment`, as it does the other domain packages. `httpapi` reaches it only through `agents`.

## Consequences

- **A Prioritization is one version of a lasting order.** ADR 0026 decides how each round places new and changed Findings in the order that stands, and what makes it run.
- **The Analista has no Slack transport yet.** It is reached over HTTP and the CLI. Connecting it to Slack (issue #96) must also decide what an Asset Owner, who is not a User, may ask it.
- **`nvd/1` gains the optional `cna_affected`.** NVD no longer analyzes most CVEs, so many have no CPE matches and what is affected comes only from the CVE's numbering authority.
- **The business context is the Customer's statement.** The Prioritizer weighs Criticality, Exposure, the kind of Asset and what its name and components say, and the Business Context the Customer states (ADR 0017): its Critical Services, data, regulations and Risk Appetite.
- **The order can differ between runs** on the same Findings, as any model's can. The Score does not, and each Finding shows both.
- A round costs one request and an Action Plan another. There is no quota yet.
- What is still missing, from a first run against the real model to a quota, is in `docs/agents-pending.md`.

## Considered Options

- **The Score alone as the order, and an Agent that only explains it**: rejected. It cannot group the Findings one update fixes, nor weigh what the Score leaves out, and the team asked for a prioritized list of what to attend first, next and at the same time.
- **TypeSafe AI's Jev for the Prioritizer, as first drawn**: rejected for now. It returns choices and probabilities, not reasons, and no public evaluation covers vulnerabilities.
- **Agents that read the Feeds by CVE**: rejected, for the reasons above; the first version did, before the pipeline was drawn. The Reader reads News Items, not Vulnerabilities by CVE, and explains no Finding (ADR 0025).
- **A tool-using agent for the Prioritizer and Luna**: rejected. It would not be repeatable, and a tool reachable while reading Feed text is what an injected instruction would aim for.
