---
status: proposed
---

# The Prioritizer keeps one lasting order per Customer, and places only what is new or changed

Until now each Prioritization ordered every open Finding of a Customer anew, in one request of at most 100, from a file (ADR 0016). The team asked for an order that lasts: the security team works through it for days, so a Finding that arrives later should find its place among those already ordered instead of reshuffling them. This ADR decides how that order is kept, what places a Finding again, and what makes the Prioritizer run.

## A chain of Prioritizations

A Customer's Prioritizations are one chain: each is built from the one before it (`previous_id`), and the newest, the one no other was built from, is the order to follow. Each is still a whole order, never changed once stored, with the Dossier of each Finding as it was when placed, so any version reads and explains as it was. `UNIQUE (previous_id)` and a single first one per Customer keep the chain linear: of two rounds that start from the same Prioritization, the second to commit fails with `postgres.ErrNotNewest` and stores nothing.

A **placement** (`finding_placements`) is what a round read of a Finding it placed: its Dossier, and `placed_at`, when the round read it. It is stored once: `prioritization_findings` holds each Finding of each Prioritization with the position of its Priority Group, its rank by Score alone and its placement, and a Finding that keeps its place keeps its placement. So a version stores only what it placed, and its `content` only its Priority Groups and the Prioritizer's Run. Action Plans and Feedback reference `(prioritization_id, finding_id)` and are read for a Finding across the chain, so a plan asked from one version shows in the next; an Action Plan stores the Dossier Luna read, as it was then. The migration deleted the Prioritizations stored before it, whose Findings were ids from files that reference nothing.

A **Priority Group** is its title and its parts: one for the Findings it was made with, and one for those each later round added, each with its own reason and evidence. A Finding that leaves the group takes its evidence with it, and a part left empty goes, so every reason still explains Findings the group holds.

## A round

A **Round** is one request of the Prioritizer. It reads the Customer's Business Context, the order that stands and the Findings to place:

- **What stands** is the Priority Groups of the newest Prioritization, without its closed Findings and those placed again, numbered from 1. The Prioritizer reads each group's title, the reason it was made with (cut to 300 characters), its size and its 3 Findings of the highest Scores, each as a short summary: a round's request grows with the groups of the order, not with its Findings. A closed Finding leaves the order, and an order that only lost closed Findings needs no round. An open Finding whose Dossier cannot be built now keeps its place as it was placed.
- **What is placed** is the open Findings the newest Prioritization does not hold, and those that **changed** since they were placed (`assessment.Changed`): KEV lists it now or says ransomware uses it now, the Cartógrafo labeled it since, its Score moved by 0.1 or more (`ScoreShift`, so EPSS's daily drift does not reorder the list), or a User said directly, since the round that placed it read it, that it should be attended earlier or later, which the Prioritizer reads in its own `<feedback>` section. Feedback the Analista recorded is left out: a conversation can be steered by text a Feed wrote, so it changes no order (ADR 0016). Changed Findings go first, then by Score, at most 100 a round; the rest wait for the next round, and a changed one keeps its place until then. `assessment.PlanRound` decides all of this, without the database.
- **A Business Context saved since** the newest Prioritization orders every open Finding anew: what the Customer says of its business can move any of them.

The Prioritizer answers the whole order: every standing group by its number, each once and in its order, and each Finding to place either joining one of them or in a new group between them. Its verifier rejects an answer that moves, merges, skips or repeats a standing group, or lists a standing Finding again, besides what it checked before (ADR 0016). `assessment.Merge` builds the new order: a standing group keeps its title and Findings, and gains the reason and evidence of those that join it.

## What the Prioritizer and Luna read now

A round sends the Business Context as its `business_context/1` document, beside the Findings, as data (ADR 0010). A reason may cite it by JSON pointer in `context_evidence`, which the verifier resolves in the version read, and the Prioritization records that version. Each Dossier names the Critical Services that run its Asset, matched by the Asset's name ignoring case (ADR 0017).

The Dossier now carries what ADR 0022 to 0024 store: its Vulnerability's Advisories as plain text, its Labeling, and up to 5 Techniques, each read as the current Technique of the catalog (`postgres.Tx.CurrentTechnique`, which `techniques` uses too) with MITRE's Mitigations of it. The Prioritizer reads the Techniques' ids, names, tactics and roles and the Advisories' titles, and weighs the phase of the attack: an `exploitation` Technique of Initial Access on an exposed Asset is the most urgent. Luna reads the whole Dossier and proposes `attack_mitigations`, each a Mitigation the Dossier gives for one of its Techniques, against the exploitation first. Every ATT&CK id an answer names must be in what it was given, and both present a label as inferred by the Cartógrafo, never as MITRE's word. No Scoring Model reads any of it (ADR 0009).

## When the Prioritizer runs

`serve` wakes the Prioritizer whenever something can change what it places: after each batch of a Feed and each Sync (`findings.Service.OnChanged`), each Business Context save (`businesscontext.Service.OnSaved`), each Feedback on the order (`agents.Service.OnOrderFeedback`), and each Cartógrafo run that labeled something. It waits until the notices stop for 2 minutes, or 15 after the first, so the many batches of one pull make one run, then calls `agents.Service.PrioritizeAll`: one round for each Customer that is not deactivated and has something to place, in turns, so one with many Findings does not keep the others waiting, up to 50 rounds each; what is left waits for the next run. It also runs every 6 hours without a notice, so a round that failed is tried again. What a round places is read from the database each time, so nothing is lost when `serve` restarts. `agent prioritize --as <email>` runs the same for one Customer.

## Considered Options

- **Reorder every open Finding each time, as before**: rejected; the team works through the order for days, and a reshuffle on every Feed pull would move what they are attending, pay a request over every Finding, and stop at 100.
- **Never move what stands**: rejected; a Finding that ransomware starts to use would stay where it was placed.
- **One list per Customer, updated in place**: rejected; a version that never changes explains itself as it was, and Plans and Feedback keep the version they were given on.
- **A round after every Feed batch, or on a schedule only**: rejected; NVD and EPSS arrive in many batches, and a schedule alone leaves new Findings waiting.

## Consequences

- The order can differ from what a full reorder would give, since it keeps what stands. A User who disagrees says so with Feedback, which places the Finding again.
- A Customer's first round, or the first after a Business Context save, with more than 100 open Findings orders the 100 highest Scores first and places the rest in the rounds that follow.
- The Cartógrafo labels a Customer's Vulnerabilities after their Findings were first placed, so its first runs place most of them again, as many rounds as a full reorder costs, though each sees the order that stands.
- Disconnecting a CMDB Source now closes the open Findings of its Assets as `asset_inactive`, since a Disconnected source is never synced again to close them (ADR 0020), so the Prioritizer does not keep ordering them.
- Each round is one paid request, and how many a day depends on how often a Customer's Findings change; no quota bounds it yet (`docs/agents-pending.md`).
- The tests of `agents` are exempt from its depguard rule, as those of `httpapi` are: they store Findings and Scores as the Findings pipeline does.
