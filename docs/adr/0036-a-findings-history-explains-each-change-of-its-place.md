---
status: proposed
---

# A Finding's history explains each change of its place

The Prioritizer keeps one lasting order per Customer, as a chain of Prioritizations that are never changed once stored (ADR 0026). A User looking at a Finding asks what the portal cannot answer yet: it was in group 1 yesterday and is in group 3 today, why? Everything needed to answer is stored already: every version's place of the Finding, the Dossier each round read when it placed it, the reason it gave, and the Feedback Users recorded. This ADR adds a read of a Finding's history that puts them together. It calls no Agent: what changed is computed from what is stored, and the justification is what the Prioritizer already wrote.

## What is a change

A Finding's history is one entry for each Prioritization where its place changed, newest first. A version that keeps it where it was, which is most of them, adds no entry. An entry is one of:

| Kind | When | Why, as the entry gives it |
|---|---|---|
| `placed` | the first Prioritization that holds it, or the first after it was reopened | the reason the round gave |
| `placed_again` | a round placed it again: its placement is not the previous version's | what changed in the Finding, and the reason the round gave |
| `moved` | it kept its placement, but its group's position changed | the groups that appeared above it or that left from above it |
| `left` | the version after one that held it no longer does | it was closed, with its close reason (ADR 0020, ADR 0035) |

**Its own change** (`placed_again`) is the difference between the Dossier of the previous placement and the new one, with the rules that place a Finding again (`assessment.Changed`, ADR 0026), each one a code:

- `kev_listed`: KEV lists it now.
- `ransomware_use`: KEV says ransomware uses it now.
- `labeled`: the Cartógrafo labeled it with Techniques since.
- `band_changed`: its Score Band went from one to another, both given.
- `score_moved`: its Score moved by 0.1 or more, from and to given.
- `feedback`: a User said directly, after the previous placement and before this one, that it should be attended earlier or later, with their note. Feedback through the Analista is left out, as it places nothing (ADR 0026).
- `business_context`: the Prioritization read a newer Business Context than the previous one, which places every open Finding again.

More than one can apply. None applying means a round placed it again for a reason the rules did not keep, such as an earlier round failing: the entry says so rather than guess.

**Being moved** (`moved`) is not a change of the Finding: a more urgent group was placed above it, or a group above it emptied when its Findings closed. The entry names the groups above it in this version whose title the previous version did not have above it, and those that were above it before and are not now. Its reason stays the one given when it was last placed.

**The justification** is the Prioritizer's own words: the title of the Finding's group and the reason of the part that holds it, with the evidence it cites of this Finding (ADR 0026). For `moved`, it is the same as the entry that last placed it.

## The API

`GET /findings/{id}/history`, for a Customer Admin or a Viewer of the Finding's Customer, a 404 otherwise. Each entry has the Prioritization's id and creation time, its kind, the position of the Finding's group before and now (null before its first placement and after it left) and the group's title, its rank by Score alone before and now, the change codes with their values, and the justification.

So that each entry compares the order the Score alone gives with the one the Prioritizer gave, it also has, before and now, the Score the Prioritizer read in the Finding's Dossier, and where its group sits in the Prioritizer's order counted Finding by Finding, as a span from and to. A span and not one position: a Priority Group's Findings are attended at the same time, so the order inside it says nothing. A Finding whose Score alone puts it 7th, in a group that spans 2 to 4, is one the Prioritizer brought forward. The frontend calls it when a User opens a Finding, not with every Prioritization, which already holds all its Findings.

## How it is read

From what ADR 0026 stores, in a fixed number of queries whatever the length of the chain: the Finding's rows of `prioritization_findings` with each version's creation time and Business Context version, ordered along the chain; the Dossiers of its distinct placements; the Priority Groups of the versions that give an entry; and the Customer's direct Feedback on the Finding. The comparison lives in `assessment`, pure and without the database, beside `Changed`, which now shares its rules with it.

## Considered Options

- **Asking the Prioritizer to explain each move**: rejected; a request per Finding per change, for words it already wrote when it placed the Finding.
- **Storing the change codes when a round places a Finding**: left out; they can be computed from the two Dossiers whenever asked, and old Prioritizations would have none.
- **The history inside `GET /prioritizations/{id}`**: rejected; it would read the whole chain for every Finding of the order, most of which nobody opens.
- **An entry for every version**: rejected; most versions keep the Finding where it was, and a User wants what changed.

## Consequences

- A Finding's history reaches back only to ADR 0026's chain: Prioritizations stored before it were deleted.
- `moved` names groups by title, which a standing group keeps (ADR 0026); two groups with the same title would be told apart only by position.
- A long chain is read whole for one Finding. It is one indexed query on `prioritization_findings`, and can be bounded later if it grows.
