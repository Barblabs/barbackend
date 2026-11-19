---
status: proposed
---

# Users close and reopen Findings by hand

Until now a Finding closed only on its own: when its match went away in a Sync or an NVD update, or its Asset became Inactive (ADR 0020). A User who knew a Finding did not apply, or that the Customer accepted its risk, could only say so as Feedback, which changes no Score and leaves the Finding open (ADR 0026). This ADR lets a User close a Finding by hand with a reason, decides which of those closes a later match undoes, and narrows Feedback to what it is for: where a Finding should be in the order.

## Who

A Customer Admin or a Viewer of the Finding's Customer. A Platform Admin sees no Customer's Findings, so cannot.

## The reasons

`finding_close_reasons` gains four rows, the reasons a User can give:

| id | name | Means | Reopens on its own |
|---|---|---|---|
| 5 | `remediated` | the User says it was fixed | at the next match: if the Sync still finds the vulnerable version, it was not |
| 6 | `false_positive` | it does not apply to this Asset, whatever the CMDB says | never |
| 7 | `accepted_risk` | the Customer knows and accepts it | at the first match after `reopen_at` |
| 8 | `postponed` | it will be attended later | at the first match after `reopen_at` |

The four of ADR 0020 stay as they are and only the Findings use case sets them; the API accepts only these four.

## What is stored

`findings` gains three nullable columns, set by a close by hand and cleared with the rest when the Finding reopens:

- `closed_by`: the User who closed it, referencing `users`.
- `close_note`: why, required, at most the length of a Feedback note.
- `reopen_at`: required for `accepted_risk` and `postponed`, null for the other reasons. It must be after the close.

CHECK constraints keep them consistent with `close_reason_id`: `closed_by` and `close_note` are set exactly when the reason is one of the four above, and `reopen_at` exactly when it is `accepted_risk` or `postponed`.

There is no history: a Finding keeps only its latest close, as it keeps only its latest open period (ADR 0020). Reopening it clears who closed it and why.

## What a match does now

`UpsertFinding` reopens a closed Finding that matches again, as before, except when its reason is `false_positive`, or `accepted_risk` or `postponed` with a `reopen_at` still in the future. Those stay closed; their component, version and evidence are still updated, so the Finding shows what the CMDB says when someone looks at it. The `Outcome` tells such a match from a reopen, so nothing downstream treats it as one.

So a Finding closed as `accepted_risk` until 1 March reopens at the first Sync or NVD match after that day, not on the day itself: no timer is added. One whose component was upgraded meanwhile no longer matches, and stays closed with the reason the User gave.

A Finding closed by hand is closed like any other: it is not rescored (ADR 0009), it leaves the Prioritizer's order and is not alerted (ADR 0026, ADR 0033), and the dashboard counts it as closed, its time to close included.

## Reopening by hand

A User can reopen a Finding closed by hand, with any of the four reasons. `opened_at` is set and the close is cleared, as when a match reopens it, and the next round of the Prioritizer places it. A Finding closed on its own cannot be reopened by hand: the next Sync would close it again, since nothing matches it.

## The API

| Method | Path | What it does |
|---|---|---|
| `POST` | `/findings/{id}/close` | closes an open Finding with `reason`, `note` and, for `accepted_risk` and `postponed`, `reopen_at`; 409 if it is closed |
| `POST` | `/findings/{id}/reopen` | reopens a Finding closed by hand; 409 if it is open or was closed on its own |
| `GET` | `/findings/closed` | the Customer's closed Findings, newest close first, each with its reason, note, who closed it, when, and `reopen_at` |

The Customer is the caller's; a Finding of another Customer is 404.

## Feedback is only about the order

The verdicts `Does Not Apply` and `Remediated` overlapped with closing: a User who chose them could expect the Finding to close, and it did not. Feedback now takes only `Applies`, `Should Be Earlier` and `Should Be Later`, from the API and from the Analista's `record_feedback`. The two rows stay in `feedback_verdicts`, so Feedback recorded with them before is kept and still reads. The note is now required, since the Prioritizer reads it with the verdict in its `<feedback>` section (ADR 0026).

## Considered Options

- **Feedback that closes the Finding**: rejected; an opinion on the order and a decision on the Finding are different things, and the Analista's Feedback can be steered by what a Feed wrote (ADR 0016).
- **Every close by hand undone by the next match**: rejected; a false positive or an accepted risk would reopen at the next Sync, since the CMDB still shows the same version.
- **`remediated` kept closed like the others**: rejected; the CMDB is what tells whether it was fixed, and reopening it when it still matches checks what the User said.
- **A table of every close and reopen**: left out; the team does not need the history now, and a Finding keeps none of its other changes.
- **A job that reopens on `reopen_at`**: left out; Syncs run often enough that the first match after it is soon, and it needs no new timer.

## Consequences

- A User can hide a Finding that does apply. Who closed it, why and until when stay on the Finding and are listed with the closed ones, so another User can see it and reopen it.
- A `remediated` Finding that was not fixed reopens at the next Sync, and counts as closed and reopened.
- The dashboard does not tell a Finding closed by hand from one closed on its own.
- The frontend's Feedback form loses two options, and the Finding view gains close and reopen, and a list of the closed Findings.
