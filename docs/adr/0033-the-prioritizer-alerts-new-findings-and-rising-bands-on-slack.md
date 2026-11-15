---
status: accepted
---

# The Prioritizer alerts on Slack when it places a new Finding or one whose Band rose

ADR 0029 has every Finding the agent emits reach Slack, and ADR 0030 queues the messages and drains them, but nothing writes them yet. Writing one for every Finding a round places would be noise: the Prioritizer places a Finding again when its Score moved by 0.1, when its Band fell, when a User said it should be earlier or later, and places every open Finding again when the Business Context changes (ADR 0026, ADR 0032). None of those is news for an Asset Owner. This ADR states when an Alert is written, what it carries, and how the first load of a Customer is sent. It amends the alerting rule of ADR 0029 and the dedupe of ADR 0030.

## When an Alert is written

An Alert is written for a Finding the Prioritizer places in a round when either:

- **it is new**: it was never placed before; or
- **its Band rose**: the Dossier it was last placed with, in any of the Customer's Prioritizations, has a lower Score Band than the one it has now (ADR 0032). A Score without a Band has none to compare.

Nothing else writes one: not a Score that moved within its Band, not a Band that fell, not User feedback, not a change of Business Context. The comparison is against each Finding's own last placement (`finding_placements`), not against the previous Prioritization: a change of Business Context places every open Finding anew over as many rounds as it takes, and from the second of them on, the previous Prioritization holds only what the first placed, so every other Finding would look new. A Finding that closed and was found again was placed before, so it is alerted only if it came back at a higher Band.

KEV listing a CVE is not a reason of its own. It sets the Exploit Signal to 1 (ADR 0032), which raises the Band of almost every Finding of it; a KEV CVE that does not raise the Band, such as one on a spare in Stock, is not urgent for that Asset. Known ransomware use is not a reason either.

The Prioritizer writes the Alerts because they carry its reason: an Alert written when the Score is saved would reach Slack before any Agent read the Finding. It waits for a round: at least two minutes of quiet after a change and at most fifteen, and a Finding beyond a round's 100 waits for the next one (ADR 0026).

## Exactly once per round

The rows are written in the transaction that stores the round's Prioritization, before its placements, so a round that fails writes none and a stored round wrote all of its own. A round places a Finding once, and the next placement compares with this one, so no other dedupe key is needed. The rows are written highest Score first, and their ids are time-ordered (UUID v7), so the worker, which sends each target's rows by `created_at` and then id, sends them in that order although one transaction gives them all the same `created_at`. `slack_deliveries` gains a nullable `finding_id` that names the Finding a row is about; a batch row names several, so its `finding_id` is null and its payload holds their ids. Delivery stays at-least-once (ADR 0030): a crash between Slack accepting a message and the row being marked `sent` still reposts it.

## The Initial Load is sent in batches

A Customer's first Findings arrive all at once: 3,000 Findings would be 3,000 DMs and 3,000 channel posts, and the channel takes nearly an hour to drain at one message a second. So the Initial Load is sent in batches of 10, and every Alert after it is one message.

The Initial Load lasts from the Customer's first round to the first round that leaves no open Finding without a place. A round holds at most 100 Findings, so a Customer with 3,000 takes about 30 rounds; "the first Prioritization" would batch only the first 100. Each Prioritization keeps whether it belongs to the Initial Load in its content, and each round carries it from the one before, so a load cut short by the rounds limit or a restart stays a load in the next run. A change of Business Context does not start a new one.

During the Initial Load, a round groups its Alerts by target, the Security Team channel and each Asset Owner's email, orders each group by Score, highest first, and writes one row of kind `finding_batch` per 10. The channel gets every Finding; each Asset Owner gets only theirs.

## What an Alert carries

The kind `finding` is one Finding. Its payload is what the message shows, so the worker renders it and reads nothing else (ADR 0030):

- `finding_id`, `prioritization_id`, and `reason`, `new` or `band_rose`, with `band_was` for the latter.
- `cve`, `asset`, `component`, `owner_email` and `portal_url`.
- `score`, from 0 to 1, and `score_band`.
- Why it scores what it does: `cvss`, `epss`, `kev`, and the Asset's `criticality`, `exposure`, `lifecycle_stage` and `information_classification`. A value never declared is sent as such (`unknown`, `unclassified`), never as empty.
- `group`: the Priority Group the Prioritizer placed it in, with its `position`, the number of groups (`of`), its `title` and its `reason`, the Prioritizer's own words for why those Findings go there.

The kind `finding_batch` is `{"findings": [...]}`, at most 10 of the above for the same target.

The Score is shown from 0 to 100, as in the portal. The Band leads the message with a colour mark: red Critical, orange High, yellow Medium, white Low. A single Alert shows each value in its own field and the group's reason under "Why it matters". A batch shows one line per Finding, with its group's number and title but not its reason, and links to the portal for the rest. Messages are in English. Until the portal has a page for one Finding, `portal_url` is the portal's own address, from `PORTAL_URL`.

Each Alert, single or batch, is still one row for the Asset Owner and one for the channel (ADR 0029, ADR 0030). A channel row's target is `security-team`, not a channel id: the worker sends it to the channel the installation names when it sends, so a row written before an admin picked a channel waits for one, as a row without an installation waits, and a channel changed since gets what was still pending. A Finding with no Asset Owner gets a DM row with an empty target, which fails as `owner_unreachable` without calling Slack, so an admin sees it.

## What changes in the worker

The queue, the claim, the retries and the failure codes of ADR 0030 stay as they are. What the worker does differently:

- The payload contract lives in package `alert` (`alert.Finding`, `alert.Batch`), shared by the Prioritizer that writes it and the worker that renders it; `findingPayload` and its `recommendation` are gone. Rendering is in `internal/slack/render.go`, one renderer per kind.
- A channel row whose target is not `security-team` fails at once as `malformed_payload`, as does a batch of no Findings or more than 10.
- A channel row of a Customer whose installation names no channel stays `pending` without counting an attempt.
- A DM row with an empty target fails at once as `owner_unreachable`, without calling Slack.
- Channel pacing is per Customer and target: every Customer's channel rows share the target `security-team`, and one Customer's must not slow another's.
- Every value an Alert carries is escaped for mrkdwn (`&`, `<`, `>`) before it goes into a message: a group's reason is the Prioritizer's, which reads Feed text, and must never mention `<!channel>` or forge a link. Each text is cut with an ellipsis to Block Kit's limits (header 150 characters, section 3,000, field 2,000), because Slack refuses a longer one and no retry would fix it.

## Considered Options

- **Alert on every Finding a round places**, as ADR 0029 wrote: rejected. A change of Business Context places every open Finding again, and each daily move of 0.1 would repeat an Alert the owner already had.
- **Alert when the Score is saved**, in the findings use case: rejected. It reaches Slack sooner and needs no round, but before any Agent has read the Finding, so the message cannot say why it matters.
- **A table of what each Finding was last alerted with**: rejected. `finding_placements` already holds the Dossier, and so the Band, each Finding was last placed with, and writing in the round's transaction makes each Alert happen once.
- **Compare with the previous Prioritization**: rejected; after a change of Business Context it holds only what the rounds so far placed again, so the rest would look new.
- **Alert when KEV lists the CVE, or ransomware use is known**: rejected; the Band already rises with the Exploit Signal, and where it does not, the Finding is not urgent.
- **Batch in the worker**, claiming up to 10 due rows of a target: rejected. Batching is only for the Initial Load; after it, each Alert is its own message, so the producer, which knows which is which, decides.
- **One summary message for the whole Initial Load**: rejected for now; batches of 10 keep every Finding visible in the channel, which is the evidence of what was reported (ADR 0029).

## Consequences

- An Alert reaches Slack two to fifteen minutes after the change that caused it, and only if the Prioritizer answers; a Customer whose rounds fail gets no Alerts until they succeed.
- A Score within thousandths of a Band threshold can cross it back and forth with EPSS's drift (ADR 0032), and each rise alerts again. Few Findings sit that close.
- A Band that falls never alerts. The portal shows it.
- The Initial Load of a Customer with 3,000 Findings is about 300 messages in the channel, at one a second.
- `finding_batch` rows have no `finding_id`; their Findings are read from the payload.
- A Customer that was in the middle of its Initial Load when this was deployed has no flag in its newest Prioritization, so the rest of its load is sent one Alert at a time.

## Pending

Found in review and left for a later change:

- **The worker reads the installation twice per channel row**: `token` reads it for the bot token and `address` again for the channel. `token` could return both, and `deliver` could check a row's shape (empty DM target, channel target other than `security-team`) in one function next to `render`.
- **`PORTAL_URL` is set through a setter** (`agents.Service.LinkAlertsTo`) rather than given to `NewService`, and an empty one renders a message with no link instead of stopping `serve` at startup.
- **The Initial Load flag can stay set**: when a round of the load leaves Findings without a place and they all close before the next round, no Prioritization is stored to clear it, and the Customer's next new Finding is sent as a batch of one.
