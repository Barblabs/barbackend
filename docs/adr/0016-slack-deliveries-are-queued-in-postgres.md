# Slack deliveries are queued in Postgres, one row per message

Every Finding produces a DM to its Asset Owner and an identical post to the Security Team channel (ADR 0015), so a batch of a hundred Findings is two hundred calls to Slack. Slack paces a bot at roughly one message per second per channel and answers a faster burst with `429` and a `Retry-After`. Sending inline from the pipeline's call would therefore drop messages exactly when there is the most to report, and the Security Team channel is meant to be the evidence of what was reported.

Deliveries are queued instead. Handing Findings to Slack writes one `slack_deliveries` row per outbound message — the DM and the channel copy separately, because they fail independently — and an in-process worker in `serve` drains the table, the same shape as Feed polling (ADR 0011). The worker honours `Retry-After` and paces per channel; DMs to different users may go out in parallel. A row is deleted once Slack accepts the message, so the table only ever holds pending, in-flight and failed work. A message that fails five times with exponential backoff stays as `failed`, with its last error, for someone to inspect; nothing alerts on it yet. The queue is not a delivery history: Slack holds the evidence, and the database keeps only what has not been delivered.

Enqueueing sits behind a small interface, so a broker can replace the table later without touching the use case or the HTTP layer.

Delivery is at-least-once. A crash between Slack accepting a message and the row being deleted reposts it, and duplicates are accepted: for an evidence channel a duplicate is a nuisance, a gap is a hole. There is no dedupe key, because that needs a stable Finding id and Findings are not persisted yet.

## Consequences

- `Notify` returns before anything is sent, so the pipeline cannot report whether a Finding reached Slack.
- A duplicate is possible on crash or redeploy; consumers of the channel must tolerate it.
- Failed rows accumulate until someone looks at them; they are the only trace of a message that never arrived.
