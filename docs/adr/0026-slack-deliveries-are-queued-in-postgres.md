# Slack deliveries are queued in Postgres, one row per message

Every Finding produces a DM to its Asset Owner and an identical post to the Security Team channel (ADR 0025), so a batch of a hundred Findings is two hundred calls to Slack. Slack paces a bot at roughly one message per second per channel and answers a faster burst with `429` and a `Retry-After`. Sending inline would drop messages exactly when there is the most to report, and the Security Team channel is meant to be the evidence of what was reported.

The pipeline writes one `slack_deliveries` row per outbound message, and an in-process worker in `serve` drains the table, the same shape as Feed polling (ADR 0011). The worker only reads and updates; it never inserts. The DM and the channel copy are separate rows because they fail independently. A row carries a `kind`, a structured `payload` and a target — an email for a DM, a channel id for the channel — and the worker renders the payload into Slack blocks. A new kind of message, such as security news, is a new renderer, not a new Slack dialect in every producer. Rows are `pending`, `sent` or `failed`; the worker deletes `sent` rows at the start of each poll, so the table only holds work that is pending or has failed.

The worker polls every minute and honours `429` `Retry-After`, pacing per channel so a channel's messages keep their order. A failure increments `attempts` and schedules the next attempt after one minute, then five; the third failure marks the row `failed` with a `failure_code` and `last_error`. An email Slack does not know fails at once as `owner_unreachable`, and a payload that cannot be decoded as `malformed_payload`, because neither can succeed on a retry. `invalid_auth` and `token_revoked` mark the row `auth_revoked` and flip the installation to `needs re-authorisation` (ADR 0025). `GET /slack/deliveries/failed` lists the Customer's failed rows and `POST /slack/deliveries/retry` returns them to `pending`, resetting `attempts`, `failure_code` and `last_error`, except for malformed payloads.

Delivery is at-least-once. A crash between Slack accepting a message and the row being marked `sent` reposts it, and duplicates are accepted: for an evidence channel a duplicate is a nuisance, a gap is a hole. There is no dedupe key, because that needs a stable Finding id and Findings are not persisted yet.

## Consequences

- The pipeline inserts rows and the worker sends them, so the pipeline cannot report whether a Finding reached Slack.
- A duplicate is possible on crash or redeploy; readers of the channel must tolerate it.
- Failed rows accumulate until someone retries or fixes them; they are the only trace of a message that never arrived.
- The queue is not a delivery history: successful rows disappear at the next poll, and Slack holds the record.
