---
status: accepted
---

# Luna writes the Action Plans on her own

ADR 0016 had Luna write an Action Plan only when a User asked for one, because a plan for every Finding would cost a request each, most of them never read. The team wants the plan to be there when someone opens a Finding, not a button and a minute's wait, so Luna now writes them on her own. A User can still ask for one again.

## What she plans, and when

After each run of the Prioritizer, `serve` wakes Luna. That happens on every change that wakes the Prioritizer, and at least every 6 hours (ADR 0026). She takes, in every Customer that is not deactivated, each open Finding of its newest Prioritization whose Action Plan is due:

- **it has none**, or
- **it changed since its newest one**, as `assessment.Changed` tells a round to place it again (ADR 0026). That is, KEV lists it now, KEV says ransomware uses it now, the Cartógrafo labeled it, its Score Band changed, or its Score moved 0.1 or more.

Feedback and a new Business Context make no plan due: an Action Plan is about the Finding on its Asset, and neither changes that. A plan a User asked for counts like hers, and the newest plan of a Finding is the one shown, whoever asked for it.

She waits for the Prioritizer because its order is what she follows. She writes the plans in that order, Priority Group by group, so the most urgent come first. A Finding that has no place yet, during an Initial Load (ADR 0033), gets its plan once a round places it.

## One at a time

She writes one plan at a time, 20 for one Customer and then the next Customer's turn, so a Customer with thousands of Findings does not keep the others waiting. Writing them one by one keeps her within the API's rate limits. The cost is that 3,000 Findings take hours, with the urgent ones first. She runs in her own goroutine, so a long run never holds back the next order, and a run of the Prioritizer that ends while she works has her run once more afterwards. Each run tries a Finding at most once.

## Failures

A refused answer, or one that kept failing verification, is a failed attempt. `action_plan_failures` counts them per placement (ADR 0026), and she stops after 3. A Finding placed again has a new placement, so she tries it anew; a User can still ask for its plan at any time. A model that cannot be called, such as with a missing key or during an outage, stops her run and spends no attempt, as with the Cartógrafo (ADR 0024). The next run of the Prioritizer tries again.

## Consequences

- **Every open Finding now costs a request, and another each time it changes.** The Cartógrafo has a daily cap and this does not, so that the first plans of a new Customer are not spread over days. A quota per Customer is still pending (`docs/agents-pending.md`).
- **Two instances of `serve` would both write the same plans.** Nothing breaks, since the newest plan is the one shown, but each one costs twice. `serve` runs as one instance.
- **The Action Plan still goes nowhere but the portal.** It goes to no Slack Alert, so Alerts are not held back waiting for it (ADR 0033).
