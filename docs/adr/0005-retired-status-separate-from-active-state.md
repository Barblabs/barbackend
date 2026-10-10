# An Asset's retired status is kept separate from whether it is Active

An Asset is meant to become an Inactive Asset when its CMDB Source reports it as retired or no longer contains it, but barbattack decides when. We store "reported as retired" as an imported value, alongside the other imported values (ADR 0004), and keep Active/Inactive as barbattack's own state, rather than deriving one from the other. Two reasons: an Asset can also become Inactive by disappearing from its CMDB Source, which is not an imported value at all, and the rules that decide when to mark an Asset Inactive or reactivate it belong to the sync, not to the model.

## Sync rules

Each sync reads a full snapshot of the CMDB Source, then:

- An Asset is marked Inactive when its record is reported as retired, or is missing from a complete, successful snapshot.
- An Inactive Asset is reactivated when its record is present again and not reported as retired.
- A failed or partial snapshot never marks any Asset Inactive, so an outage of the CMDB Source cannot silently stop monitoring.

## Considered Options

- **Derive Active from imported values** (Active unless retired or missing): rejected because it fixes the sync rules into the model and cannot express "missing from the CMDB Source", which is not an imported value.

## Consequences

- Between syncs, an Asset can be reported as retired and still be Active. The sync is responsible for marking it Inactive.
- "Status" in ADR 0004 means the imported retired status, not Active/Inactive.
