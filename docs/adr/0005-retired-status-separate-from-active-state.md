# An Asset's retired status is kept separate from whether it is Active

An Asset is meant to become an Inactive Asset when its CMDB Source reports it as retired or no longer contains it, but barbattack decides when. We store "reported as retired" as an imported value, alongside the other imported values (ADR 0004), and keep Active/Inactive as barbattack's own state, rather than deriving one from the other. Two reasons: an Asset can also become Inactive by disappearing from its CMDB Source, which is not an imported value at all, and the sync rules that decide when to mark an Asset Inactive or reactivate it are still an open business question that the model should not decide early.

## Considered Options

- **Derive Active from imported values** (Active unless retired or missing): rejected for now because it fixes the sync rules into the model before they are decided. It can be revisited once the sync semantics are settled.

## Consequences

- Until sync rules exist, an Asset can be reported as retired and still be Active. The sync is responsible for marking it Inactive.
- "Status" in ADR 0004 means the imported retired status, not Active/Inactive.
