# Coding Standards

Review rules for judgement calls that no linter checks. Apply every rule to the diff; names and domain meaning come from `GLOSSARY.md` and `docs/adr/`.

## Domain packages

- **Pure**: no I/O, clock, provider names (iTop, ServiceNow) or Go interfaces. A seam appears when a second adapter exists, not before.
- **Own rules only**: the domain enforces its invariants (from the glossary and ADRs). Validating or normalizing external formats, such as email syntax or provider statuses, happens at the edge that receives them.
- **Invariants live in constructors**: types whose invariants matter keep unexported fields, are built by a validating constructor, and reject their zero value where it would mean "unset".
- **Blank means `strings.TrimSpace(s) == ""`**; stored text stays raw, as the CMDB Source wrote it, unless it is an identity the domain owns (an `OwnerEmail` is canonical, ADR 0003).
- **Defensive copies**: slices and pointers are copied on the way in and on the way out.
- **One home per rule**: a check used in more than one place is a single unexported function (for example `blank`).

## Persistence

- **Business rules live in Go, not SQL**: the schema holds only structural integrity (keys, foreign keys, `NOT NULL`, catalog references, uniqueness an upsert relies on). Domain invariants and tenancy rules are enforced and tested in code, so they survive a change of database.
- **Tightening a domain invariant ships with a migration for existing rows**: stored Assets are rebuilt through the domain constructors, so a row that breaks a new rule fails the Sync of its CMDB Source until it is fixed.
- **Merged migrations are immutable**: change the schema with a new migration.

## Tests

- **Black-box**: `package <name>_test`, exercising only the exported interface, table-driven where cases share a shape.
- **Shared helpers** sit in `helpers_test.go`.
- **Each test earns its place**: it covers a case no other test covers; a check that cannot fail (for example mutating a string copy) is removed.

## Code hygiene

- No dead code: every identifier, sentinel error and helper is used.
- Comments explain a non-trivial decision or implementation, per the global rule.
