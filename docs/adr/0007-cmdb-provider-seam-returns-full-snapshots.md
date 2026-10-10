# CMDB Providers sit behind a snapshot interface; Postgres does not

Every CMDB Provider is an adapter under `internal/cmdb/<provider>` implementing two methods. `Snapshot` returns every in-scope record of a CMDB Source as imported values plus the records it rejected, or an error if it could not read them all. `ValidateSettings` checks a CMDB Source's connection settings when the source is added, so a typo fails then rather than at its first Sync. Authentication, pagination, provider classes and normalization of external formats stay inside the adapter, and each adapter parses its own connection settings, stored as an opaque JSON document on the CMDB Source. The snapshot types (`Snapshot`, `Record`, `Rejection`) live in `inventory`, not `cmdb`, because the pure reconciliation rules (ADR 0005) consume them and the domain cannot import its adapters. The Sync (`cmdb.Sources.Sync`) reconciles a snapshot with the stored Assets using those rules, so a complete snapshot is what allows an Asset missing from the source to be marked Inactive.

The seam is real: iTop and a test fake implement it today and ServiceNow is next. Postgres has no interface: it has a single adapter and tests run it for real, one fresh database per test cloned from a migrated template, so a port would be indirection without a second implementation.

## Considered Options

- **Incremental change feeds**: rejected; deletions are invisible to them, and providers expose changes very differently.
- **A repository interface over Postgres with an in-memory fake**: rejected; the bugs worth catching here (constraints, transactions, row locks) would only exist in the real database.
