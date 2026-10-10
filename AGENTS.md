<important if="you are updating AGENTS.md">
Keep entries concise and useful across future sessions. Point to authoritative files or commands instead of repeating discoverable codebase details. Prefer rewriting or pruning over appending.
</important>

## Domain

- `GLOSSARY.md` contains the domain language for the project. Use the terms as defined in the file, don't drift to synonyms.
- `docs/adr/` Read adrs that touch the area you are working in. If your output contradicts an existing ADR, surface it rather than overriding.
- When a domain term or decision changes, use the `domain-modeling` skill to update both.

## Database

- Schema lives in `internal/postgres/migrations` (goose); queries in `internal/postgres/queries`. After editing either, run `go tool sqlc generate`; never edit `internal/postgres/sqlcgen`.
- Integration tests use `internal/postgres/pgtest` (embedded Postgres, one database per test); call `pgtest.Main` from the package's `TestMain`.
