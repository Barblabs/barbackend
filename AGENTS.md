<important if="you are updating AGENTS.md">
Keep entries concise and useful across future sessions. Point to authoritative files or commands instead of repeating discoverable codebase details. Prefer rewriting or pruning over appending.
</important>

## Domain

- `GLOSSARY.md` contains the domain language for the project. Use the terms as defined in the file, don't drift to synonyms.
- `docs/adr/` Read adrs that touch the area you are working in. If your output contradicts an existing ADR, surface it rather than overriding.
- When a domain term or decision changes, use the `domain-modeling` skill to update both.

## Architecture

- Package layers and where new features go: ADR 0008. `depguard` in `.golangci.yaml` enforces the import direction; if a rule blocks you, move the code to the right layer rather than loosening the rule.

## Database

- Schema lives in `internal/postgres/migrations` (goose); queries in `internal/postgres/queries`. After editing either, run `go tool -modfile=tools.mod sqlc generate`; never edit `internal/postgres/sqlcgen`.
- Integration tests use `internal/postgres/pgtest` (embedded Postgres, one database per test); call `pgtest.Main` from the package's `TestMain`.

## Tools

- Dev tools (`golangci-lint`, `sqlc`, `govulncheck`) are pinned in `tools.mod`; run them as `go tool -modfile=tools.mod <tool>` so local runs and CI use the same versions.
