<important if="you are updating AGENTS.md">
Keep entries concise and useful across future sessions. Point to authoritative files or commands instead of repeating discoverable codebase details. Prefer rewriting or pruning over appending.
</important>

## Architecture

- Package layers and where new features go: ADR 0008. `depguard` in `.golangci.yaml` enforces the import direction; if a rule blocks you, move the code to the right layer rather than loosening the rule.

## Database

- Schema lives in `internal/postgres/migrations` (goose); queries in `internal/postgres/queries`. After editing either, run `go tool -modfile=tools.mod sqlc generate`.
- Integration tests use `internal/postgres/pgtest` (embedded Postgres, one database per test); call `pgtest.Main` from the package's `TestMain`.

## Tools

- Dev tools (`golangci-lint`, `sqlc`, `govulncheck`) are pinned in `tools.mod`; run them as `go tool -modfile=tools.mod <tool>` so local runs and CI use the same versions.

## Agent skills

### Issue tracker

Issues are tracked in GitHub Issues for `Barblabs/barbackend` (via the `gh` CLI). See `docs/agents/issue-tracker.md`.

### Triage labels

Default triage roles with neutral names: `implementation` (ready-for-agent) and `hands-on` (ready-for-human). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `GLOSSARY.md` and `docs/adr/` at the repo root. Before working in an area, read `docs/agents/domain.md`.
