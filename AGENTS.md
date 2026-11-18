# AGENTS.md

Go backend for barbattack: syncs CMDB Sources into Postgres as Assets, turns Feeds into scored Findings, and serves them over an HTTP API (Gin + Huma).

## Project map

- `cmd/barbackend/` - CLI: flags, usage and wiring only
- `internal/` - packages layered by role (transports, use cases, adapters, persistence, pure domain); the full map and allowed imports are in `docs/adr/0008-package-layering.md`
- `internal/postgres/` - all persistence: `migrations/` (goose), `queries/` (sqlc), generated `sqlcgen/`
- `GLOSSARY.md` - domain terms; `docs/adr/` - design decisions; `CODING_STANDARDS.md` - code conventions

`dev` is the default branch: branch off it and open PRs against it. `main` only moves on a formal release, by merging `dev` into it.

<important if="you need to run commands to build, test, lint, or generate code">

Dev tools are pinned in `tools.mod`; always run them through `go tool -modfile=tools.mod` so local runs match CI.

| Command | What it does |
|---|---|
| `go build ./cmd/barbackend` | Build the CLI |
| `go test -race ./...` | Run tests (embedded Postgres downloaded on first run) |
| `go tool -modfile=tools.mod sqlc generate` | Regenerate `sqlcgen` after editing migrations or queries |
| `go tool -modfile=tools.mod sqlc diff` | Check generated code is up to date (CI) |
| `go tool -modfile=tools.mod golangci-lint run ./...` | Lint (CI) |
| `go tool -modfile=tools.mod govulncheck ./...` | Vulnerability check |
| `go tool -modfile=tools.mod deadcode ./...` | List functions only tests reach (CI) |
</important>

<important if="you are adding a package, moving code between packages, or a depguard rule blocks an import">
- Place code by the layers in ADR 0008. `depguard` in `.golangci.yaml` enforces the import direction; if a rule blocks you, move the code to the right layer rather than loosening the rule.
</important>

<important if="you are removing code or a function is only called from tests">
- CI's `lint` job fails on any function `deadcode` reports outside the test-helper packages (`internal/**/*test/`). Delete dead code rather than keep it alive for a test.
</important>

<important if="you are editing the database schema or SQL queries">
- Schema lives in `internal/postgres/migrations` (goose); queries in `internal/postgres/queries`. After editing either, run `sqlc generate`. Never edit `internal/postgres/sqlcgen` by hand.
</important>

<important if="you are writing tests that touch Postgres">
- Use `internal/postgres/pgtest` (embedded Postgres, one database per test): call `pgtest.Main` from the package's `TestMain`.
</important>

<important if="you are exploring an unfamiliar area, naming a domain concept, or making a design decision">
- Read `docs/agents/domain.md` first: it explains how to use `GLOSSARY.md` and `docs/adr/` (single-context repo).
</important>

<important if="you are reading, creating, or triaging GitHub issues">
- Issues live in GitHub Issues for `Barblabs/barbackend`, via the `gh` CLI. See `docs/agents/issue-tracker.md`.
- Triage labels: `implementation` (ready-for-agent) and `hands-on` (ready-for-human). See `docs/agents/triage-labels.md`.
</important>

<important if="you are updating AGENTS.md">
- Keep entries concise and useful across future sessions. Point to authoritative files or commands instead of repeating discoverable codebase details. Prefer rewriting or pruning over appending.
</important>
