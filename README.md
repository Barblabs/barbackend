# barbackend

Backend for barbattack. It keeps the asset inventory: it registers CMDB Sources and Syncs their records into Postgres as Assets.

Domain terms are defined in [`GLOSSARY.md`](GLOSSARY.md), design decisions in [`docs/adr/`](docs/adr/), and code conventions in [`CODING_STANDARDS.md`](CODING_STANDARDS.md).

## Requirements

- Go (version in `go.mod`)
- Postgres 15 for running the CLI. Tests start their own embedded Postgres.

## Running

```bash
go build ./cmd/barbackend

# migrate, source and sync need a database
export DATABASE_URL="postgres://user:pass@localhost:5432/barbackend?sslmode=disable"

./barbackend migrate   # apply migrations in internal/postgres/migrations
./barbackend serve     # HTTP server, only GET /ping for now (gin, :8080 unless PORT is set)
```

Run `./barbackend` with no arguments to print the usage.

## Flows

### Add a CMDB Source

```bash
./barbackend source add \
  --customer <customer-uuid> \
  --provider <provider-id> \
  --settings '<json>'
```

The provider validates the settings before the source is stored. Prints the new CMDB Source ID.

Providers are registered in `providers()` in `cmd/barbackend/app.go`.

#### iTop (`--provider itop`)

Reads every Server, Virtual Machine, PC and Network Device in the instance through the REST API (version 1.4, iTop 2.7 or later). The user needs the REST Services User profile and read access to those classes.

```bash
./barbackend source add --customer <customer-uuid> --provider itop \
  --settings '{"url": "https://itop.example.com", "auth": {"mode": "basic", "user": "barb-reader", "password_env": "ITOP_PASSWORD"}}'
```

- `url`: the iTop root, with or without a path (`https://example.com/itop`); no credentials, query or fragment.
- `auth.mode: "basic"`: `user` and `password_env`, the environment variable holding the password.
- `auth.mode: "token"`: `token_env`, the environment variable holding a token from the authent-token extension.

Settings are stored in plain text, so they only name the variables. Secrets are read when `sync` runs, so the variable must be set in the process that syncs, not the one that adds the source.

### Sync a CMDB Source

```bash
./barbackend sync --source <source-uuid>
```

Prints the outcome of the Sync Run, its counts (created, updated, deactivated, reactivated, skipped), and each Skipped Record with its reason. Interrupting with Ctrl-C still records the failed Sync Run.

## Development

```bash
go test -race ./...                                   # tests, embedded Postgres downloaded on first run
go tool -modfile=tools.mod sqlc generate              # after editing migrations or queries
go tool -modfile=tools.mod sqlc diff                  # check generated code is up to date (CI)
go tool -modfile=tools.mod golangci-lint run ./...    # lint (CI)
go tool -modfile=tools.mod govulncheck ./...          # vulnerability check
```

- Migrations (goose): `internal/postgres/migrations`
- Queries (sqlc): `internal/postgres/queries`. Never edit the generated `internal/postgres/sqlcgen`.
- Integration tests use `internal/postgres/pgtest`: call `pgtest.Main` from the package's `TestMain` and `pgtest.NewDB(t)` for a fresh database per test.
