# barbackend

Backend for barbattack. It keeps the asset inventory: it registers CMDB Sources and Syncs their records into Postgres as Assets.

Domain terms are defined in [`GLOSSARY.md`](GLOSSARY.md), design decisions in [`docs/adr/`](docs/adr/), and code conventions in [`CODING_STANDARDS.md`](CODING_STANDARDS.md).

## Requirements

- Go (version in `go.mod`)
- Postgres 15 for running the CLI. Tests start their own embedded Postgres.

## Running

```bash
go build ./cmd/barbackend

# migrate, serve, source and sync need a database
export DATABASE_URL="postgres://user:pass@localhost:5432/barbackend?sslmode=disable"
# serve, source and sync seal and open CMDB Source credentials with this key (ADR 0012)
export CREDENTIALS_KEY="$(openssl rand -base64 32)"
# serve acts for this Customer until authentication exists, so it is for local dev only
export CUSTOMER_ID=<customer-uuid>
# browser origins allowed to call the HTTP API, comma-separated
export CORS_ALLOWED_ORIGINS=http://localhost:5173

./barbackend migrate   # apply migrations in internal/postgres/migrations
./barbackend serve     # HTTP server (gin, :8080 unless PORT is set)
```

### HTTP API

Every error answers `{code, error}`: `code` is stable for the dashboard to translate, and `error` is readable on its own.

- `GET /ping`: liveness.
- `GET /cmdb/source`: the Customer's Connected CMDB Source as `{provider, url, user, lastSync, lastSyncFailure}`, or `null` if none is connected. `lastSync` is when the latest successful Sync Run finished; `lastSyncFailure` is `{at, error}` while the latest Sync Run is a failed one. Credentials are never returned.
- `POST /cmdb/source`: connects a CMDB Source from `{provider, url, user, password}`. It checks the login against the CMDB, stores the source with encrypted credentials, runs the first Sync under the same limits as `POST /cmdb/source/sync`, and answers as `GET /cmdb/source`. A failed first Sync still answers 200, with `lastSync: null` and `lastSyncFailure` set, and the source stays connected. Answers 400 `invalid_request` for an invalid body, 400 `invalid_login` for an unknown provider or a login it rejects without reaching the CMDB, 409 `already_connected` if a source is already connected, and 422 with the CMDB's failure code when the CMDB rejects the login, storing nothing.
- `PUT /cmdb/source`: replaces the login of the Connected CMDB Source with `{url, user, password}`, such as after a password rotation. The source keeps its provider. It checks the login against the CMDB, then replaces the settings and encrypted credentials of the same source, keeping its Assets and their Declarations, and answers as `GET /cmdb/source`. It runs no Sync. Answers 400 `invalid_request` or `invalid_login` as `POST /cmdb/source` does, 404 `not_connected` if no source is connected, and 422 with the CMDB's failure code when the CMDB rejects the login, changing nothing.
- `DELETE /cmdb/source`: disconnects the Connected CMDB Source, deleting nothing: the source and its Assets stay stored, its Assets become Inactive, and a Sync of it is refused from then on. Connecting again creates a new CMDB Source. Answers 204, 404 `not_connected` if no source is connected, and 409 `sync_in_progress` while a Sync of it commits.
- `POST /cmdb/source/sync`: runs a Sync of the Connected CMDB Source and answers `{lastSync, created, updated, deactivated, reactivated, skipped}`. The Sync outlives its request and is cancelled only by a 5-minute limit or server shutdown. Answers 404 `not_connected` if no source is connected, 409 `sync_in_progress` while another Sync of it runs, and 502 when the Sync fails, which is recorded as a failed Sync Run. Its code is the CMDB's failure code, such as `invalid_credentials` after a password rotation, or `sync_failed` when the CMDB Provider did not classify why.

Run `./barbackend` with no arguments to print the usage.

## Flows

### Add a CMDB Source

```bash
./barbackend source add \
  --customer <customer-uuid> \
  --provider <provider-id> \
  --settings '<json>' < credentials.json
```

Settings are plain JSON and hold no secret. The credentials are a JSON document read from stdin, so secrets stay out of the process list and shell history. The provider validates both before the source is stored, and the credentials are stored encrypted with `CREDENTIALS_KEY`. Prints the new CMDB Source ID.

Keep `CREDENTIALS_KEY` safe: credentials stored with a lost key cannot be recovered, and their sources must be added again. `serve`, `source` and `sync` refuse to start without it. A Sync with another key fails and is recorded as a failed Sync Run.

Providers are registered in `providers()` in `cmd/barbackend/app.go`.

#### iTop (`--provider itop`)

Reads every Server, Virtual Machine, PC and Network Device in the instance through the REST API (version 1.4, iTop 2.7 or later). The user needs the REST Services User profile and read access to those classes.

```bash
jq -n --arg password "$ITOP_PASSWORD" '{$password}' | ./barbackend source add --customer <customer-uuid> --provider itop \
  --settings '{"url": "https://itop.example.com", "auth": {"mode": "basic", "user": "barb-reader"}}'
```

- `url`: the iTop root, with or without a path (`https://example.com/itop`); no credentials, query or fragment.
- `auth.mode: "basic"`: settings take `user`, credentials are `{"password": "..."}`.
- `auth.mode: "token"`: settings take nothing else, credentials are `{"token": "..."}`, a token from the authent-token extension.

To type the password instead, run the command without a pipe, enter `{"password": "..."}` and press Ctrl-D.

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
