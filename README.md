# barbackend

Backend for barbattack. It keeps the asset inventory: it registers CMDB Sources and Syncs their records into Postgres as Assets.

Domain terms are defined in [`GLOSSARY.md`](GLOSSARY.md), design decisions in [`docs/adr/`](docs/adr/), and code conventions in [`CODING_STANDARDS.md`](CODING_STANDARDS.md).

## Requirements

- Go (version in `go.mod`)
- Postgres 15 for running the CLI. Tests start their own embedded Postgres.

## Running

```bash
go build ./cmd/barbackend

# migrate and serve need a database
export DATABASE_URL="postgres://user:pass@localhost:5432/barbackend?sslmode=disable"
# serve seals and opens CMDB Source credentials with this key (ADR 0012)
export CREDENTIALS_KEY="$(openssl rand -base64 32)"
# the Cognito user pool Users sign in with (ADR 0013); serve also needs the app client
export COGNITO_REGION=us-east-1
export COGNITO_USER_POOL_ID=<pool-id>
export COGNITO_CLIENT_ID=<app-client-id>
# browser origins allowed to call the HTTP API, comma-separated
export CORS_ALLOWED_ORIGINS=http://localhost:5173

./barbackend migrate   # apply migrations in internal/postgres/migrations
./barbackend serve     # HTTP server (gin, :8080 unless PORT is set)
./barbackend create-platform-admin <email>   # invite the first Platform Admin
```

`create-platform-admin` creates the user in Cognito, which emails the invitation, so it needs AWS credentials allowed to call `AdminCreateUser` and `AdminDeleteUser` on the pool, from the default AWS credential chain. The pool itself is created by Terraform outside this repo.

### Container image

The `Dockerfile` builds an image with the static binary and CA certificates only, running as a non-root user with Gin in release mode. `serve` is the default command, and any other command replaces it.

```bash
docker build -t barbackend .
# both architectures, as CI builds them
docker buildx build --platform linux/amd64,linux/arm64 -t barbackend .

docker run --rm --env-file barbackend.env barbackend migrate   # before every deploy; safe to repeat
docker run -d --restart unless-stopped -p 8080:8080 --env-file barbackend.env barbackend
docker run --rm --env-file barbackend.env barbackend create-platform-admin <email>
```

`barbackend.env` holds the variables above as plain `KEY=value` lines: Docker reads no `export` and no quotes. Health checks go to `GET /ping`, as the image has no shell for a `HEALTHCHECK`.

On EC2, give the instance a role allowed to call `AdminCreateUser` and `AdminDeleteUser` on the pool, and leave AWS keys out of the env file: the SDK falls back to the instance role. With IMDSv2, the container is one network hop further from the metadata service, so set the instance's metadata hop limit to at least 2 (`http_put_response_hop_limit = 2` in Terraform), or Cognito admin calls fail to get credentials.

### HTTP API

Every error answers `{code, error}`: `code` is stable for the dashboard to translate, and `error` is readable on its own.

Every endpoint below except `/ping` needs `Authorization: Bearer <Cognito access token>`, and acts for the Customer of the User it signs in. A missing or invalid token, or one of a disabled User, answers 401 `unauthenticated`: the dashboard should send the User to sign in again. A valid token of a User of a Deactivated Customer answers 403 `customer_deactivated`, as does a request that finds its Customer deactivated while it runs: signing in again would not help. A Platform Admin, who belongs to no Customer, answers 403 `forbidden`.

The OpenAPI 3.1 spec is served at `/openapi.json` and `/openapi.yaml`, with a browsable reference at `/docs`.

- `GET /ping`: liveness.
- `GET /me`: the signed-in User as `{id, email, role, customer}`, where `role` is `platform_admin`, `customer_admin` or `viewer` and `customer` is `{id, name}`, or `null` for a Platform Admin. Unlike every other endpoint, a Platform Admin gets 200, not 403.
- `GET /cmdb/source`: the Customer's Connected CMDB Source as `{provider, url, user, last_sync, last_sync_failure}`, or `null` if none is connected. `last_sync` is when the latest successful Sync Run finished; `last_sync_failure` is `{at, error}` while the latest Sync Run is a failed one. Credentials are never returned.
- `POST /cmdb/source`: connects a CMDB Source from `{provider, url, user, password}`. It checks the login against the CMDB, stores the source with encrypted credentials, runs the first Sync under the same limits as `POST /cmdb/source/sync`, and answers as `GET /cmdb/source`. A failed first Sync still answers 200, with `last_sync: null` and `last_sync_failure` set, and the source stays connected. Answers 400 `invalid_request` for an invalid body, 400 `invalid_login` for an unknown provider or a login it rejects without reaching the CMDB, 409 `already_connected` if a source is already connected, and 422 with the CMDB's failure code when the CMDB rejects the login, storing nothing.
- `PUT /cmdb/source`: replaces the login of the Connected CMDB Source with `{url, user, password}`, such as after a password rotation. The source keeps its provider. It checks the login against the CMDB, then replaces the settings and encrypted credentials of the same source, keeping its Assets and their Declarations, and answers as `GET /cmdb/source`. It runs no Sync. Answers 400 `invalid_request` or `invalid_login` as `POST /cmdb/source` does, 404 `not_connected` if no source is connected, and 422 with the CMDB's failure code when the CMDB rejects the login, changing nothing.
- `DELETE /cmdb/source`: disconnects the Connected CMDB Source, deleting nothing: the source and its Assets stay stored, its Assets become Inactive, and a Sync of it is refused from then on. Connecting again creates a new CMDB Source. Answers 204, 404 `not_connected` if no source is connected, and 409 `sync_in_progress` while a Sync of it commits.
- `POST /cmdb/source/sync`: runs a Sync of the Connected CMDB Source and answers `{last_sync, created, updated, deactivated, reactivated, skipped}`. The Sync outlives its request and is cancelled only by a 5-minute limit or server shutdown. Answers 404 `not_connected` if no source is connected, 409 `sync_in_progress` while another Sync of it runs, and 502 when the Sync fails, which is recorded as a failed Sync Run. Its code is the CMDB's failure code, such as `invalid_credentials` after a password rotation, or `sync_failed` when the CMDB Provider did not classify why.

- `GET /prioritizations`: the Customer's Prioritizations, newest first, as `{id, created_at, findings, groups}`. The newest is the order to follow. Takes `limit`.
- `GET /prioritizations/{id}`: one Prioritization: its `groups` in the order to attend them, each `{position, title, reason, finding_ids, evidence}`; its `findings`, each with its `score`, its `score_rank` by Score alone, its `group` and its `dossier`, whose shape is not a contract; the newest Action Plan of each Finding that has one in `plans`; and its `feedback`. Answers 404 `prioritization_not_found`.
- `POST /prioritizations/{id}/plans`: has Luna write the Action Plan of `{finding_id}` and answers 201 with it, which can take a minute. Answers 404 `prioritization_not_found` or `finding_not_found`, and 502 `agent_refused`, `agent_rejected` or `agent_unavailable` when Luna has no verified answer, storing nothing.
- `POST /prioritizations/{id}/feedback`: records `{finding_id, verdict, note}`, where `verdict` is `applies`, `does_not_apply`, `remediated`, `should_be_earlier` or `should_be_later`. It changes no Score and no order.
- `POST /analista/conversations`: starts a conversation with the Analista from `{message}` and answers 201 with `{conversation_id, reply}`.
- `POST /analista/conversations/{id}/messages`: sends `{message}` in one of the User's conversations. Answers 404 `conversation_not_found`, 409 `conversation_busy` while it answers another message, refused without calling the model, and 409 `conversation_full` after 40 turns. A server that dies mid-answer leaves that conversation busy for up to 10 minutes. Both Analista endpoints answer 502 `agent_refused` or `agent_unavailable` when the model does not answer, storing nothing. A `reply`, like all other Agent text, comes from a model: render it as plain text.

- `GET /business-context`: the newest version of the Customer's Business Context as `{version, saved_at, saved_by, context, key_fields, gaps}`, version 0 with nothing stated until one is saved. `context` is the `business_context/1` document: `profile`, `geography`, `operations`, `footprint` and `risk`, where blank text, a blank code or an empty list means not stated; `gaps` are the `key_fields` not stated. Every User of the Customer reads it.
- `PUT /business-context`: a Customer Admin saves `{version, context}`, the whole document, as the version after `version`, the one read. Answers 400 `invalid_request` naming each field that breaks a rule, and 409 `business_context_stale` when another save came first, saving nothing.
- `GET /business-context/brief`: the newest version as Markdown, for a model's prompt or a person, with the version as its ETag. Every field has a line, and one not stated says so.
- `POST /business-context/draft`: a Customer Admin gives `{text, files}`, either or both, where each file is `{name, media_type, data}` with `data` in base64: text, Markdown, CSV, JSON, PDFs or `.docx`, up to 10 files, 10 MB each and 20 MB together. The Drafter reads them together and answers `{context, gaps}`, which can take a minute, and nothing is saved. Answers 400 `invalid_document` for a document it cannot read, and 502 `agent_refused`, `agent_rejected` or `agent_unavailable` without a verified draft.

Run `./barbackend` with no arguments to print the usage.

## Agents

The Prioritizer, Luna (Advisor), the Analista (feedback) and the Drafter (Business Context) run on Anthropic's models; `docs/adr/0016-the-prioritizer-orders-findings-from-their-dossiers.md` explains what they read and how they are kept honest, and `docs/adr/0017-the-business-context-is-a-versioned-document-the-customer-states.md` what the Drafter reads. They need credentials, usually `ANTHROPIC_API_KEY`. No Agent reads a Feed: the Findings pipeline hands them one Dossier per Finding, in the shape of `docs/examples/findings.json`. Until that pipeline exists, `agent finding` builds one from the live Feeds. What they still lack, starting with each Customer's business context in the Prioritizer's criterion, is in `docs/agents-pending.md`.

```sh
# The Dossier of one Finding, from the live Feeds. Collect several into a JSON list.
./barbackend agent finding --asset docs/examples/asset.json --component PostgreSQL --cve CVE-2025-1094 --id f-1

# Prioritize the Findings of a file, and with --plans have Luna write each Action Plan. Needs no database and stores nothing.
./barbackend agent run --findings docs/examples/findings.json --plans

# The same for a Customer, acting as one of its Users, storing the Prioritization; then an Action Plan. These need DATABASE_URL.
./barbackend agent prioritize --as <email> --findings docs/examples/findings.json
./barbackend agent plan --as <email> --prioritization <id> --finding f-1

# Talk with the Analista. Pass the printed conversation id to continue.
./barbackend agent ask --as <email> "¿qué atiendo primero?"
./barbackend agent ask --as <email> --conversation <id> "el de lab-01 debería ir antes, ahí corre la nómina"
```

## Findings

`serve` turns Feeds and Syncs into Findings, one per Asset, Product and CVE (`docs/adr/0020-findings-are-opened-and-closed-never-deleted.md`). Each NVD pull matches its CVEs against the Software Components of every Active Asset (`docs/adr/0015-vulnerabilities-matched-by-product-and-version.md`); a match stores the CVE and opens, updates or reopens its Finding, scored with Scoring Model 1 (`docs/adr/0009-findings-scored-by-versioned-two-layer-model.md`). KEV and EPSS pulls rescore the open Findings of the CVEs already stored, and ignore every other CVE. After each successful Sync, the CMDB Source's Assets are matched again against the stored CVEs: Findings that no longer match are closed with a reason, and new Assets get theirs. `feed pull` only counts what each Feed returns and stores nothing.

Only Software Components with a Product match, written as NVD's CPE vendor and product tokens in the CMDB (`docs/adr/0019-software-components-take-their-product-from-the-cmdb-in-cpe-terms.md`): in iTop, the Software linked to each SoftwareInstance.

## CMDB Sources

A CMDB Source is connected and synced through the HTTP API above. Its credentials are stored encrypted with `CREDENTIALS_KEY`. Keep that key safe: credentials stored with a lost key cannot be recovered, and their sources must be connected again. `serve` refuses to start without it, and a Sync with another key fails and is recorded as a failed Sync Run.

Providers are registered in `providers()` in `cmd/barbackend/app.go`.

### iTop (`"provider": "itop"`)

Reads every Server, Virtual Machine, PC and Network Device in the instance through the REST API (version 1.4, iTop 2.7 or later), with basic auth. The user needs the REST Services User profile and read access to those classes. `url` is the iTop root, with or without a path (`https://example.com/itop`), and no credentials, query or fragment.

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
