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
# the Slack app Customers install from the portal (ADR 0029); the redirect
# URI must be registered in the Slack app and end in /slack/install/callback
export SLACK_CLIENT_ID=<client-id>
export SLACK_CLIENT_SECRET=<client-secret>
export SLACK_REDIRECT_URI=https://api.example.com/slack/install/callback

./barbackend migrate   # apply migrations in internal/postgres/migrations
./barbackend serve     # HTTP server (gin, :8080 unless PORT is set)
./barbackend create-platform-admin <email>   # invite the first Platform Admin
```

`create-platform-admin` stores the Platform Admin and has Cognito email their Invitation, so it needs AWS credentials allowed to call `AdminCreateUser` and `AdminGetUser` on the pool, from the default AWS credential chain. The pool itself is created by Terraform outside this repo.

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

On EC2, give the instance a role allowed to call `AdminCreateUser` and `AdminGetUser` on the pool, and leave AWS keys out of the env file: the SDK falls back to the instance role. With IMDSv2, the container is one network hop further from the metadata service, so set the instance's metadata hop limit to at least 2 (`http_put_response_hop_limit = 2` in Terraform), or Cognito admin calls fail to get credentials.

### HTTP API

Every error answers `{code, error}`: `code` is stable for the dashboard to translate, and `error` is readable on its own.

Every endpoint below except `/ping` and the Slack install callback (`/slack/install/callback`, where Slack redirects the popup) needs `Authorization: Bearer <Cognito access token>`, and acts for the Customer of the User it signs in. A missing or invalid token, or one of a disabled User, answers 401 `unauthenticated`: the dashboard should send the User to sign in again. A valid token of a User of a Deactivated Customer answers 403 `customer_deactivated`, as does a request that finds its Customer deactivated while it runs: signing in again would not help. A Platform Admin, who belongs to no Customer, answers 403 `forbidden`.

The OpenAPI 3.1 spec is served at `/openapi.json` and `/openapi.yaml`, with a browsable reference at `/docs`. It is generated from the handlers (ADR 0014), so it is the authoritative, always-current list of endpoints, their request and response shapes, and their error codes. `GET /ping` is the liveness probe, and `GET /me` returns the signed-in User; browse `/docs` for the rest.

Run `./barbackend` with no arguments to print the usage.

## Agents

The Prioritizer, Luna (Advisor), the Analista (feedback), the Drafter (Business Context) and the Cartógrafo (ATT&CK Techniques of a Vulnerability, `docs/adr/0024-the-cartografo-labels-vulnerabilities-with-attack-techniques.md`) run on Anthropic's models; `docs/adr/0016-the-prioritizer-orders-findings-from-their-dossiers.md` explains what they read and how they are kept honest, and `docs/adr/0017-the-business-context-is-a-versioned-document-the-customer-states.md` what the Drafter reads. They need credentials, usually `ANTHROPIC_API_KEY`. No Agent that weighs a Finding reads a Feed: each Dossier is built from what the Findings pipeline stored, with the Finding's latest Score, its Vulnerability's Advisories, ATT&CK Techniques and Mitigations, and the Critical Services of the Business Context that run its Asset, in the shape of `docs/examples/findings.json`. Two more Agents are designed but not built (`docs/adr/0025-news-items-are-read-once-and-matched-to-customers-by-rules.md`): the Reader, which reads each News Item once for every Customer, and the Editor, which writes each Customer's News Digest from what rules found relevant. What they still lack is in `docs/agents-pending.md`.

`serve` keeps one lasting order per Customer (`docs/adr/0026-the-prioritizer-keeps-one-lasting-order-per-customer.md`). A Feed batch, a Sync, a Business Context save, a User's Feedback on the order or a Cartógrafo run that labels something wakes the Prioritizer, which waits until changes stop for 2 minutes, or 15 at most, and runs a round for each Customer with something to place, one Customer after another in turns: open Findings without a place, and those that changed since they were placed, up to 100 a request. Every other open Finding keeps its place, and a closed one leaves the order without a request. It also runs every 6 hours, to try again after a round that failed.

```sh
# Order the Findings of a file, and with --plans have Luna write each Action Plan. Needs no database and stores nothing.
./barbackend agent run --findings docs/examples/findings.json --plans

# Run the rounds a Customer needs now, as serve does when its Findings change, acting as one of its Users; then an Action Plan. These need DATABASE_URL.
./barbackend agent prioritize --as <email>
./barbackend agent plan --as <email> --prioritization <id> --finding <finding id>

# Talk with the Analista. Pass the printed conversation id to continue.
./barbackend agent ask --as <email> "¿qué atiendo primero?"
./barbackend agent ask --as <email> --conversation <id> "el de lab-01 debería ir antes, ahí corre la nómina"

# Label the stored Vulnerabilities with ATT&CK Techniques now, as serve does daily, within the same cap of 50 a day. Needs DATABASE_URL.
./barbackend agent label
```

## Findings

`serve` turns Feeds and Syncs into Findings, one per Asset, Product and CVE (`docs/adr/0020-findings-are-opened-and-closed-never-deleted.md`). Each NVD pull matches its CVEs against the Software Components of every Active Asset (`docs/adr/0015-vulnerabilities-matched-by-product-and-version.md`); a match stores the CVE and opens, updates or reopens its Finding, scored with Scoring Model 2 (`docs/adr/0009-findings-scored-by-versioned-two-layer-model.md`, with the Lifecycle Stage multiplier of `docs/adr/0028-the-lifecycle-stage-is-imported-from-itop-and-scored.md`). KEV and EPSS pulls rescore the open Findings of the CVEs already stored, and ignore every other CVE. After each successful Sync, the CMDB Source's Assets are matched again against the stored CVEs: Findings that no longer match are closed with a reason, and new Assets get theirs. `feed pull` only counts what each Feed returns and stores nothing.

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
