# barbackend

Backend for barbattack. It syncs each Customer's CMDB into an asset inventory, matches the inventory against threat-intelligence Feeds to open scored Findings, has AI Agents prioritize and explain those Findings, and serves everything over an HTTP API.

## Quick start

Requirements: Go (version in `go.mod`) and Postgres 15.

```bash
cp .env.example .env   # fill in the values, see Configuration
source .env
go build ./cmd/barbackend
./barbackend migrate
./barbackend serve     # :8080 unless PORT is set
```

Check it is up with `curl localhost:8080/ping`, and browse the API at `http://localhost:8080/docs`.

## Configuration

All configuration is read from the environment. `.env.example` lists every variable with a short note.

| Variable | Required | Purpose |
|---|---|---|
| `DATABASE_URL` | yes | Postgres connection string |
| `CREDENTIALS_KEY` | `serve` | Encrypts CMDB Source credentials (`openssl rand -base64 32`). A lost key cannot be recovered: its sources must be connected again |
| `COGNITO_REGION`, `COGNITO_USER_POOL_ID`, `COGNITO_CLIENT_ID` | `serve` | The Cognito user pool Users sign in with |
| `CORS_ALLOWED_ORIGINS` | `serve` | Comma-separated browser origins allowed to call the API |
| `SLACK_CLIENT_ID`, `SLACK_CLIENT_SECRET`, `SLACK_REDIRECT_URI` | `serve` | The Slack app Customers install. The redirect URI must end in `/slack/install/callback` |
| `PORTAL_URL` | `serve` | The portal every Slack Alert links to |
| `ANTHROPIC_API_KEY` | for Agents | Without it the API still serves, and Agent requests answer 502 |
| `PORT` | no | HTTP port, default `8080` |
| `NVD_API_KEY` | no | Raises NVD's rate limit |
| `RANSOMWARELIVE_ENABLED` | no | Polls Ransomware.live. Enable only with its owner's written approval: its terms forbid commercial use without it |
| `<AGENT>_MODEL` | no | Overrides an Agent's model, e.g. `LUNA_MODEL` (see `internal/agents/crew.go`) |

`create-platform-admin` also needs AWS credentials allowed to call `AdminCreateUser` and `AdminGetUser` on the pool, from the default AWS credential chain.

## Usage

Run `./barbackend` with no arguments for the full usage.

| Command | What it does |
|---|---|
| `migrate` | Apply database migrations. Safe to repeat |
| `serve` | Run the HTTP API, Feed polling, Syncs and the Agents |
| `create-platform-admin <email>` | Invite the first Platform Admin through Cognito |
| `feed pull [--feed <name>]` | Pull Feeds and count what they return, storing nothing |
| `agent <subcommand>` | Run an Agent by hand: `run`, `prioritize`, `plan`, `ask`, `label`, `news` |

`agent run --findings docs/examples/findings.json --plans` needs no database, which makes it the quickest way to try the Agents.

### HTTP API

The OpenAPI 3.1 spec is generated from the handlers and is the authoritative reference: `/openapi.json`, `/openapi.yaml`, and a browsable version at `/docs`.

Every endpoint except `/ping` and `/slack/install/callback` needs `Authorization: Bearer <Cognito access token>`. Errors answer `{code, error}`, where `code` is stable for clients to branch on.

### CMDB providers

| Provider | Notes |
|---|---|
| iTop (`itop`) | REST API 1.4, iTop 2.7 or later, basic auth. The user needs the REST Services User profile and read access to Servers, Virtual Machines, PCs and Network Devices |

Providers are registered in `providers()` in `cmd/barbackend/app.go`.

## Deployment

The `Dockerfile` builds a minimal non-root image (static binary and CA certificates only) whose default command is `serve`.

```bash
docker build -t barbackend .
docker run --rm --env-file barbackend.env barbackend migrate
docker run -d -p 8080:8080 --env-file barbackend.env barbackend
```

The env file takes plain `KEY=value` lines, with no `export` or quotes. The image has no shell, so health checks go to `GET /ping`.

Merging into `main` deploys to production: CI builds the arm64 image, pushes it to ECR and runs `barbackend-deploy` on the EC2 instance through SSM (`.github/workflows/ci.yml`). On EC2, give the instance a role allowed to call the Cognito admin APIs instead of putting AWS keys in the env file, and set the IMDSv2 metadata hop limit to at least 2 so the container can reach the instance role.

## Development

```bash
go test -race ./...                                   # tests, embedded Postgres downloaded on first run
go tool -modfile=tools.mod sqlc generate              # after editing migrations or queries
go tool -modfile=tools.mod sqlc diff                  # check generated code is up to date (CI)
go tool -modfile=tools.mod golangci-lint run ./...    # lint (CI)
go tool -modfile=tools.mod deadcode ./...             # functions only tests reach (CI)
go tool -modfile=tools.mod govulncheck ./...          # vulnerability check
```

Dev tools are pinned in `tools.mod`, so always run them through `go tool -modfile=tools.mod`. Migrations live in `internal/postgres/migrations` (goose) and queries in `internal/postgres/queries` (sqlc); never edit the generated `internal/postgres/sqlcgen`.

Branch off `dev` and open pull requests against it. `main` only moves on a release.

## Documentation

- [`GLOSSARY.md`](GLOSSARY.md): domain terms (Asset, Finding, Feed, Customer, ...)
- [`docs/adr/`](docs/adr/): design decisions, including how Findings are scored and how each Agent works
- [`CODING_STANDARDS.md`](CODING_STANDARDS.md): code conventions
- [`AGENTS.md`](AGENTS.md): project map and instructions for coding agents
- [`docs/agents-pending.md`](docs/agents-pending.md): what the Agents still lack
