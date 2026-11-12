# Packages are layered by role, and depguard enforces the direction

Packages are split by role, not by feature, and each layer may only import the layers below it:

```
cmd/barbackend/        flags, usage, wiring only
internal/
  httpapi/             router + handlers           -> use-case packages, inventory, tenancy
  users/               use cases on Users          -> cognito, postgres, tenancy
  assets/              use cases on Assets         -> inventory, postgres, tenancy
  areas/               use cases on Areas          -> inventory, postgres, tenancy
  cmdb/                use cases on CMDB Sources   -> cmdb/provider, encryption, inventory, postgres
    provider/          CMDB Provider seam          -> inventory
      <provider>/      adapters                    -> cmdb/provider, inventory, own subpackages
  agents/              use case on the Agents      -> assessment, business, claude, inventory, postgres, tenancy
  businesscontext/     use cases on the Business Context -> business, postgres, tenancy
  findings/            use case turning Feeds and Syncs into Findings -> finding, inventory, matching, postgres, scoring, stixext
  advisories/          use case linking Advisories to Vulnerabilities -> postgres, stixext
  techniques/          use case keeping the ATT&CK catalog -> postgres
  ingest/              use case polling Feeds      -> feeds, stixext
  feeds/               Feed seam                   -> stixext
    httpx/             shared HTTP client setup    -> nothing internal
    <feed>/            adapters                    -> feeds, httpx, stixext
  claude/              Anthropic adapter           -> nothing internal
  cognito/             Cognito adapter             -> tenancy
  encryption/          sealing credentials         -> nothing internal
  postgres/            all persistence             -> assessment, business, finding, inventory, matching, scoring, tenancy
  finding/             pure domain                 -> inventory, matching, scoring, stixext
  matching/            pure domain                 -> inventory, stixext
  assessment/          pure domain                 -> inventory, scoring, stixext
  business/            pure domain                 -> nothing internal
  scoring/             pure domain                 -> inventory
  stixext/             barbattack's STIX conventions -> nothing internal
  inventory/           pure domain                 -> tenancy
  tenancy/             pure domain                 -> nothing internal
```

A use case is a package that orchestrates the domain, persistence and adapters; transports (the CLI, `httpapi`) only call use cases, and only `cmd` wires them together. The domain does no I/O, so its rules stay testable without a database (ADR 0005). Adapters never depend on persistence, so adding a CMDB Provider never pulls in Postgres (ADR 0007). Persistence depends only on the domain, so a use case can never be reached from below.

Everything about CMDBs lives under `internal/cmdb`, but the use case and the seam stay separate packages: the use case is `cmdb` itself, and the seam is `cmdb/provider`, below it. The seam cannot be the use case's package, because adapters import the seam and would then pull in Postgres. Go import paths carry no direction, so the nesting is only a home; `depguard` keeps `cmdb/provider` from importing `cmdb`.

New features get a home before they get code:

- **Declarations**: the use-case package `internal/assets`, which already lists Assets, with its queries in `postgres`.
- **Areas**: the use-case package `internal/areas`, which lists a Customer's Areas and states their Area Owners, with its queries in `postgres`. The Sync that imports Areas stays in `internal/cmdb` (ADR 0018).
- **Slack alerts**: an adapter under `internal/slack`, called from an alerting use-case package.
- **Customers and Users**: Customer, User and Role are a pure domain package, `internal/tenancy`, which takes `CustomerID` out of `inventory`. It sits below `inventory`, since every CMDB Source belongs to a Customer, so it cannot also hold the use cases: they call `postgres`, which stores Users and so imports `tenancy`. Authenticating and creating Users is the use-case package `internal/users`, which also manages Customers, since creating a Customer creates its first Customer Admin in the same transaction, and Cognito is an adapter, `internal/cognito`, that `users` calls (ADR 0013).
- **Threat matching**: the pure domain package `internal/matching`, which imports `inventory` and reads Feed objects through `stixext` (ADR 0010), never the reverse.
- **Findings**: the pure domain package `internal/finding` holds what identifies a Finding, what a match makes of it and why it is closed, so `postgres` can store it; the use-case package `internal/findings` reacts to Feeds and Syncs by calling `matching`, `scoring` and `postgres` (ADR 0020).
- **Advisories**: the use-case package `internal/advisories` keeps the Advisories that name a stored Vulnerability and links them by CVE, with its queries in `postgres` (ADR 0022). It is not part of `internal/findings`, which turns Feeds into Findings: an Advisory is about a Vulnerability, not a Finding.
- **ATT&CK catalog**: the use-case package `internal/techniques` stores the Techniques, Mitigations and their relationships from the ATT&CK Feed and reads a Technique across ATT&CK versions, with its queries in `postgres` (ADR 0023).
- **Business Context**: the pure domain package `internal/business`, which imports no other layer, and the use-case package `internal/businesscontext`, which reads and saves it. The Drafter is an Agent, so it lives in `internal/agents`, which reads the Business Context through `postgres`, never through `businesscontext` (ADR 0017).
- **News Items**: Feed adapters like any other, `internal/feeds/rss` for every text Feed and one package per structured Feed. The use-case package `internal/newsitems` stores what they emit through `ingest.Feed.Handle`, as `internal/advisories` does for Advisories, with its queries in `postgres`. The pure domain package `internal/news` holds the News Item, the Reported Attack, the rules of Relevance and the Reader's verifier, and imports `business`, `inventory` and `stixext`. The Reader and the Editor are Agents, so they live in `internal/agents` (ADR 0025).

The direction is enforced by `depguard` rules in `.golangci.yaml`, which deny all of `barbackend/internal` to a layer and allow back only the layers below it, so a new use-case package is forbidden to `inventory`, `cmdb/provider` and `postgres` without touching the config. `internal/httpapi` may import only the domain packages `inventory`, `tenancy` and `business` and the use-case packages it serves, listed by name, so serving a new use case means adding it to that list. It is denied `cmdb/provider` by name, since allowing `cmdb` would otherwise allow everything under it; for the same reason, every layer allowed `business` is denied `businesscontext` by name. Its tests are exempt, because they wire a real router on Postgres as `cmd` does, and so are those of `internal/agents`, which store Findings and Scores as the Findings pipeline does (ADR 0026). Only `cmd` and `internal/httpapi` may import gin.

## Considered Options

- **Document the layering only in `AGENTS.md`**: rejected; a paragraph drifts and nothing fails when a handler calls `postgres` directly.
- **Merge the CMDB use case into the seam's package**: rejected; every adapter would import Postgres through it (ADR 0007).
- **Keep the use case in a sibling package (`internal/sources`, then `internal/cmdbsources`)**: rejected; the seam took the name `cmdb`, so the package callers use most had the less obvious name, and "source" alone is the word the glossary avoids for Feeds.
- **Make `internal/tenancy` both the Customer domain and the use cases on Users**: rejected; `inventory` and `postgres` need `CustomerID` and the User types, so the package would import `postgres` while `postgres` imports it.
