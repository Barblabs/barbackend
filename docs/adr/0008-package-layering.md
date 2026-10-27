# Packages are layered by role, and depguard enforces the direction

Packages are split by role, not by feature, and each layer may only import the layers below it:

```
cmd/barbackend/        flags, usage, wiring only
internal/
  httpapi/             router + handlers           -> use-case packages, inventory, tenancy
  users/               use cases on Users          -> cognito, postgres, tenancy
  cmdb/                use cases on CMDB Sources   -> cmdb/provider, encryption, inventory, postgres
    provider/          CMDB Provider seam          -> inventory
      <provider>/      adapters                    -> cmdb/provider, inventory, own subpackages
  cognito/             Cognito adapter             -> tenancy
  encryption/          sealing credentials         -> nothing internal
  postgres/            all persistence             -> inventory, tenancy
  inventory/           pure domain                 -> tenancy
  tenancy/             pure domain                 -> nothing internal
```

A use case is a package that orchestrates the domain, persistence and adapters; transports (the CLI, `httpapi`) only call use cases, and only `cmd` wires them together. The domain does no I/O, so its rules stay testable without a database (ADR 0005). Adapters never depend on persistence, so adding a CMDB Provider never pulls in Postgres (ADR 0007). Persistence depends only on the domain, so a use case can never be reached from below.

Everything about CMDBs lives under `internal/cmdb`, but the use case and the seam stay separate packages: the use case is `cmdb` itself, and the seam is `cmdb/provider`, below it. The seam cannot be the use case's package, because adapters import the seam and would then pull in Postgres. Go import paths carry no direction, so the nesting is only a home; `depguard` keeps `cmdb/provider` from importing `cmdb`.

New features get a home before they get code:

- **Declarations**: a use-case package such as `internal/assets`, with its queries in `postgres`.
- **Slack alerts**: an adapter under `internal/slack`, called from an alerting use-case package.
- **Customers and Users**: Customer, User and Role are a pure domain package, `internal/tenancy`, which takes `CustomerID` out of `inventory`. It sits below `inventory`, since every CMDB Source belongs to a Customer, so it cannot also hold the use cases: they call `postgres`, which stores Users and so imports `tenancy`. Authenticating and creating Users is the use-case package `internal/users`, which also manages Customers, since creating a Customer creates its first Customer Admin in the same transaction, and Cognito is an adapter, `internal/cognito`, that `users` calls (ADR 0013).
- **Threat matching**: a new domain package that imports `inventory`, never the reverse.

The direction is enforced by `depguard` rules in `.golangci.yaml`, which deny all of `barbackend/internal` to a layer and allow back only the layers below it, so a new use-case package is forbidden to `inventory`, `cmdb/provider` and `postgres` without touching the config. `internal/httpapi` may import only the domain packages `inventory` and `tenancy` and the use-case packages it serves, listed by name, so serving a new use case means adding it to that list. It is denied `cmdb/provider` by name, since allowing `cmdb` would otherwise allow everything under it. Its tests are exempt, because they wire a real router on Postgres as `cmd` does. Only `cmd` and `internal/httpapi` may import gin.

## Considered Options

- **Document the layering only in `AGENTS.md`**: rejected; a paragraph drifts and nothing fails when a handler calls `postgres` directly.
- **Merge the CMDB use case into the seam's package**: rejected; every adapter would import Postgres through it (ADR 0007).
- **Keep the use case in a sibling package (`internal/sources`, then `internal/cmdbsources`)**: rejected; the seam took the name `cmdb`, so the package callers use most had the less obvious name, and "source" alone is the word the glossary avoids for Feeds.
- **Make `internal/tenancy` both the Customer domain and the use cases on Users**: rejected; `inventory` and `postgres` need `CustomerID` and the User types, so the package would import `postgres` while `postgres` imports it.
