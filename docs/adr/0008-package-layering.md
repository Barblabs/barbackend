# Packages are layered by role, and depguard enforces the direction

Packages are split by role, not by feature, and each layer may only import the layers below it:

```
cmd/barbackend/        flags, usage, wiring only
internal/
  httpapi/             router + handlers           -> use-case packages
  sources/             use cases on CMDB Sources   -> cmdb, encryption, inventory, postgres
  cmdb/                CMDB Provider seam          -> inventory
    <provider>/        adapters                    -> cmdb, inventory, own subpackages
  encryption/          sealing credentials         -> nothing internal
  postgres/            all persistence             -> inventory
  inventory/           pure domain                 -> nothing internal
```

A use case is a package that orchestrates the domain, persistence and adapters; transports (the CLI, `httpapi`) only call use cases, and only `cmd` wires them together. The domain does no I/O, so its rules stay testable without a database (ADR 0005). Adapters never depend on persistence, so adding a CMDB Provider never pulls in Postgres (ADR 0007). Persistence depends only on the domain, so a use case can never be reached from below.

New features get a home before they get code:

- **Declarations**: a use-case package such as `internal/assets`, with its queries in `postgres`.
- **Slack alerts**: an adapter under `internal/slack`, called from an alerting use-case package.
- **Customer as a real entity**: `internal/tenancy`, taking `CustomerID` out of `inventory`.
- **Threat matching**: a new domain package that imports `inventory`, never the reverse.

The direction is enforced by `depguard` rules in `.golangci.yaml`, which deny all of `barbackend/internal` to a layer and allow back only the layers below it, so a new use-case package is forbidden to `inventory`, `cmdb` and `postgres` without touching the config. `internal/httpapi` may import only `inventory` and the use-case packages it serves, listed by name, so serving a new use case means adding it to that list. Only `cmd` and `internal/httpapi` may import gin.

## Considered Options

- **Document the layering only in `AGENTS.md`**: rejected; a paragraph drifts and nothing fails when a handler calls `postgres` directly.
