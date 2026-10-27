# The HTTP API's OpenAPI spec is generated from handler types by Huma

`internal/httpapi` registers every endpoint as a Huma operation (`github.com/danielgtaylor/huma/v2`) on the Gin router through the `humagin` adapter, and serves the generated OpenAPI 3.1 spec at `/openapi.json` and `/openapi.yaml`, with Huma's docs UI at `/docs`. Each operation's typed input and output structs are the spec, so the spec cannot drift from the code, and a new endpoint is documented the moment it is registered. Gin stays as the router, so the CORS middleware and `/ping` are untouched, and the layering of ADR 0008 holds: Huma is transport, like Gin, and parsing and domain rules stay in the use cases (`cmdb.AssetQuery` parses the Asset list query, so its parameters are plain strings in the spec).

## Consequences

- **The wire format predates Huma and is kept**: every error is `{code, error}`, through a replacement `huma.NewError`, and Huma's own 422 for a body that fails its schema is answered as 400 `invalid_request`, so 422 keeps meaning a CMDB Provider rejected the request. JSON is encoded as Gin did, without the `$schema` field Huma adds by default. Request bodies tolerate unknown fields and reject empty required strings, as Gin's binding did.
- **Huma's global settings are set once**: `huma.NewError` and `huma.DefaultArrayNullable` are package globals, assigned in `init`, not per router.
- **Two gaps in Huma are patched in `internal/httpapi/openapi.go`**: it cannot mark an object field nullable, and it lists 422 on every operation with parameters or a body.

## Considered Options

- **swaggo comment annotations**: rejected; the spec is written a second time in comments that nothing checks against the handler, so it drifts.
- **Spec-first with oapi-codegen**: rejected; the spec becomes a hand-maintained YAML file and handlers implement a generated interface, which is more ceremony than a small API with one client needs, and moves the source of truth away from the Go types.
