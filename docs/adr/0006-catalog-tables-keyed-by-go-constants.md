# Closed value sets are catalog tables keyed by the Go constant

Asset Kind, Criticality, Software Component role and Exposure are closed sets that only change with code. We store each as a catalog table (`id smallint`, `name text`) seeded by a migration, and the `id` equals the Go constant's value. The domain constants use explicit values rather than `iota`, so reordering them cannot remap stored data, and an integration test asserts that every Go value's name matches its catalog row. "Unknown" and "not declared" are `NULL`, never a catalog row.

## Considered Options

- **Postgres `ENUM` types**: rejected; hard to evolve (values cannot be removed or reordered) and opaque outside SQL.
- **`text` with `CHECK` constraints**: rejected; spreads the allowed values across constraints instead of one table that can be joined and listed.
- **Catalog tables with generated UUIDs**: rejected; Go would need a runtime lookup or hardcoded UUIDs to map constants to rows, for values that only change through a migration anyway.
