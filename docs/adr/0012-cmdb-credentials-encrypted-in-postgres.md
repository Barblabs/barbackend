# CMDB Source credentials are encrypted in Postgres, not named environment variables

A CMDB Source's secrets (an iTop password or token) are stored encrypted in their own `credentials` column on `cmdb_sources`, apart from the plain `settings` document. They are encrypted with AES-256-GCM using a key from the server's environment, and each ciphertext carries a key id so the key can be rotated. Encryption and decryption happen in one place below the use case; adapters receive decrypted credentials through `ParseSettings` and never see the key or ciphertext (ADR 0007). Settings stay free of secrets, so they remain safe to log and return.

This replaces naming an environment variable in the settings (`password_env`, `token_env`). The dashboard lets an admin type the password, and a process cannot set environment variables for another, so env-named secrets would need an operator for every connect. There is a single storage model: the CLI reads the secret from stdin and stores it the same way.

## Considered Options

- **Keep env-named secrets; the dashboard sends the variable name**: rejected; every connect or password rotation would need an operator to redeploy.
- **External secrets manager**: rejected for now; it adds infrastructure for a single secret per Customer. The key-id envelope leaves room to move the key there later.
- **Encrypt inside the settings document**: rejected; settings are opaque provider JSON, and mixing ciphertext into them would make every adapter handle encryption.

## Consequences

- Losing the encryption key makes every stored credential unrecoverable; Customers would have to re-enter them.
- Existing CMDB Sources with env-named secrets are disconnected by the migration, and their Assets become Inactive; their Customers connect or add a new CMDB Source.
