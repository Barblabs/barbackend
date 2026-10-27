# Users authenticate with one Cognito user pool and are authorized in Postgres

Users sign in with Amazon Cognito, but Cognito only proves who a User is. Their Customer and role (Platform Admin, Customer Admin, or a regular User) live in a `users` table in Postgres, keyed by the Cognito `sub`. Every request resolves the token's `sub` to that row, and Customer-scoped queries take the Customer from it, never from the URL or request body. All Users of all Customers share one user pool, and Platform Admins are Users with no Customer in the same pool.

Users are created only by the backend. Both a Platform Admin creating a Customer's first Customer Admin and a Customer Admin creating Users go through the same creation path in the backend. The backend checks the caller's role and Customer before it calls Cognito's `AdminCreateUser`, which sends the invitation. Nobody creates Users in the Cognito console. The first Platform Admin is bootstrapped by a CLI command.

## Considered Options

- **One user pool per Customer**: rejected; each pool has its own issuer, app clients and settings, so the backend would have to pick the pool before validating a token, and AWS limits the number of pools per account. It would only isolate login, which the `sub` to Customer lookup already scopes.
- **Customer and role as Cognito groups or custom attributes in the token**: rejected; claims stay stale until the token refreshes, so a removed User or demoted admin keeps access, immutable custom attributes can never be corrected, and authorization would be split between AWS and our code.
- **A separate user pool for Platform Admins**: rejected for now; it means validating two issuers for little gain while Platform Admins cannot see Customer data.

## Consequences

- A User belongs to at most one Customer. Letting a person work for several Customers would move the Customer and role from `users` into a membership table and require a Customer switcher.
- Customers cannot sign in through their own identity provider (SSO). Adding it later fits the single pool, but federated Users would be created on first sign-in rather than by invitation.
- Disabling a User means disabling them in Cognito and marking them disabled in Postgres, so the two must stay in step.
- Deactivating a Customer is only recorded in Postgres: its Users stay enabled in Cognito and can still get a token, but every request they make is refused. Disabling each of them in Cognito would be many calls with no transaction, and reactivating the Customer could not tell them apart from Users a Customer Admin disabled.
