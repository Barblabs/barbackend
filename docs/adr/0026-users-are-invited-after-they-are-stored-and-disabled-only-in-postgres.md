# Users are invited after they are stored, and disabled only in Postgres

Postgres decides who may sign in: every request resolves the token's `sub` to a stored User and checks that they can sign in (ADR 0013). Cognito only proves who someone is, so no Cognito call runs inside a Postgres transaction, and no change to a User has to be undone in one when the other fails.

Inviting a User stores them pending, with no `sub`, together with their Invitation, in one transaction. Only after the commit does the backend call Cognito's `AdminCreateUser`, which emails the Invitation and returns the `sub` that it then stores. The caller claims the Invitation when storing it, for longer than the deadline of one Cognito call, and sends it right away, so the email goes out during the request. A failed attempt is recorded with its error and retried by `serve` after a delay that doubles up to an hour. A claim that runs out, because the process died, makes the Invitation due again. A pending User cannot sign in, since no token's `sub` names them, and the Customer's User list shows them as pending. A pending Customer Admin does not count as one of the Customer's active Customer Admins. Invitations of disabled Users and of Deactivated Customers wait.

Sending an Invitation can be retried: when Cognito already has the email, from an earlier attempt or a crash before the `sub` was stored, the adapter resends the Invitation with a new temporary password, or, when that person has already set a password, takes their `sub` as it is.

Disabling a User only marks them disabled in Postgres, and `Authenticate` refuses them from their next request. They stay enabled in Cognito, as the Users of a Deactivated Customer already do.

## Considered Options

- **Call Cognito inside the transaction and undo it on failure** (what ADR 0013 first described): rejected; a crash or a failed undo leaves a Cognito user Postgres does not know, which blocks every later invite of the email, the person is emailed an invitation to an account that is then deleted, and a slow Cognito holds the transaction and, for Disable, the Customer's lock.
- **Only the background job sends Invitations**: rejected; the email would wait for the next poll, and `create-platform-admin` would need `serve` running.
- **Disable in Cognito too, as a retried job after the commit**: rejected; it would revoke refresh tokens, but refresh tokens are revoked only at sign-out, and a disabled User's access tokens are refused anyway.
- **On a Cognito user that exists, only take their `sub`**: rejected; when their temporary password has expired, the person could never sign in, and their email could not be invited again.

## Consequences

- A disabled User stays enabled in Cognito, so they can still sign in there and get tokens; every request with them is refused.
- The same person can be emailed twice, the second time with a new temporary password, when storing the `sub` fails after Cognito's reply, or the process dies in between.
- An Invitation Cognito rejects for good, such as one to a malformed email, is retried every hour forever and keeps its email taken. Its last error is stored in `user_invitations` for operators; no endpoint shows it.
