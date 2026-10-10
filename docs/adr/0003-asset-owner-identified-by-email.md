# Asset Owners are identified by email and imported only when unambiguous

Alerts go to the Asset Owner on Slack, but no CMDB stores Slack identities, and Slack usernames and display names change. We identify the owner by email, which both iTop (Person) and ServiceNow (`sys_user`) store, and resolve it to a Slack member ID. A barbattack user can declare an owner, and that declaration always wins over the imported one. If there is no owner, alerts go to the Security Team.

An Asset Owner is a person shared by all the Assets they own, not a value copied onto each Asset. Their Slack member ID is resolved once, and a departed owner is handled in one place.

Emails that differ only in case or surrounding space identify the same Asset Owner. The domain keeps owner emails in one canonical form (trimmed, lowercased) rather than trusting each edge to normalize them, so an import and a Declaration of the same person can never become two owners. Checking email syntax stays at the edge.

## Import rules

- **ServiceNow**: the email of the `owned_by` user.
- **iTop**: contacts have no role, so we never guess. If the CI has exactly one Person contact, that Person is the owner; if it has several Persons, only Teams or no contacts, it has no imported owner.
