# Asset Owners are identified by email and imported only when unambiguous

Alerts go to the Asset Owner on Slack, but no CMDB stores Slack identities, and Slack usernames and display names change. We identify the owner by email, which both iTop (Person) and ServiceNow (`sys_user`) store, and resolve it to a Slack member ID. A barbattack user can declare an owner, and that declaration always wins over the imported one. If there is no owner, alerts go to the Security Team.

## Import rules

- **ServiceNow**: the email of the `owned_by` user.
- **iTop**: contacts have no role, so we never guess. If the CI has exactly one Person contact, that Person is the owner; if it has several Persons, only Teams or no contacts, it has no imported owner.
