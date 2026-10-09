# Asset model is owned by barbattack, not by any CMDB Provider

barbattack will import from several CMDB Providers (iTop first, ServiceNow next), and they model inventory differently: iTop has a deep class tree under `FunctionalCI`, ServiceNow has `cmdb_ci` with `sys_class_name`, and neither stores Exposure or a Slack identity. We define our own Asset with a small closed set of Asset Kinds, and each provider adapter translates its records into it. Provider class names never appear in the domain; the original record is only kept as a Source Reference.

An Asset mirrors exactly one record in one CMDB Source. We do not merge records from different sources into one Asset: the same machine present in two CMDB Sources is two Assets. An Asset belongs to its CMDB Source, which belongs to a Customer; provider-level organizations (such as iTop's `org_id`) are not part of the Asset.

## Consequences

- Adding a provider means writing a mapping, never changing the Asset model.
- Exposure is declared by barbattack users because no provider reliably records it (iTop has no such field; ServiceNow's `internet_facing` is not populated automatically).
