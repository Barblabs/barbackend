# Assets are hosts; software and business services are not Assets

CMDBs model installed software (iTop `SoftwareInstance`) and business services (iTop `ApplicationSolution`, ServiceNow business applications) as their own CIs linked to hosts. Because we do not model relationships, we fold software into its host as Software Components and leave business-level CIs out entirely. Version-based threat matching needs the version and the Exposure on the same record, and a business service has no version to match on. Business context is carried by the Asset's free-text description, which is shown in alerts but never used for matching.

## Considered Options

- **Business services as an "Application" Asset Kind**: only useful for vendor or product-level intel (breaches, campaigns against a SaaS product). Deferred; it can be added as a new Kind without reshaping the model.
