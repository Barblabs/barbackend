# Assets are hosts; software and business services are not Assets

CMDBs model installed software (iTop `SoftwareInstance`) and business services (iTop `ApplicationSolution`, ServiceNow business applications) as their own CIs linked to hosts. Because we do not model relationships, we fold software into its host as Software Components and leave business-level CIs out entirely. Version-based threat matching needs the version and the Exposure on the same record, and a business service has no version to match on. Business context is carried by the Asset's free-text description, which is shown in alerts but never used for matching.

CMDBs record software as free text ("Ubuntu 22.04 LTS"), while threat intelligence names affected Products canonically. A Software Component therefore keeps the raw name and version as imported, plus an optional Product once identified, and a role (Operating System or Application). Unidentified Components stay visible so that "not affected" is never confused with "could not check". Physical Assets also carry Hardware (vendor and model), because firmware vulnerabilities often depend on the device model.

Exposure is a property of the whole Asset, not of each Software Component. An internal-only service on an internet-facing host is treated as exposed; per-component exposure was rejected as too much manual work for the precision gained.

## iTop import rules

- **Operating System**: the OS family as name and the OS version as version. Network Devices have no OS family in iTop, only an IOSVersion (a brand and a version name), so the brand is the name and the IOSVersion's name the version: Cisco `15.2(7)E`. A fixed "IOS" name would mislabel the other vendors iTop stores as IOSVersions, and the friendly name "Cisco 15.2(7)E" as a name would leave no version to match on.
- No Operating System when its name is blank.

## Considered Options

- **Business services as an "Application" Asset Kind**: only useful for vendor or product-level intel (breaches, campaigns against a SaaS product). Deferred; it can be added as a new Kind without reshaping the model.
