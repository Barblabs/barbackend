# barbattack

barbattack is a threat intelligence platform that watches a customer's assets for relevant threats and alerts the people responsible for them.

## Language

### Tenancy

**Customer**:
An organization that uses barbattack. Everything barbattack knows about an environment belongs to exactly one Customer.
_Avoid_: Tenant, account, organization

### Inventory

**CMDB Provider**:
A configuration management product that barbattack can import assets from, such as iTop or ServiceNow.
_Avoid_: CMDB type, vendor

**CMDB Source**:
One connected instance of a CMDB Provider, belonging to a Customer.
_Avoid_: Integration, connector, connection

**Asset**:
A host-level thing in a Customer's environment that barbattack monitors for threats: a server, virtual machine, workstation or network device. It mirrors exactly one record in one CMDB Source, and is an operational configuration item, never a financial or procurement record.
_Avoid_: CI, configuration item, device, host, machine

**Source Reference**:
The identity of the record an Asset was imported from, made of its CMDB Source and the provider's own identifier for that record.
_Avoid_: External ID, foreign key

**Asset Kind**:
The barbattack category of an Asset (Server, Virtual Machine, Workstation, Network Device), independent of how any CMDB Provider classifies it.
_Avoid_: Class, CI type, finalclass

**Hardware**:
The vendor and model of a physical Asset. Virtual Assets have none.
_Avoid_: Brand, device model, platform

**Software Component**:
A piece of software running on an Asset, with a role of either Operating System or Application. It keeps the name and version as the CMDB Source wrote them, belongs to its Asset and has no identity of its own. An Asset has at most one Operating System.
_Avoid_: Software instance, package, installed software

**Product**:
The canonical identity of a piece of hardware or software, in the terms threat intelligence uses to say what is affected.
_Avoid_: CPE, package, SKU

**Unidentified Component**:
A Software Component that has not been matched to a Product, so barbattack cannot tell whether threats affect it.
_Avoid_: Unknown software, unmatched

**Inactive Asset**:
An Asset that its CMDB Source reports as retired or no longer contains. It is kept for history but no longer monitored.
_Avoid_: Deleted, obsolete, retired, archived

**Declaration**:
A value about an Asset set by a barbattack user rather than imported from its CMDB Source. Where both exist, the Declaration wins, and removing it restores the imported value.
_Avoid_: Override, manual value, custom field

### Risk

**Exposure**:
Whether an Asset as a whole is reachable from the public internet: Internet-facing, Internal, or Unknown. It only comes from a Declaration and is Unknown until declared.
_Avoid_: Public/private, external, DMZ

**Criticality**:
How important an Asset is to the Customer's business: High, Medium, Low, or Unknown. It is only imported, never declared.
_Avoid_: Priority, severity, business criticity

### People

**Asset Owner**:
A person, identified by email, who is responsible for one or more Assets and receives alerts about them on Slack. It is imported from the CMDB Source or set by a Declaration. An Asset Owner is not a barbattack user.
_Avoid_: User, contact, assignee, responsible, manager

**Security Team**:
The Customer's cybersecurity team, which receives alerts for any Asset that has no Asset Owner.
_Avoid_: Fallback owner, default owner, cyber team
