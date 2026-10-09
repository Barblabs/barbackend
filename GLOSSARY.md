# barbattack

barbattack is a threat intelligence platform that watches a customer's assets for relevant threats and alerts the people responsible for them.

## Language

### Inventory

**CMDB Provider**:
A configuration management product that barbattack can import assets from, such as iTop or ServiceNow.
_Avoid_: CMDB type, vendor

**CMDB Source**:
One connected instance of a CMDB Provider belonging to a customer.
_Avoid_: Integration, connector, connection

**Asset**:
A host-level thing in a customer's environment that barbattack monitors for threats: a server, virtual machine, workstation or network device. It is an operational configuration item, never a financial or procurement record.
_Avoid_: CI, configuration item, device, host, machine

**Source Reference**:
The identity of the record an Asset was imported from, made of its CMDB Source and the provider's own identifier for that record.
_Avoid_: External ID, foreign key

**Asset Kind**:
The barbattack category of an Asset (Server, Virtual Machine, Workstation, Network Device), independent of how any CMDB Provider classifies it.
_Avoid_: Class, CI type, finalclass

**Software Component**:
A piece of software running on an Asset, including its operating system or firmware, described by vendor, product and version. It belongs to its Asset and has no identity of its own.
_Avoid_: Software instance, package, application, installed software

**Inactive Asset**:
An Asset that its CMDB Source reports as retired or no longer contains. It is kept for history but no longer monitored.
_Avoid_: Deleted, obsolete, retired, archived

### Risk

**Exposure**:
Whether an Asset is reachable from the public internet: Internet-facing, Internal, or Unknown. It is declared by a barbattack user, never imported from a CMDB, and is Unknown until declared.
_Avoid_: Public/private, external, DMZ

**Criticality**:
How important an Asset is to the customer's business: High, Medium, Low, or Unknown.
_Avoid_: Priority, severity, business criticity

### People

**Asset Owner**:
The person responsible for an Asset who receives alerts about it on Slack. It is imported from the CMDB Source unless a barbattack user declares one, and the declaration wins. An Asset Owner is not a barbattack user.
_Avoid_: User, contact, assignee, responsible, manager

**Security Team**:
The customer's cybersecurity team, which receives alerts for any Asset that has no Asset Owner.
_Avoid_: Fallback owner, default owner, cyber team
