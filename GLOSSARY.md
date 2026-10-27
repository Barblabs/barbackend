# barbattack

barbattack is a threat intelligence platform that watches a customer's assets for relevant threats and alerts the people responsible for them.

## Language

### Tenancy

**Customer**:
An organization that uses barbattack. Everything barbattack knows about an environment belongs to exactly one Customer.
_Avoid_: Tenant, account, organization

**Deactivated Customer**:
A Customer that barbattack no longer serves. It is never deleted, its Users can no longer sign in, and its CMDB Source is no longer synced.
_Avoid_: Deleted customer, suspended, churned

### Inventory

**CMDB Provider**:
A configuration management product that barbattack can import assets from, such as iTop or ServiceNow.
_Avoid_: CMDB type, vendor

**CMDB Source**:
One connected instance of a CMDB Provider, belonging to a Customer.
_Avoid_: Integration, connector, connection

**Connected CMDB Source**:
The CMDB Source a Customer currently syncs its Assets from. A Customer has at most one; switching CMDBs means disconnecting it and connecting another.
_Avoid_: Active connection, current integration

**Disconnected CMDB Source**:
A CMDB Source that is no longer synced. It is never deleted, its Assets become Inactive Assets, and connecting the same CMDB again creates a new CMDB Source.
_Avoid_: Deleted source, removed source, inactive source

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
An Asset that barbattack has stopped monitoring, normally because its CMDB Source reports it as retired or no longer contains it, or because its CMDB Source was disconnected. It is kept for history; being reported as retired is an imported value, not the same as being Inactive.
_Avoid_: Deleted, obsolete, retired, archived

**Sync**:
Bringing the Assets of one CMDB Source in line with a complete snapshot of its records: creating, updating, deactivating and reactivating Assets.
_Avoid_: Import job, refresh, poll, crawl

**Sync Run**:
The record of one Sync of a CMDB Source: whether it succeeded or failed, when it ran, how many Assets it created, updated, deactivated and reactivated, and its Skipped Records. A failed Sync Run changed no Asset.
_Avoid_: Job, import log, sync history

**Skipped Record**:
A record still present in a CMDB Source that a Sync could not import, with the reason. Its Asset, if it has one, is left as it was and is not deactivated.
_Avoid_: Rejection, rejected record, invalid record

**Declaration**:
A value about an Asset set by a User rather than imported from its CMDB Source. Where both exist, the Declaration wins, and removing it restores the imported value.
_Avoid_: Override, manual value, custom field

### Threat intelligence

**Feed**:
An external source of threat intelligence that barbattack reads, such as NVD, EPSS or the CISA KEV catalog. Text from a Feed is data to evaluate, never instructions to follow.
_Avoid_: Source (that is a CMDB Source), provider, integration

**Vulnerability**:
A publicly disclosed weakness in a Product, identified by its CVE ID. On its own it says nothing about a Customer's environment.
_Avoid_: Vuln, flaw, bug

### Risk

**Finding**:
The fact that one Vulnerability affects one Software Component of one Asset. It is open until it is remediated or no longer applies, and only open Findings are scored.
_Avoid_: Hallazgo, issue, vulnerability instance, alert

**Score**:
A deterministic number from 0 to 1 that ranks how urgently a Finding should be remediated, computed from its Vulnerability's CVSS base score, EPSS probability and presence in the CISA KEV catalog, and its Asset's Criticality and Exposure.
_Avoid_: Risk score, priority, rating

**Score Band**:
A named range of Scores used to decide how a Finding is reported.
_Avoid_: Tier, severity, level

**Scoring Model**:
An immutable, versioned definition of how a Score is computed: its weights, its aggregation and its defaults for missing inputs. Every Score records the Scoring Model that produced it.
_Avoid_: Weights config, algorithm, formula version

**Data Gap**:
An input that was missing when a Score was computed and was replaced by the Scoring Model's default. It is recorded on the Score, so an estimated Score is never mistaken for a measured one.
_Avoid_: Missing data, warning, flag

**Exposure**:
Whether an Asset as a whole is reachable from the public internet: Internet-facing, Internal, or Unknown. It only comes from a Declaration and is Unknown until declared.
_Avoid_: Public/private, external, DMZ

**Criticality**:
How important an Asset is to the Customer's business: High, Medium, Low, or Unknown. It is only imported, never declared.
_Avoid_: Priority, severity, business criticity

### People

**User**:
A person who signs in to barbattack. A User is either a Platform Admin or belongs to exactly one Customer, and never moves between Customers.
_Avoid_: Account, login, member

**Platform Admin**:
A barbattack staff User who creates Customers and their first Customer Admin. A Platform Admin belongs to no Customer and cannot see any Customer's Assets or Findings.
_Avoid_: Super admin, superadmin, staff

**Customer Admin**:
A User who manages the Users of their own Customer, including other Customer Admins. Every Customer has at least one.
_Avoid_: Tenant admin, org admin, owner

**Viewer**:
A User of a Customer who is not a Customer Admin and cannot manage Users.
_Avoid_: Member, regular user, analyst

**Asset Owner**:
A person, identified by email, who is responsible for one or more Assets and receives alerts about them on Slack. It is imported from the CMDB Source or set by a Declaration. An Asset Owner is not a User.
_Avoid_: User, contact, assignee, responsible, manager

**Security Team**:
The Customer's cybersecurity team, which receives every alert about the Customer's Assets, whether or not the Asset has an Asset Owner.
_Avoid_: Fallback owner, default owner, cyber team
