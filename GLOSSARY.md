# barbattack

barbattack is a threat intelligence platform that watches a customer's assets for relevant threats and alerts the people responsible for them.

## Language

### Tenancy

**Customer**:
An organization that uses barbattack. Everything barbattack knows about an environment belongs to exactly one Customer.
_Avoid_: Tenant, account, organization

**Deactivated Customer**:
A Customer that barbattack no longer serves. It is never deleted, its Users can no longer sign in, and its CMDB Source is no longer synced. A Platform Admin can reactivate it, which restores its Users and its CMDB Source as they were.
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
A CMDB Source that is no longer synced. It is never deleted, its Assets become Inactive Assets and its Areas Inactive, and connecting the same CMDB again creates a new CMDB Source.
_Avoid_: Deleted source, removed source, inactive source

**Asset**:
A host-level thing in a Customer's environment that barbattack monitors for threats: a server, virtual machine, workstation or network device. It mirrors exactly one record in one CMDB Source, and is an operational configuration item, never a financial or procurement record.
_Avoid_: CI, configuration item, device, host, machine

**Area**:
A part of a Customer's organization, such as a department or a subsidiary, that Assets belong to, imported from a CMDB Source; iTop calls it an Organization. Areas are flat, and an Area that its CMDB Source marks inactive or no longer contains becomes Inactive, never deleted.
_Avoid_: Organization, department, business unit, org

**Source Reference**:
The identity of the record an Asset or an Area was imported from, made of its CMDB Source and the provider's own identifier for that record.
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
The canonical identity of a piece of hardware or software, in the terms threat intelligence uses to say what is affected. A Product may also be imported from a CMDB Source as free text, which is not yet normalized to threat intelligence terms (ADR 0010).
_Avoid_: CPE, package, SKU

**Unidentified Component**:
A Software Component that has not been matched to a Product, so barbattack cannot tell whether threats affect it.
_Avoid_: Unknown software, unmatched

**Inactive Asset**:
An Asset that barbattack has stopped monitoring, normally because its CMDB Source reports it as retired or no longer contains it, or because its CMDB Source was disconnected. It is kept for history; being reported as retired is an imported value, not the same as being Inactive.
_Avoid_: Deleted, obsolete, retired, archived

**Sync**:
Bringing the Assets and Areas of one CMDB Source in line with a complete snapshot of its records: creating, updating, deactivating and reactivating them.
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
The fact that one Vulnerability affects one Product installed on one Asset. It is open until it is remediated or no longer applies, then closed with a reason, and reopened if it applies again; it is never deleted. Only open Findings are scored.
_Avoid_: Hallazgo, issue, vulnerability instance, alert

**Match Flag**:
A reason a Finding's match is uncertain, such as a version that could not be compared. A Finding with no Match Flags is a certain match; one with any is still a Finding.
_Avoid_: Dudoso, warning, uncertain boolean

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
Whether an Asset as a whole is reachable from the public internet: Internet-facing, Internal, or Unknown. It is imported from the iTop Location (`exposed` or `not exposed`) and can be declared over it; the Declaration wins. It is Unknown when neither gives it, as for every Virtual Machine until declared (ADR 0021).
_Avoid_: Public/private, external, DMZ

**Criticality**:
How important an Asset is to the Customer's business: High, Medium, Low, or Unknown. It is only imported, never declared.
_Avoid_: Priority, severity, business criticity

### Business

**Business Context**:
What a Customer tells barbattack about its business, for the Agents to weigh Findings and threats with: what it does, its sectors, size and revenue, where it operates, its Critical Services, the data it holds, the regulations it follows, its domains, brands, technologies and third parties, its Risk Appetite and the risks that worry it. A Customer Admin edits it and every User of the Customer reads it. Each save is a new version that is never changed. A field the Customer has not stated is a gap, never a value (ADR 0017).
_Avoid_: Company profile, business profile, organization info, contexto empresarial

**Critical Service**:
A business service a Customer cannot afford to lose, such as online payments or payroll, part of its Business Context, with how badly losing it hurts, how long it can be down, and the names of the Assets that run it.
_Avoid_: Crown jewel, critical process, key system

**Risk Appetite**:
How much risk a Customer as a whole is willing to take, as its leadership sets it. How much a single Critical Service tolerates is its impact and maximum tolerable downtime, not the Risk Appetite.
_Avoid_: Risk tolerance (that is per Critical Service), risk profile

### Agents

**Agent**:
A model-driven role of barbattack, named for what it does rather than for the model it runs on. It orders, explains and advises: it never outputs a number, changes a Score or closes a Finding.
_Avoid_: Bot, AI, assistant

**Prioritizer**:
The Agent that decides in what order a Customer's open Findings should be attended, weighing each Score with what its Asset means to the business, and says why.
_Avoid_: JEV, triage agent, ranking agent

**Luna**:
The Agent that writes the Action Plan of a Finding. Not OpenAI's model of the same name.
_Avoid_: Advisor agent

**Analista**:
The feedback Agent: it talks with a Customer's Users about their Prioritizations and Action Plans and records what they say.
_Avoid_: Chatbot, feedback bot

**Drafter**:
The Agent that drafts a Customer's Business Context from the documents a Customer Admin gives it, read together. Its draft is never saved until a Customer Admin reviews and saves it.
_Avoid_: Importer, extractor, autofill

**Crew**:
The Agents that answer in one call, checked against what they were given: the Prioritizer and Luna, which read Dossiers, and the Drafter.
_Avoid_: Team, pipeline

**Dossier**:
All that an Agent knows about a Finding: its Asset, its Software Component, its Vulnerability as the Feeds describe it and its Score, as the Findings pipeline gives them. An Agent's output may rely on nothing outside it.
_Avoid_: Context, expediente, prompt data

**Prioritization**:
The order the Prioritizer gave a Customer's open Findings at one moment, as Priority Groups, with the Dossiers it read. It is kept as history: the newest is the one to follow.
_Avoid_: Ranking, triage list

**Priority Group**:
Findings of a Prioritization to attend at the same time, such as those one update fixes together. The first group is attended first.
_Avoid_: Tier, wave, bucket

**Action Plan**:
Luna's output: the steps to remediate a Finding on its Asset, what mitigates it meanwhile and how to confirm the fix.
_Avoid_: Recommendation, remediation plan

**Feedback**:
What a User says about a Finding of a Prioritization: that its Vulnerability applies, does not apply or was remediated, or that it should be attended earlier or later. It changes no Score and no order.
_Avoid_: Label, correction, comment

### People

**User**:
A person who signs in to barbattack. A User is either a Platform Admin or belongs to exactly one Customer, and never moves between Customers.
_Avoid_: Account, login, member

**Platform Admin**:
A barbattack staff User who creates, renames, deactivates and reactivates Customers, and creates each Customer's first Customer Admin. A Platform Admin belongs to no Customer and cannot see any Customer's Assets or Findings.
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

**Area Owner**:
The person, identified by email, whom barbattack reaches about an Area. Only a Customer Admin states it, never a CMDB Source; it is not an Asset Owner and need not be a User.
_Avoid_: Asset Owner, area contact, area manager

**Security Team**:
The Customer's cybersecurity team, which receives every alert about the Customer's Assets, whether or not the Asset has an Asset Owner.
_Avoid_: Fallback owner, default owner, cyber team
