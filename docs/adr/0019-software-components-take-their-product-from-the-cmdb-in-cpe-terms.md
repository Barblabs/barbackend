---
status: proposed
---

# Software Components take their Product from the CMDB in CPE terms, and their name from the installation

The asset filter matches a Software Component's Product against the CPE 2.3 `vendor` and `product` tokens of NVD's `affected` entries (ADR 0015). Whether a component can be matched therefore depends entirely on what its CMDB Source records, and ADR 0010 left open how a Product is keyed. This ADR settles where each value of an Application comes from in iTop, and who is responsible for it being right.

## Where each value comes from in iTop

An Application is one iTop SoftwareInstance (`DBServer`, `WebServer`, `Middleware`, `PCSoftware` or `OtherSoftware`) on a Server, Virtual Machine, PC or Network Device (ADR 0002). An iTop SoftwareInstance links to a Software from iTop's catalog, which carries the vendor, the name and the version.

| `software_components` | iTop | Read by | Example |
|---|---|---|---|
| `name` | the SoftwareInstance's `name` | people: dashboard, alerts | `Web server of the payments API` |
| `product_vendor` | the linked Software's `vendor` | matching | `apache` |
| `product_name` | the linked Software's `name` | matching | `http_server` |
| `version` | the linked Software's `version` | matching | `2.4.57` |

The name is for people and is never matched. The Product and version are for matching and must be written as NVD writes them: the Software's vendor and name are the CPE 2.3 vendor and product tokens, which NVD's CPE search (https://nvd.nist.gov/products/cpe/search) shows for any product, and its version is the full version installed (`2.4.57`, not `2.4`), since NVD states ranges such as `< 2.4.58`. As iTop keeps the version on the Software, each installed version is its own Software in the catalog.

An iTop SoftwareInstance that links to no Software, or to one with a blank vendor, has no Product: it is an Unidentified Component, named after the SoftwareInstance, and shown as such (ADR 0002). Operating Systems keep the rules of ADR 0002: iTop's OS family and IOSVersion carry no vendor, so they have no Product.

## Products match as the CMDB writes them

barbattack does not translate Products. A component matches only when its Product's vendor and name are NVD's tokens, ignoring only case and surrounding spaces (ADR 0015): a Software named `Apache HTTP Server` by `Apache` matches nothing, while `apache` / `http_server` does. Writing the tokens correctly is the responsibility of the CMDB Source and of whoever maintains it.

The dashboard only reads Assets and their Software Components; it never edits a Product, a name or a version. Every correction is made in the CMDB Source and reaches barbattack with the next Sync (ADR 0004).

An Asset's description is free text and is never read for matching, even when it lists software (`nginx 1.18, PostgreSQL 15`). Software that is not recorded as a SoftwareInstance does not exist for the asset filter.

## Considered Options

- **The Software's name as the component's name**, as ADR 0002 had it: rejected; it puts the CPE token (`http_server`) where people read, and loses the name the CMDB gave the installation.
- **An alias table** that translates CMDB free text into CPE tokens during the Sync (`Apache HTTP Server` → `apache` / `http_server`): deferred. It is the next step once a CMDB Source cannot record CPE tokens, and it keeps the raw value next to the identified Product, as ADR 0002 intends.
- **Searching NVD's CPE dictionary** by the CMDB's text: deferred, and only to suggest aliases for a person to approve. A wrong guess would read as "not affected", which is the miss ADR 0015 avoids.
- **Declaring Products in the dashboard**: rejected. The CMDB Source stays the only place Software Components are written; Software Components are rewritten on every Sync and have no identity a Declaration could attach to (ADR 0004, ADR 0015).
- **Reading software from the Asset's description**: rejected; free text cannot be matched reliably.

## Consequences

- Matching is as good as the CMDB's data. A Product written in the CMDB's own words matches no Vulnerability and its Asset looks unaffected, so the convention above has to be known to whoever fills iTop.
- The iTop adapter names an Application after its SoftwareInstance instead of its Software. This replaces the naming part of ADR 0002's "Application" rule; its Product rule is unchanged.
- The open question "How a Product is keyed" of ADR 0010 is answered: by the CPE tokens, written in the CMDB.
