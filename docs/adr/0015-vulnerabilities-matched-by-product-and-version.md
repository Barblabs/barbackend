---
status: proposed
---

# Vulnerabilities are matched to Software Components by Product and version, and doubt is flagged, never dropped

The asset filter decides whether a Vulnerability affects a Software Component. It is a pure function in `internal/matching` (ADR 0008) that reads the `nvd/1` extension through `stixext` (ADR 0010): it takes one Software Component and the `affected` entries of one Vulnerability, and returns whether they match, the `affected` entry that matched as evidence, and the Match Flags of that match. It does no I/O, so every rule below is tested without iTop, Feeds or Postgres.

In security a missed Vulnerability costs more than one reviewed in vain. So the rule behind every decision here is: **unless we are sure a component is not affected, it is a match**, and whatever makes us unsure is recorded as a Match Flag. Nothing is dropped because of doubt.

## Rules

1. **Product.** Only a Software Component with a Product is evaluated. It matches an `affected` entry when its Product's vendor and name equal the entry's `vendor` and `product` CPE tokens, ignoring case and surrounding spaces, since a CMDB may write `Apache` where NVD writes `apache`. An Unidentified Component is never matched; it is reported as such, not silently skipped.
2. **Version form.** An `affected` entry states versions in exactly one of four ways, read from its `criteria` CPE (fields 6 and 7, version and update) and its range bounds. Of the 647 entries in the sample below, none had both an exact version and a range.

   | `criteria` version | Range bounds | Meaning | Rule |
   |---|---|---|---|
   | exact (`5.6.1`) | none | only that version | match if equal |
   | `*` | one or more | a range | match if inside, honouring including/excluding |
   | `*` | none | every version | match |
   | `-` | none | the Product has no versions | match |

   An update field other than `*` or `-` is part of the exact version: `2.0` with update `beta9` is `2.0-beta9`. The NVD adapter stores both as the `version` and `update` fields of each `affected` entry, a minor version of `nvd/1` (ADR 0010), so `matching` reads them as fields instead of parsing `criteria`.
3. **Version comparison.** Versions are split into numeric and alphabetic segments and compared segment by segment; numbers compare as numbers, so `1.9` < `1.10`, and missing trailing segments count as zero, so `1.18` = `1.18.0`. Letters glued to a number are part of the version and compare after it: `1.0.1f` < `1.0.1g`, `17.9.4` < `17.9.4a`, `1.8.31p2` < `1.8.32`. Parentheses separate segments like a dot, as Cisco writes its releases: `15.2(7)e` reads as `15.2.7.e`, so `15.2(7)e` < `15.2(8)`; unbalanced parentheses make the version unparsed. A leading `v` and a Debian epoch are ignored: `v1.18.0` and `1:1.18.0` read as `1.18.0`. A label after a hyphen that names a pre-release (`alpha`, `beta`, `rc`, `pre`, followed by digits, optionally after a dot) sorts before the release: `2.0-beta9` < `2.0`, and `beta.2` = `beta2`. Any other text after a hyphen is a packaging revision (`1.0.1f-1ubuntu2.2`, `1.20.1-1.el8`): the upstream part before it is compared, and a match is flagged `distro_backport`, since the distribution may have patched it without changing the upstream version.
4. **Doubt.** When the version, or the part of it needed to decide, cannot be read or compared (empty, `latest`, a number and letters at the same position as in `1.0.1f` against `1.0.1.2`, `1.9.5p1` against update `patch1`), the entry matches and is flagged `version_unparsed`. An exact version that is only the leading part of the component's version (`20.04` of `20.04.6`) also matches with `version_unparsed`, because NVD often names only a release line.
5. **Vulnerability status.** A Vulnerability whose `vuln_status` is `Rejected` never matches. Any other status (`Analyzed`, `Modified`, `Awaiting Analysis`...) is evaluated; one without `affected` entries matches nothing yet, and is evaluated again when NVD modifies it and it reaches the 24-hour window (ADR 0011).
6. **Configurations are lists.** NVD can join Products with AND (Spring4Shell affects `vmware:spring_framework` only when running on `oracle:jdk` 9 or later). Every vulnerable entry of a configuration is matched on its own, as if the configuration were a plain list of entries, and the condition is not checked. Missing a vulnerable component because its condition could not be verified would be a silent miss.
7. **One result per component and Vulnerability.** A Vulnerability may have several `affected` entries for the same Product (Log4Shell has seven for `apache:log4j`). The component gets one result: a match if any entry matches. An entry that matches without flags wins over one that matches with flags, and is the one kept as evidence.

## Match Flags

Match Flags are a closed set, stored as a catalog table keyed by Go constants (ADR 0006). A match carries zero or more of them; no flags means a certain match.

| id | name | Meaning |
|---|---|---|
| 1 | `version_unparsed` | The version could not be read or fully compared |
| 2 | `distro_backport` | Only the upstream version was compared; a packaging revision may already include the fix |

A flagged match is still a Finding: it is opened, scored and alerted like any other, and shows why it is uncertain. Like the Data Gaps of a Score (ADR 0009), a flag records doubt instead of hiding it.

## Which Vulnerabilities are matched

Only Vulnerabilities received from the Feeds after barbattack starts reading them are matched: a CVE NVD publishes or modifies within the 24-hour window (ADR 0011). There is no backfill. An old CVE that NVD does not modify again is never matched, even if it affects a Customer's Assets: the 2021 CVE in a still-installed nginx is out of scope, by decision of the team. For the same reason, an Asset added later is matched only against the Vulnerabilities received after it is synced.

## Scores follow their Vulnerability

KEV and EPSS objects carry no `affected` entries, so they never open a Finding. When one arrives for a CVE that already has Findings, those Findings are rescored with it (ADR 0009); one for a CVE with no Finding is ignored. When NVD modifies a CVE, it is matched again and its Findings are rescored with the new CVSS.

## What a match becomes

A match opens a Finding for (Asset, Product, Vulnerability). The component's version is an attribute of the Finding, updated on every Sync, not part of its identity: patching nginx from 1.18.0 to 1.19.0, still vulnerable, keeps the same Finding and its Score history, and patching it to 1.20.1 closes it. Software Components have no identity of their own and are rewritten on every Sync, so a Finding cannot point at a component row.

A Finding is never deleted. It is closed, with its reason, when its match no longer holds: the version leaves the range, the component disappears, its Asset becomes Inactive or the Vulnerability is rejected. If the same (Asset, Product, Vulnerability) matches again, the same Finding is reopened. Only Active Assets are matched. The `findings` table is designed separately.

## Examples

Real `affected` entries from NVD, as the tests will use them:

| # | Product · component version | Vulnerability · NVD entry | Result |
|---|---|---|---|
| 1 | `f5:nginx` · `1.18.0` | CVE-2021-23017 · `>=0.6.18 <1.20.1` | match |
| 2 | `f5:nginx` · `1.20.1` | same | no match |
| 3 | `f5:nginx` · `0.6.18` | same | match |
| 4 | `tukaani:xz` · `5.6.1` | CVE-2024-3094 · exact `5.6.1` | match |
| 5 | `tukaani:xz` · `5.4.6` | same | no match |
| 6 | `apache:log4j` · `2.14.1` | CVE-2021-44228 · `>=2.13.0 <2.15.0` | match |
| 7 | `apache:log4j` · `2.12.2` | same · `>=2.4.0 <2.12.2` | no match |
| 8 | `apache:log4j` · `2.0-beta9` | same · exact `2.0`, update `beta9` | match |
| 9 | `openssl:openssl` · `1.0.1f` | CVE-2014-0160 · `>=1.0.1 <1.0.1g` | match |
| 10 | `openssl:openssl` · `1.0.1g` | same | no match |
| 11 | `openssl:openssl` · `1.0.1f-1ubuntu2.2` | same | match, `distro_backport` |
| 12 | `sudo_project:sudo` · `1.8.31p2` | CVE-2021-3156 · `>=1.8.2 <1.8.32` | match |
| 13 | `sudo_project:sudo` · `1.9.5p1` | same · exact `1.9.5`, update `patch1` | match, `version_unparsed` |
| 14 | `cisco:ios_xe` · `17.9.4` | CVE-2023-20198 · `>=17.9 <17.9.4a` | match |
| 15 | `canonical:ubuntu_linux` · `20.04` | CVE-2020-1472 · exact `20.04` (`lts`) | match |
| 16 | `vmware:spring_framework` · `5.3.17` | CVE-2022-22965 · `<5.3.18` AND `oracle:jdk >=9` | match (condition not checked) |
| 17 | `f5:nginx` · `latest` | CVE-2021-23017 | match, `version_unparsed` |
| 18 | no Product · `nginx 1.18.0` | CVE-2021-23017 | not evaluated |

## Deferred special cases

Each Vulnerability can describe its Products in its own way. These cases are known, are handled today by the rules above (a flagged match at worst), and can each be refined later with its own example:

- **Conditional configurations.** Rule 6 matches AND configurations as lists, so a firmware tied to its hardware, or Spring4Shell without JDK 9, still matches. Once the NVD adapter keeps what an entry requires, a `conditional` flag, or a check against the Asset's other components, can be added.
- **Update naming.** Vendors and CMDBs write updates differently (`1.9.5p1` against `patch1`, `sp1`, `r2`). They are flagged `version_unparsed` rather than mapped.
- **Version inside the product name.** Windows names releases as Products (`windows_server_2012` with version `r2`, `windows_server_1903`). This belongs to Product identification, not to matching.
- **CPE part.** The `a`/`o`/`h` field (application, operating system, hardware) is not compared with the component's role; vendor and product already identify the Product.
- **Other CPE fields.** Edition, language, `sw_edition` (`lts`, `esm`), `target_sw` and `target_hw` are ignored.
- **Distribution advisories.** Telling whether a packaging revision includes the fix needs the distributions' own advisories (Ubuntu USN, Debian DSA), which would be a new Feed.

## Considered Options

- **Drop uncertain matches**: rejected; a missed Vulnerability is silent, while a flagged one can be reviewed.
- **Backfill old CVEs**: rejected for this project; matching the whole NVD history against every Asset is out of its scope.
- **Check AND conditions against the Asset's other components**: deferred; Software Components rarely list the runtime a condition names, so it would turn real matches into misses.
- **Compare only the range bounds**: rejected; 415 of the 647 sample entries name an exact version and have no bounds, so they would all read as "every version".
- **Treat any text after the version as a distribution revision**: rejected; `1.0.1f`, `17.9.4a` and `1.8.31p2` are upstream versions.
- **A boolean "uncertain" on the Finding**: rejected; it cannot say what is uncertain.
- **Postgres `ENUM` or `text[]` for Match Flags**: rejected, as in ADR 0006.
- **The component version as part of the Finding's identity**: rejected; patching to a version that is still vulnerable would close one Finding and open another for the same problem, splitting its Score history.

## Consequences

- Matching needs Products. The iTop adapter fills the Product of an Application from its linked Software (ADR 0002), but as free text (`Apache`/`Apache HTTP Server` where NVD has `apache`/`http_server`), so it matches no CPE until Products are normalized (ADR 0010, "How a Product is keyed").
- Vulnerabilities are stored only when they open a Finding, instead of one row per STIX object as ADR 0010's "Storage" section intended. A Vulnerability that matched nothing when it arrived is not kept, and is never matched again unless NVD modifies it.
- The NVD adapter stores each entry's exact `version` and `update`, a minor version of `nvd/1`.
- EPSS publishes a score for every CVE each day, but only the few with Findings are rescored.
