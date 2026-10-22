---
status: proposed
---

# Feeds are normalized to STIX 2.1 on ingestion, with `github.com/TcM1911/stix2`

Every Feed speaks its own format: NVD returns CVE JSON, EPSS a CSV or JSON of probabilities, the CISA KEV catalog its own JSON, MITRE ATT&CK a STIX 2.1 bundle. Each Feed adapter converts what it reads into STIX 2.1 objects as soon as it receives them. After that, everything downstream (filters that match Vulnerabilities to Software Components, scoring, agents, exports) reads one format and never a Feed's own. The adapter is the only code that knows a Feed's format, just as a CMDB Provider adapter is the only code that knows its provider's (ADR 0007).

We use [`github.com/TcM1911/stix2`](https://github.com/TcM1911/stix2), pinned at `v0.10.4`. It is pure Go, covers every STIX 2.1 object, including `extension-definition` and property extensions, parses foreign bundles (ATT&CK) and keeps their custom `x_` properties readable.

## Where the code goes

This adds layers to ADR 0008. Its table must be updated, and `depguard` must get rules for them, when the first one lands:

```
internal/
  feeds/               Feed seam                       -> stixext
    <feed>/            adapters: nvd, epss, kev, attack -> feeds, stixext
  stixext/             barbattack's STIX conventions    -> nothing internal (stix2, uuid)
```

`internal/stixext` is pure, with no I/O. It holds everything in this ADR that more than one package needs: the identifier helpers, the `extension-definition` objects, the typed Go structs for each extension and their decode helpers, and the barbattack Identity and TLP marking constants. Feed adapters write with it, and threat matching (ADR 0008) reads with it. Only `feeds/...` and `stixext` construct STIX objects. Other packages read them through `stixext`, so a change of library touches only these two places.

## What objects to create

| barbattack term | STIX 2.1 object | Notes |
|---|---|---|
| Vulnerability | `vulnerability` SDO | One per CVE, shared by every Feed. `name` is the CVE ID. |
| Feed data about a Vulnerability (CVSS, EPSS, KEV) | property extension on that `vulnerability` | One extension per Feed. See below. |
| barbattack itself | `identity` SDO, `identity_class: "system"` | `created_by_ref` of every object we mint. |
| Feed (provenance) | `external_references` entry + its extension | Not an Identity: the Feed is a source, not the producer of the normalized object. |
| ATT&CK technique, tactic, group, etc. | MITRE's own objects, unchanged | Do not re-mint IDs or translate `x_mitre_*` properties. |
| Advisory or news item (later) | `report` SDO with `object_refs` to Vulnerabilities | Its text is untrusted data. |
| Asset, Software Component, Finding, Score | none for now | These belong to the Customer and live in Postgres. Exporting them to STIX (e.g. `infrastructure`, `software`, `sighting`) is a separate decision. |

Do not create `software` SCOs or `relationship` objects for affected products in this version. A `software` object holds a single version, but NVD says "every version from 2.4.0 up to but not including 2.4.58". The affected ranges go in the NVD extension instead, where filters can compare them with a Software Component's version.

Do not create relationships between CVEs and ATT&CK techniques: no Feed provides them (ADR 0009).

## Identifiers are deterministic

The library gives SDOs a random UUIDv4. We override it so that the same CVE always gets the same ID, whichever Feed sees it first and however many times it is re-ingested:

```go
// internal/stixext
var namespace = uuid.NewSHA1(uuid.NameSpaceURL, []byte("https://github.com/Barblabs/barbackend/stix"))

func ID(typ stix2.STIXType, key string) stix2.Identifier {
	return stix2.Identifier(fmt.Sprintf("%s--%s", typ, uuid.NewSHA1(namespace, []byte(string(typ)+":"+key))))
}

func VulnerabilityID(cveID string) stix2.Identifier { return ID(stix2.TypeVulnerability, cveID) } // cveID already upper-cased
```

- `vulnerability`: key is the CVE ID, trimmed and upper-cased (`CVE-2024-3094`). Reject anything that does not match `^CVE-\d{4}-\d{4,}$`.
- barbattack `identity`: `ID(stix2.TypeIdentity, "barbattack")`.
- `extension-definition`: `ID(stix2.TypeExtensionDefinition, "<feed>/<major version>")`, e.g. `"nvd/1"`.
- SCOs, if any are ever created, keep the library's IDs. Those are already UUIDv5s defined by the spec.
- Foreign objects (ATT&CK) keep their own IDs.

Because IDs are deterministic, EPSS or KEV can deliver a CVE before NVD has published it. The adapter that sees it first creates the `vulnerability` with only its `name` and its own extension, and NVD fills in the rest later.

## Extensions

STIX 2.1 deprecates custom top-level properties (`x_...`). New data goes in a property extension: the object's `extensions` map holds an entry keyed by the ID of an `extension-definition` object, and its value carries `"extension_type": "property-extension"`. Each Feed owns exactly one extension. An adapter writes only its own and leaves the others untouched, so two Feeds never overwrite each other.

The `extension-definition` objects are created once in `stixext` with `stix2.NewExtensionDefinition(name, schema, version, []stix2.ExtensionType{stix2.ExtensionTypePropertyExtension}, ...)`. They get the ID derived above, `created_by_ref` set to the barbattack identity and `schema` set to this ADR's URL. They are included in every bundle barbattack exports. Changing a field's meaning or removing a field means a new major version (`nvd/2`) with a new ID, never an edit of the old one, like Scoring Models (ADR 0009). Adding an optional field is a minor version bump of the same definition.

### `nvd/1`: from the NVD CVE API

| Field | Type | Meaning |
|---|---|---|
| `published`, `last_modified` | timestamp | NVD's own dates for the CVE |
| `vuln_status` | string | NVD status as given (`Analyzed`, `Awaiting Analysis`, `Rejected`...) |
| `cvss` | list | Every CVSS metric NVD returns: `{version, base_score, vector, source, type}`, with `type` `Primary` or `Secondary`. Keep all of them. Choosing one is scoring's job (ADR 0009), not normalization's. |
| `cwes` | list of string | `CWE-79`, ... |
| `affected` | list | One entry per CPE match with `vulnerable: true`: `{criteria, vendor, product, version_start_including, version_start_excluding, version_end_including, version_end_excluding}`. `vendor` and `product` are the CPE 2.3 tokens split out of `criteria`. Absent bounds are omitted. |

The CVE's English description goes in the SDO's `description`. NVD's reference URLs go in `external_references`, after the required `{"source_name": "cve", "external_id": "CVE-..."}` entry, which must always come first.

NVD configurations can say "vulnerable only when running on X" (AND nodes). `nvd/1` flattens them to the vulnerable matches and loses that condition. That is a known over-match, accepted for this version.

### `epss/1`: from FIRST EPSS

| Field | Type | Meaning |
|---|---|---|
| `probability` | number 0–1 | The EPSS score. This is what scoring uses (ADR 0009). |
| `percentile` | number 0–1 | Kept for display only |
| `score_date` | date | The day the score was computed for |
| `model_version` | string | e.g. `v2025.03.14`, when the Feed provides it |

### `kev/1`: from the CISA KEV catalog

| Field | Type | Meaning |
|---|---|---|
| `date_added`, `due_date` | date | As in the catalog |
| `required_action` | string | As in the catalog (untrusted text) |
| `known_ransomware_campaign_use` | string | `Known` or `Unknown` |
| `vendor_project`, `product` | string | As in the catalog |
| `catalog_version`, `catalog_released` | string, timestamp | The catalog read that last confirmed this entry |

Having the extension means the CVE is in the catalog. If a later catalog read no longer lists it, the KEV adapter removes the extension. Whether the catalog itself is stale (`kev_stale`, ADR 0009) is a property of the Feed's last successful read, not of any CVE. The ingestion records it, not the STIX objects.

### Writing and reading an extension

```go
type EPSS struct {
	ExtensionType string  `json:"extension_type"` // always "property-extension"
	Probability   float64 `json:"probability"`
	Percentile    float64 `json:"percentile"`
	ScoreDate     string  `json:"score_date"` // YYYY-MM-DD
	ModelVersion  string  `json:"model_version,omitempty"`
}

v, err := stix2.NewVulnerability(cveID,
	stix2.OptionCreatedBy(stixext.BarbattackID),
	stix2.OptionExternalReferences([]*stix2.ExternalReference{{Name: "cve", ExternalID: cveID}}),
	stix2.OptionObjectMarking([]stix2.Identifier{stixext.TLPClear}),
	stix2.OptionExtension(string(stixext.EPSSDefinitionID), stixext.NewEPSS(p, pct, date, model)),
)
v.ID = stixext.VulnerabilityID(cveID)
```

When a bundle is parsed, the library returns any extension it does not know as a `*stix2.CustomObject`. `stixext` exposes decode helpers such as `stixext.EPSSOf(v) (EPSS, bool)` that re-marshal that value into the typed struct. Filters and scoring use those helpers and never read the map by hand.

## Rules for every adapter

- **Timestamps**: always UTC. `created` is when barbattack first minted the object. `modified` changes only when the object's content changes, so re-ingesting identical data leaves it alone. A Feed's own dates go inside its extension, never in `created` or `modified`.
- **One current version**: store the latest version of each object by ID, and do not keep STIX version history. Score history (ADR 0009) already records what changed when it mattered.
- **Markings**: all of today's Feeds are public, so every minted object gets the STIX 2.1 predefined TLP:CLEAR marking (`marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487`).
- **Bad records**: a record that cannot be normalized (no valid CVE ID, an unparsable score) is skipped and logged with its reason. It does not fail the whole read. Adapters emit objects one at a time as they parse them, so a Feed never has to fit in memory. A read that cannot complete stops emitting; the objects already emitted stay, and deterministic IDs make a re-pull idempotent.
- **Untrusted text**: descriptions, required actions and report text are stored as data and are never interpolated into an agent's instructions (see Feed in `GLOSSARY.md`).
- **Validation**: the library's constructors check required properties. Adapter tests should also round-trip each produced bundle through `stix2.FromJSON` and assert on the decoded extensions.

## Storage

The schema is not decided by this ADR and comes with the first Feed's migration. The intended shape is one row per STIX object ID, holding its type, `modified` and the object as `jsonb`. Each adapter updates only its own extension key, in one statement, so two Feeds writing the same `vulnerability` at once cannot lose each other's data. Columns that filters need often (the CVE ID, the affected `vendor`/`product` pairs) may be extracted next to the `jsonb` when the filters need them.

## Open questions

- **How a Product is keyed**: filters match `nvd/1.affected` `vendor`/`product` against `software_components.product_vendor`/`product_name`. Today those columns hold free text (`Canonical`/`Ubuntu`, `f5`/`nginx`). For matching to work, a Product must be keyed by the CPE 2.3 vendor and product tokens (`canonical`/`ubuntu_linux`). This has to be agreed with whoever owns Product identification before the filters are built.
- **cve.org and CISA Vulnrichment**: ADR 0009 falls back to them for CVSS. They will be their own Feed with their own extension, not fields of `nvd/1`.
- **TAXII**: neither publishing nor consuming TAXII is in scope. A TAXII server would only serve the objects described here.

## Considered Options

- **`github.com/freetaxii/libstix2`**: rejected. Its last tagged release is `v0.6.1` from 2020, and its STIX 2.1 support is incomplete.
- **Our own Go structs, no library**: rejected. We would re-implement IDs, timestamps, required-property checks and parsing of foreign bundles such as ATT&CK, for every object type.
- **The OASIS Python `stix2` library in a separate service**: rejected. It would add a second language and a network hop just for serialization.
- **Custom top-level `x_barbattack_*` properties instead of extensions**: rejected. They are deprecated in STIX 2.1, and consumers cannot discover their schema.
- **Normalizing later, at filtering time**: rejected. Every consumer would have to know every Feed's format.

## Consequences

- `github.com/TcM1911/stix2 v0.10.4` becomes a dependency. Its last release is from October 2024 and it has one maintainer. Keeping it behind `feeds` and `stixext` limits the cost of forking or replacing it.
- The library's own dependencies (`google/uuid`, `gojsonschema`) are small. `govulncheck` covers them like any other module.
