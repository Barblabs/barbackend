---
status: proposed
---

# Areas are imported Organizations owned by their CMDB Source, and their owner is stated, never imported

A Customer's Assets sit in parts of its organization, and each part has someone to reach about it. iTop calls such a part an Organization and gives every CI one (`org_id` is mandatory). barbattack imports them as **Areas**: a Sync reads every Organization of the CMDB Source, inactive ones included, and each Asset references the Area its CI belongs to. A Customer Admin states each Area's **Area Owner** email, which a Sync never touches.

## The Snapshot carries Areas, complete like its Records

`inventory.Snapshot` gains `Areas []AreaRecord` beside `Records`, and `ImportedAsset` names its Area by the Area's record id. An Area left out of a Snapshot would be deactivated, so a provider reads all of them, not only those its CIs reference (ADR 0007). `inventory.Reconcile` takes the stored Areas with the stored Assets (`inventory.Stored`) and reconciles both in the same pure call, inside the same `CommitSync` transaction and row lock, so a failed Sync changes no Area either. Areas are written before the Assets that reference them.

- **An Asset whose Area is not in the Snapshot is a Skipped Record.** The iTop provider skips a CI whose `org_id` is not among the Organizations it read ("organization <id> is not readable"), so its Asset stays as it was rather than losing its Area silently. `Reconcile` rejects a Snapshot whose Asset names an unknown Area (`ErrInvalidSnapshot`), so a provider bug fails the Sync instead of storing a dangling reference.
- **An Asset whose Area changed is Updated**, like any other imported value. The first Sync after Areas shipped reported every Asset as Updated.
- **The Sync Run does not count Areas.** Its counts and the `POST /cmdb/source/sync` response cover Assets only, so creating, renaming, deactivating or reactivating an Area changes no count; `GET /areas` shows the result.

## An Area is keyed by its Source Reference

`customer_areas` is unique on `(cmdb_source_id, record_id)`, like `assets`, and `assets` references its Area by that pair (`cmdb_source_id, area_record_id`) through a composite foreign key. iTop ids mean something only inside their instance, and a rename in iTop keeps the row and its owner email. Referencing the Source Reference rather than the surrogate `id` lets Postgres itself guarantee that an Asset's Area belongs to the Asset's own CMDB Source, and lets the Asset insert (COPY) write the record id with no id map. `customer_areas.id` stays as the handle the HTTP API uses.

After a disconnect and a reconnect, the new CMDB Source gets new Areas, and a Customer Admin states their owners again. CMDB Sources are never deleted, so the old Areas stay as Inactive history.

## An Area is Inactive or Active, never deleted

An Area becomes Inactive when its CMDB Source marks it inactive (iTop's `inactive` status), no longer returns it, or is disconnected. `inactive_since` keeps the first time, as for Assets. It becomes Active again when it returns as active, with its owner intact. Unlike Assets (ADR 0005), there is no separate retired value: the provider's status is folded into Active, since nothing needs to tell the two apart. Assets that still reference an Inactive Area keep showing it.

## Areas are flat

The fetch does not read `parent_id`: a child Organization is an Area like any other. A nullable parent and one more fetched field can come when a feature needs owners to pass down a hierarchy.

## The Area Owner is a stated email, apart from Asset Owners

`customer_areas.owner_email` holds it, with no link to `asset_owners`. It is a different role: whom barbattack reaches about an Area, who need not be a User nor own any Asset. Tying the two would change Asset ownership (ADR 0003) for a feature that did not ask for it, so `Asset.Owner()` is unchanged. The domain reuses `inventory.OwnerEmail` for its canonical form (trimmed, lowercased); syntax is checked at the HTTP edge, as ADR 0003 requires.

It follows the imported-versus-declared split of ADR 0004 in its strictest form: nothing imports it. Only a Customer Admin states or clears it, through `PUT /areas/{id}/owner`, gated by `tenancy.User.ManageAreas`. `Reconcile` never reads an owner from a Snapshot, so every Sync keeps it, renames included.

## Where the code goes

This adds a use-case package to ADR 0008:

```
internal/
  areas/   use cases on Areas: list them, state their owners -> inventory, postgres, tenancy
```

`httpapi` serves it: `GET /areas` for any User of the Customer, which lists the Areas of every CMDB Source of the Customer, Disconnected ones included, filtered by `active` and not paged, and `PUT /areas/{id}/owner` for a Customer Admin. `GET /assets` shows each Asset's Area as `{id, name}`.

## Considered Options

- **Keying an Area by `(customer_id, name)`**: rejected; a rename in the CMDB Source would look like a new Area and lose its owner.
- **Referencing the Area by `customer_areas.id` from `assets`**: rejected; Postgres could not check that the Area belongs to the Asset's CMDB Source, and the Asset insert would need an id map.
- **Storing the Area Owner in `asset_owners`, or making it the fallback owner of its Assets**: rejected; the roles differ, and it would change who owns an Asset.
- **Importing an Asset with no Area when its Organization is unreadable**: rejected; the Asset would silently lose its Area.
- **Deleting an Area that leaves its CMDB Source**: rejected; it would lose the owner and break the Assets that reference it.
- **Importing the Organization hierarchy now**: deferred; it forces decisions on missing parents, cycles and owner inheritance with no feature asking for them.
- **Counting Areas in the Sync Run**: deferred; four more columns and response fields with no reader yet.
