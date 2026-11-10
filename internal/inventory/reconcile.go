package inventory

import (
	"errors"
	"fmt"
	"slices"
)

var (
	ErrInvalidSnapshot       = errors.New("invalid snapshot")
	ErrInvalidExistingAssets = errors.New("invalid existing assets")
	ErrInvalidExistingAreas  = errors.New("invalid existing areas")
)

type SyncCounts struct {
	Created, Updated, Deactivated, Reactivated, Skipped int
}

// Reconciliation is built only by Reconcile, so whoever stores it can rely on
// its Assets and Areas being consistent with one Snapshot of one CMDB Source.
// Updated Assets are those whose imported values changed; an Updated Asset can
// also be Deactivated or Reactivated, while a Created Asset is in no other list.
type Reconciliation struct {
	source      CMDBSourceID
	created     []*Asset
	updated     []*Asset
	deactivated []*Asset
	reactivated []*Asset
	skipped     []SkippedRecord
	areas       AreaChanges
}

// AreaChanges follows the same rules as the Asset lists of a Reconciliation:
// a Renamed Area can also be Deactivated or Reactivated, while a Created Area
// is in no other list.
type AreaChanges struct {
	Created, Renamed, Deactivated, Reactivated []*Area
}

func (r Reconciliation) Source() CMDBSourceID { return r.source }

func (r Reconciliation) Created() []*Asset { return slices.Clone(r.created) }

func (r Reconciliation) Updated() []*Asset { return slices.Clone(r.updated) }

func (r Reconciliation) Deactivated() []*Asset { return slices.Clone(r.deactivated) }

func (r Reconciliation) Reactivated() []*Asset { return slices.Clone(r.reactivated) }

func (r Reconciliation) Skipped() []SkippedRecord { return slices.Clone(r.skipped) }

func (r Reconciliation) Areas() AreaChanges {
	return AreaChanges{
		Created:     slices.Clone(r.areas.Created),
		Renamed:     slices.Clone(r.areas.Renamed),
		Deactivated: slices.Clone(r.areas.Deactivated),
		Reactivated: slices.Clone(r.areas.Reactivated),
	}
}

// Counts covers Assets only: a Sync Run does not count Areas.
func (r Reconciliation) Counts() SyncCounts {
	return SyncCounts{
		Created:     len(r.created),
		Updated:     len(r.updated),
		Deactivated: len(r.deactivated),
		Reactivated: len(r.reactivated),
		Skipped:     len(r.skipped),
	}
}

// Stored is what a CMDB Source has in barbattack before a Sync.
type Stored struct {
	Assets []*Asset
	Areas  []*Area
}

// Reconcile applies the Sync rules (ADR 0005) to the stored Assets and Areas
// of one CMDB Source and a complete Snapshot of it. It takes ownership of
// existing and changes those Assets and Areas in place; on error none of them
// has been changed.
func Reconcile(source CMDBSourceID, existing Stored, s Snapshot) (Reconciliation, error) {
	if source == (CMDBSourceID{}) {
		return Reconciliation{}, fmt.Errorf("%w: zero source", ErrInvalidSourceReference)
	}
	storedAssets, err := indexExisting(source, existing.Assets, ErrInvalidExistingAssets)
	if err != nil {
		return Reconciliation{}, err
	}
	storedAreas, err := indexExisting(source, existing.Areas, ErrInvalidExistingAreas)
	if err != nil {
		return Reconciliation{}, err
	}
	skipped, err := validateSnapshot(s)
	if err != nil {
		return Reconciliation{}, err
	}

	r := Reconciliation{source: source, skipped: slices.Clone(s.Skipped)}
	r.reconcileAreas(source, storedAreas, existing.Areas, s.Areas)
	present := make(map[string]bool, len(s.Records))
	for _, rec := range s.Records {
		present[rec.RecordID] = true
		a, ok := storedAssets[rec.RecordID]
		if !ok {
			r.created = append(r.created, create(source, rec))
			continue
		}
		r.update(a, rec.Imported)
	}
	for _, a := range existing.Assets {
		id := a.Ref().RecordID
		if !present[id] && !skipped[id] {
			r.setActive(a, false)
		}
	}
	return r, nil
}

func indexExisting[T interface{ Ref() SourceReference }](source CMDBSourceID, existing []T, invalid error) (map[string]T, error) {
	stored := make(map[string]T, len(existing))
	for _, e := range existing {
		ref := e.Ref()
		if ref.Source != source {
			return nil, fmt.Errorf("%w: %v belongs to another source", invalid, ref)
		}
		if _, dup := stored[ref.RecordID]; dup {
			return nil, fmt.Errorf("%w: duplicate record id %q", invalid, ref.RecordID)
		}
		stored[ref.RecordID] = e
	}
	return stored, nil
}

func validateSnapshot(s Snapshot) (map[string]bool, error) {
	areas, err := validateAreas(s.Areas)
	if err != nil {
		return nil, err
	}
	skipped := make(map[string]bool, len(s.Skipped))
	for _, sr := range s.Skipped {
		if blank(sr.RecordID) {
			return nil, fmt.Errorf("%w: skipped record with empty record id", ErrInvalidSnapshot)
		}
		if skipped[sr.RecordID] {
			return nil, fmt.Errorf("%w: record %q skipped twice", ErrInvalidSnapshot, sr.RecordID)
		}
		skipped[sr.RecordID] = true
	}
	seen := make(map[string]bool, len(s.Records))
	for _, rec := range s.Records {
		switch {
		case blank(rec.RecordID):
			return nil, fmt.Errorf("%w: record with empty record id", ErrInvalidSnapshot)
		case seen[rec.RecordID]:
			return nil, fmt.Errorf("%w: duplicate record %q", ErrInvalidSnapshot, rec.RecordID)
		case skipped[rec.RecordID]:
			return nil, fmt.Errorf("%w: record %q is both imported and skipped", ErrInvalidSnapshot, rec.RecordID)
		case rec.Imported.isZero():
			return nil, fmt.Errorf("record %q: %w", rec.RecordID, ErrZeroImportedAsset)
		}
		// A provider bug naming an Area it did not read must fail the Sync,
		// not store an Asset whose Area does not exist.
		if area, ok := rec.Imported.Area(); ok && !areas[area] {
			return nil, fmt.Errorf("%w: record %q names unknown area %q", ErrInvalidSnapshot, rec.RecordID, area)
		}
		seen[rec.RecordID] = true
	}
	return skipped, nil
}

func validateAreas(areas []AreaRecord) (map[string]bool, error) {
	seen := make(map[string]bool, len(areas))
	for _, rec := range areas {
		switch {
		case blank(rec.RecordID):
			return nil, fmt.Errorf("%w: area with empty record id", ErrInvalidSnapshot)
		case seen[rec.RecordID]:
			return nil, fmt.Errorf("%w: duplicate area %q", ErrInvalidSnapshot, rec.RecordID)
		case rec.Imported.isZero():
			return nil, fmt.Errorf("area %q: %w", rec.RecordID, ErrZeroImportedArea)
		}
		seen[rec.RecordID] = true
	}
	return seen, nil
}

// reconcileAreas never reads an owner from the Snapshot: only a Customer Admin
// states it, so a Sync keeps it.
func (r *Reconciliation) reconcileAreas(source CMDBSourceID, stored map[string]*Area, existing []*Area, snapshot []AreaRecord) {
	present := make(map[string]bool, len(snapshot))
	for _, rec := range snapshot {
		present[rec.RecordID] = true
		a, ok := stored[rec.RecordID]
		if !ok {
			r.areas.Created = append(r.areas.Created, &Area{
				ref:      SourceReference{Source: source, RecordID: rec.RecordID},
				imported: rec.Imported,
				active:   !rec.Imported.Inactive(),
			})
			continue
		}
		if a.imported.Name() != rec.Imported.Name() {
			r.areas.Renamed = append(r.areas.Renamed, a)
		}
		a.imported = rec.Imported
		r.setAreaActive(a, !rec.Imported.Inactive())
	}
	for _, a := range existing {
		if !present[a.Ref().RecordID] {
			r.setAreaActive(a, false)
		}
	}
}

func (r *Reconciliation) setAreaActive(a *Area, active bool) {
	switch {
	case active && !a.active:
		a.active = true
		r.areas.Reactivated = append(r.areas.Reactivated, a)
	case !active && a.active:
		a.active = false
		r.areas.Deactivated = append(r.areas.Deactivated, a)
	}
}

func create(source CMDBSourceID, rec Record) *Asset {
	return &Asset{
		ref:      SourceReference{Source: source, RecordID: rec.RecordID},
		imported: rec.Imported,
		active:   !rec.Imported.Retired(),
	}
}

func (r *Reconciliation) update(a *Asset, imported ImportedAsset) {
	if !a.Imported().equal(imported) {
		a.imported = imported
		r.updated = append(r.updated, a)
	}
	r.setActive(a, !imported.Retired())
}

func (r *Reconciliation) setActive(a *Asset, active bool) {
	switch {
	case active && !a.Active():
		a.Reactivate()
		r.reactivated = append(r.reactivated, a)
	case !active && a.Active():
		a.MarkInactive()
		r.deactivated = append(r.deactivated, a)
	}
}
