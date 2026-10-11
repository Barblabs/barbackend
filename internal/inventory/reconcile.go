package inventory

import (
	"errors"
	"fmt"
	"slices"
)

var (
	ErrInvalidSnapshot       = errors.New("invalid snapshot")
	ErrInvalidExistingAssets = errors.New("invalid existing assets")
)

type SyncCounts struct {
	Created, Updated, Deactivated, Reactivated, Skipped int
}

// Reconciliation is built only by Reconcile, so whoever stores it can rely on
// its Assets being consistent with one Snapshot of one CMDB Source. Updated
// Assets are those whose imported values changed; an Updated Asset can also be
// Deactivated or Reactivated, while a Created Asset is in no other list.
type Reconciliation struct {
	source      CMDBSourceID
	created     []*Asset
	updated     []*Asset
	deactivated []*Asset
	reactivated []*Asset
	skipped     []SkippedRecord
}

func (r Reconciliation) Source() CMDBSourceID { return r.source }

func (r Reconciliation) Created() []*Asset { return slices.Clone(r.created) }

func (r Reconciliation) Updated() []*Asset { return slices.Clone(r.updated) }

func (r Reconciliation) Deactivated() []*Asset { return slices.Clone(r.deactivated) }

func (r Reconciliation) Reactivated() []*Asset { return slices.Clone(r.reactivated) }

func (r Reconciliation) Skipped() []SkippedRecord { return slices.Clone(r.skipped) }

func (r Reconciliation) Counts() SyncCounts {
	return SyncCounts{
		Created:     len(r.created),
		Updated:     len(r.updated),
		Deactivated: len(r.deactivated),
		Reactivated: len(r.reactivated),
		Skipped:     len(r.skipped),
	}
}

// Reconcile applies the Sync rules (ADR 0005) to the stored Assets of one CMDB
// Source and a complete Snapshot of it. It takes ownership of existing and
// changes those Assets in place; on error none of them has been changed.
func Reconcile(source CMDBSourceID, existing []*Asset, s Snapshot) (Reconciliation, error) {
	stored, err := indexExisting(source, existing)
	if err != nil {
		return Reconciliation{}, err
	}
	skipped, err := validateSnapshot(s)
	if err != nil {
		return Reconciliation{}, err
	}

	r := Reconciliation{source: source, skipped: slices.Clone(s.Skipped)}
	present := make(map[string]bool, len(s.Records))
	for _, rec := range s.Records {
		present[rec.RecordID] = true
		a, ok := stored[rec.RecordID]
		if !ok {
			created, err := create(source, rec)
			if err != nil {
				return Reconciliation{}, err
			}
			r.created = append(r.created, created)
			continue
		}
		r.update(a, rec.Imported)
	}
	// A Skipped Record is still in the CMDB Source, so its Asset is not missing.
	for _, a := range existing {
		id := a.Ref().RecordID
		if !present[id] && !skipped[id] {
			r.setActive(a, false)
		}
	}
	return r, nil
}

func indexExisting(source CMDBSourceID, existing []*Asset) (map[string]*Asset, error) {
	stored := make(map[string]*Asset, len(existing))
	for _, a := range existing {
		ref := a.Ref()
		if ref.Source != source {
			return nil, fmt.Errorf("%w: %v belongs to another source", ErrInvalidExistingAssets, ref)
		}
		if _, dup := stored[ref.RecordID]; dup {
			return nil, fmt.Errorf("%w: duplicate record id %q", ErrInvalidExistingAssets, ref.RecordID)
		}
		stored[ref.RecordID] = a
	}
	return stored, nil
}

// validateSnapshot checks everything that could make Reconcile fail before
// any Asset is changed, and returns the ids of the Skipped Records.
func validateSnapshot(s Snapshot) (map[string]bool, error) {
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
		seen[rec.RecordID] = true
	}
	return skipped, nil
}

func create(source CMDBSourceID, rec Record) (*Asset, error) {
	a, err := NewAsset(SourceReference{Source: source, RecordID: rec.RecordID}, rec.Imported)
	if err != nil {
		return nil, fmt.Errorf("record %q: %w", rec.RecordID, err)
	}
	if rec.Imported.Retired() {
		a.MarkInactive()
	}
	return a, nil
}

// update keeps an Asset present in the Snapshot Active exactly when its
// record is not reported as retired.
func (r *Reconciliation) update(a *Asset, imported ImportedAsset) {
	if !a.Imported().equal(imported) {
		// ReplaceImported only rejects a zero ImportedAsset, which
		// validateSnapshot has already ruled out.
		_ = a.ReplaceImported(imported)
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
