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

// Change is one Asset a Reconciliation creates or modifies. A created Asset
// is new as a whole, so its other flags are false.
type Change struct {
	Asset           *Asset
	Created         bool
	ImportedChanged bool
	ActiveChanged   bool
}

type SyncCounts struct {
	Created, Updated, Deactivated, Reactivated, Skipped int
}

// Reconciliation is built only by Reconcile, so whoever stores it can rely on
// its Changes being consistent with one Snapshot of one CMDB Source.
type Reconciliation struct {
	source     CMDBSourceID
	changes    []Change
	rejections []Rejection
}

func (r Reconciliation) Source() CMDBSourceID { return r.source }

func (r Reconciliation) Changes() []Change { return slices.Clone(r.changes) }

func (r Reconciliation) Rejections() []Rejection { return slices.Clone(r.rejections) }

func (r Reconciliation) Counts() SyncCounts {
	counts := SyncCounts{Skipped: len(r.rejections)}
	for _, c := range r.changes {
		switch {
		case c.Created:
			counts.Created++
		case c.ActiveChanged && c.Asset.Active():
			counts.Reactivated++
		case c.ActiveChanged:
			counts.Deactivated++
		}
		if c.ImportedChanged {
			counts.Updated++
		}
	}
	return counts
}

// Reconcile applies the Sync rules (ADR 0005) to the stored Assets of one CMDB
// Source and a complete Snapshot of it. It takes ownership of existing and
// changes those Assets in place; on error none of them has been changed.
func Reconcile(source CMDBSourceID, existing []*Asset, s Snapshot) (Reconciliation, error) {
	stored, err := indexExisting(source, existing)
	if err != nil {
		return Reconciliation{}, err
	}
	rejected, err := validateSnapshot(s)
	if err != nil {
		return Reconciliation{}, err
	}

	r := Reconciliation{source: source, rejections: slices.Clone(s.Rejections)}
	present := make(map[string]bool, len(s.Records))
	for _, rec := range s.Records {
		present[rec.RecordID] = true
		a, ok := stored[rec.RecordID]
		if !ok {
			c, err := create(source, rec)
			if err != nil {
				return Reconciliation{}, err
			}
			r.changes = append(r.changes, c)
			continue
		}
		c, err := update(a, rec.Imported)
		if err != nil {
			return Reconciliation{}, err
		}
		if c.ImportedChanged || c.ActiveChanged {
			r.changes = append(r.changes, c)
		}
	}
	// A rejected record is still in the CMDB Source, so its Asset is not missing.
	for _, a := range existing {
		id := a.Ref().RecordID
		if !present[id] && !rejected[id] && a.Active() {
			a.MarkInactive()
			r.changes = append(r.changes, Change{Asset: a, ActiveChanged: true})
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
// any Asset is changed, and returns the rejected record ids.
func validateSnapshot(s Snapshot) (map[string]bool, error) {
	rejected := make(map[string]bool, len(s.Rejections))
	for _, rej := range s.Rejections {
		if blank(rej.RecordID) {
			return nil, fmt.Errorf("%w: rejection with empty record id", ErrInvalidSnapshot)
		}
		if rejected[rej.RecordID] {
			return nil, fmt.Errorf("%w: record %q rejected twice", ErrInvalidSnapshot, rej.RecordID)
		}
		rejected[rej.RecordID] = true
	}
	seen := make(map[string]bool, len(s.Records))
	for _, rec := range s.Records {
		switch {
		case blank(rec.RecordID):
			return nil, fmt.Errorf("%w: record with empty record id", ErrInvalidSnapshot)
		case seen[rec.RecordID]:
			return nil, fmt.Errorf("%w: duplicate record %q", ErrInvalidSnapshot, rec.RecordID)
		case rejected[rec.RecordID]:
			return nil, fmt.Errorf("%w: record %q is both imported and rejected", ErrInvalidSnapshot, rec.RecordID)
		case rec.Imported.isZero():
			return nil, fmt.Errorf("record %q: %w", rec.RecordID, ErrZeroImportedAsset)
		}
		seen[rec.RecordID] = true
	}
	return rejected, nil
}

func create(source CMDBSourceID, rec Record) (Change, error) {
	a, err := NewAsset(SourceReference{Source: source, RecordID: rec.RecordID}, rec.Imported)
	if err != nil {
		return Change{}, fmt.Errorf("record %q: %w", rec.RecordID, err)
	}
	if rec.Imported.Retired() {
		a.MarkInactive()
	}
	return Change{Asset: a, Created: true}, nil
}

// update keeps an Asset present in the Snapshot Active exactly when its
// record is not reported as retired.
func update(a *Asset, imported ImportedAsset) (Change, error) {
	c := Change{Asset: a}
	if !a.Imported().equal(imported) {
		if err := a.ReplaceImported(imported); err != nil {
			return Change{}, fmt.Errorf("record %q: %w", a.Ref().RecordID, err)
		}
		c.ImportedChanged = true
	}
	switch active := !imported.Retired(); {
	case active && !a.Active():
		a.Reactivate()
		c.ActiveChanged = true
	case !active && a.Active():
		a.MarkInactive()
		c.ActiveChanged = true
	}
	return c, nil
}
