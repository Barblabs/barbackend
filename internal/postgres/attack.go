package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"barbackend/internal/postgres/sqlcgen"
	"github.com/jackc/pgx/v5"
)

// AttackTechnique is an ATT&CK Technique of the stored catalog (ADR 0023):
// its STIX object is opaque here, and its use case decodes it.
type AttackTechnique struct {
	ID         string
	AttackID   string
	Name       string
	Tactics    []string
	Revoked    bool
	Deprecated bool
	Object     json.RawMessage
	Modified   time.Time
}

// AttackMitigation is an ATT&CK Mitigation of the stored catalog.
type AttackMitigation struct {
	ID       string
	AttackID string
	Name     string
	Object   json.RawMessage
	Modified time.Time
}

// AttackRelationship is a mitigates or revoked-by relationship of the stored
// catalog, between two STIX ids.
type AttackRelationship struct {
	ID          string
	Type        string
	Source      string
	Target      string
	Description string
	Modified    time.Time
}

// TechniqueMitigation is a Mitigation of one Technique, with its advice for
// that Technique.
type TechniqueMitigation struct {
	AttackID string
	Name     string
	Advice   string
}

// StoreAttackTechnique stores t, or replaces it with a later modification.
func (t *Tx) StoreAttackTechnique(ctx context.Context, technique AttackTechnique) error {
	if err := t.q.UpsertAttackTechnique(ctx, sqlcgen.UpsertAttackTechniqueParams{
		ID: technique.ID, AttackID: technique.AttackID, Name: technique.Name, Tactics: technique.Tactics,
		Revoked: technique.Revoked, Deprecated: technique.Deprecated, Object: technique.Object, ModifiedAt: technique.Modified,
	}); err != nil {
		return fmt.Errorf("store technique %s: %w", technique.AttackID, err)
	}
	return nil
}

// StoreAttackMitigation stores m, or replaces it with a later modification.
func (t *Tx) StoreAttackMitigation(ctx context.Context, m AttackMitigation) error {
	if err := t.q.UpsertAttackMitigation(ctx, sqlcgen.UpsertAttackMitigationParams{
		ID: m.ID, AttackID: m.AttackID, Name: m.Name, Object: m.Object, ModifiedAt: m.Modified,
	}); err != nil {
		return fmt.Errorf("store mitigation %s: %w", m.AttackID, err)
	}
	return nil
}

// StoreAttackRelationship stores r, or replaces it with a later modification.
func (t *Tx) StoreAttackRelationship(ctx context.Context, r AttackRelationship) error {
	if err := t.q.UpsertAttackRelationship(ctx, sqlcgen.UpsertAttackRelationshipParams{
		ID: r.ID, Type: r.Type, SourceID: r.Source, TargetID: r.Target, Description: r.Description, ModifiedAt: r.Modified,
	}); err != nil {
		return fmt.Errorf("store relationship %s: %w", r.ID, err)
	}
	return nil
}

// AttackTechnique fails with ErrNotFound when no stored Technique has that
// ATT&CK id.
func (t *Tx) AttackTechnique(ctx context.Context, attackID string) (AttackTechnique, error) {
	row, err := t.q.GetAttackTechnique(ctx, attackID)
	if errors.Is(err, pgx.ErrNoRows) {
		return AttackTechnique{}, fmt.Errorf("technique %s: %w", attackID, ErrNotFound)
	}
	if err != nil {
		return AttackTechnique{}, fmt.Errorf("get technique %s: %w", attackID, err)
	}
	return AttackTechnique{
		ID: row.ID, AttackID: row.AttackID, Name: row.Name, Tactics: row.Tactics,
		Revoked: row.Revoked, Deprecated: row.Deprecated, Object: row.Object, Modified: row.ModifiedAt,
	}, nil
}

// RevokingTechnique is the stored Technique that replaced the one of that
// STIX id. It fails with ErrNotFound when there is none.
func (t *Tx) RevokingTechnique(ctx context.Context, techniqueID string) (AttackTechnique, error) {
	row, err := t.q.GetRevokingTechnique(ctx, techniqueID)
	if errors.Is(err, pgx.ErrNoRows) {
		return AttackTechnique{}, fmt.Errorf("technique replacing %s: %w", techniqueID, ErrNotFound)
	}
	if err != nil {
		return AttackTechnique{}, fmt.Errorf("get technique replacing %s: %w", techniqueID, err)
	}
	return AttackTechnique{
		ID: row.ID, AttackID: row.AttackID, Name: row.Name, Tactics: row.Tactics,
		Revoked: row.Revoked, Deprecated: row.Deprecated, Object: row.Object, Modified: row.ModifiedAt,
	}, nil
}

// MitigationsOf is the stored Mitigations of the Technique of that STIX id,
// by ATT&CK id.
func (t *Tx) MitigationsOf(ctx context.Context, techniqueID string) ([]TechniqueMitigation, error) {
	rows, err := t.q.ListMitigationsOfTechnique(ctx, techniqueID)
	if err != nil {
		return nil, fmt.Errorf("list mitigations of %s: %w", techniqueID, err)
	}
	out := make([]TechniqueMitigation, len(rows))
	for i, row := range rows {
		out[i] = TechniqueMitigation{AttackID: row.AttackID, Name: row.Name, Advice: row.Description}
	}
	return out, nil
}
