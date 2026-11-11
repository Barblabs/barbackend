// Package techniques keeps the ATT&CK catalog whole, as reference data, and
// reads a Technique by its ATT&CK id across ATT&CK versions (ADR 0023). Its
// Handle functions have the shape of ingest.Feed.Handle.
package techniques

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"barbackend/internal/postgres"
	"github.com/TcM1911/stix2"
)

// maxReplacements is how many revoked-by steps a read follows: a revoked
// Technique can be replaced by one that was revoked later.
const maxReplacements = 5

// Service stores the ATT&CK catalog and reads it.
type Service struct {
	db *postgres.DB
}

func New(db *postgres.DB) *Service {
	return &Service{db: db}
}

// Technique is an ATT&CK Technique with its Mitigations.
type Technique struct {
	AttackID    string
	Name        string
	Tactics     []string
	Revoked     bool
	Deprecated  bool
	Mitigations []Mitigation
}

// Mitigation is an ATT&CK Mitigation of one Technique, with its advice for
// that Technique.
type Mitigation struct {
	AttackID string
	Name     string
	Advice   string
}

// Resolved is the Technique read for an ATT&CK id. When the id was revoked,
// Technique is its current replacement and Asked keeps the id.
type Resolved struct {
	Asked string
	Technique
}

// Replaced reports whether the Technique is a replacement of the one asked.
func (r Resolved) Replaced() bool { return r.AttackID != r.Asked }

// HandleATTACK stores the Techniques, Mitigations and relationships of a
// batch of the ATT&CK Feed, replacing an object only with a later
// modification. The batch is one transaction.
func (s *Service) HandleATTACK(ctx context.Context, batch []stix2.STIXObject) error {
	return s.db.InTx(ctx, func(tx *postgres.Tx) error {
		stored := 0
		for _, obj := range batch {
			ok, err := store(ctx, tx, obj)
			if err != nil {
				return err
			}
			if ok {
				stored++
			}
		}
		log.Printf("techniques: attack: stored %d of %d", stored, len(batch))
		return nil
	})
}

// store stores obj when it is part of the catalog, and reports whether it was.
func store(ctx context.Context, tx *postgres.Tx, obj stix2.STIXObject) (bool, error) {
	switch o := obj.(type) {
	case *stix2.AttackPattern:
		t, err := technique(o)
		if err != nil {
			return false, err
		}
		return true, tx.StoreAttackTechnique(ctx, t)
	case *stix2.CourseOfAction:
		m, err := mitigation(o)
		if err != nil {
			return false, err
		}
		return true, tx.StoreAttackMitigation(ctx, m)
	case *stix2.Relationship:
		return true, tx.StoreAttackRelationship(ctx, postgres.AttackRelationship{
			ID: string(o.ID), Type: string(o.RelationshipType), Source: string(o.Source), Target: string(o.Target),
			Description: o.Description, Modified: timeOf(o.Modified),
		})
	default:
		return false, nil
	}
}

func technique(p *stix2.AttackPattern) (postgres.AttackTechnique, error) {
	object, err := json.Marshal(p)
	if err != nil {
		return postgres.AttackTechnique{}, fmt.Errorf("encode technique %s: %w", p.ID, err)
	}
	var mitre struct {
		Deprecated bool `json:"x_mitre_deprecated"`
	}
	if err := json.Unmarshal(object, &mitre); err != nil {
		return postgres.AttackTechnique{}, fmt.Errorf("decode technique %s: %w", p.ID, err)
	}
	tactics := []string{}
	for _, phase := range p.KillChainPhase {
		if phase.Name == "mitre-attack" {
			tactics = append(tactics, phase.Phase)
		}
	}
	return postgres.AttackTechnique{
		ID: string(p.ID), AttackID: attackID(p.ExternalReferences), Name: p.Name, Tactics: tactics,
		Revoked: p.Revoked, Deprecated: mitre.Deprecated, Object: object, Modified: timeOf(p.Modified),
	}, nil
}

func mitigation(c *stix2.CourseOfAction) (postgres.AttackMitigation, error) {
	object, err := json.Marshal(c)
	if err != nil {
		return postgres.AttackMitigation{}, fmt.Errorf("encode mitigation %s: %w", c.ID, err)
	}
	return postgres.AttackMitigation{
		ID: string(c.ID), AttackID: attackID(c.ExternalReferences), Name: c.Name, Object: object, Modified: timeOf(c.Modified),
	}, nil
}

// Technique reads the Technique of attackID with its Mitigations. A revoked
// Technique is read as its current replacement, following revoked-by for at
// most maxReplacements steps; one with no replacement stored is read as it
// is, marked revoked. It fails with postgres.ErrNotFound for an unknown id.
func (s *Service) Technique(ctx context.Context, attackID string) (Resolved, error) {
	asked := strings.ToUpper(strings.TrimSpace(attackID))
	var out Resolved
	err := s.db.InTx(ctx, func(tx *postgres.Tx) error {
		t, err := current(ctx, tx, asked)
		if err != nil {
			return err
		}
		mitigations, err := tx.MitigationsOf(ctx, t.ID)
		if err != nil {
			return err
		}
		out = Resolved{Asked: asked, Technique: Technique{
			AttackID: t.AttackID, Name: t.Name, Tactics: t.Tactics, Revoked: t.Revoked, Deprecated: t.Deprecated,
			Mitigations: make([]Mitigation, len(mitigations)),
		}}
		for i, m := range mitigations {
			out.Mitigations[i] = Mitigation{AttackID: m.AttackID, Name: m.Name, Advice: m.Advice}
		}
		return nil
	})
	return out, err
}

// current is the Technique of attackID, or the one that replaced it.
func current(ctx context.Context, tx *postgres.Tx, attackID string) (postgres.AttackTechnique, error) {
	t, err := tx.AttackTechnique(ctx, attackID)
	if err != nil {
		return postgres.AttackTechnique{}, err
	}
	for step := 0; t.Revoked && step < maxReplacements; step++ {
		next, err := tx.RevokingTechnique(ctx, t.ID)
		if errors.Is(err, postgres.ErrNotFound) {
			break
		}
		if err != nil {
			return postgres.AttackTechnique{}, err
		}
		t = next
	}
	return t, nil
}

// attackID is the ATT&CK id among refs, such as T1190 or M1051.
func attackID(refs []*stix2.ExternalReference) string {
	for _, ref := range refs {
		if ref.Name == "mitre-attack" {
			return strings.TrimSpace(ref.ExternalID)
		}
	}
	return ""
}

// timeOf is t, or now when the Feed gave none.
func timeOf(t *stix2.Timestamp) time.Time {
	if t == nil {
		return time.Now().UTC()
	}
	return t.Time
}
