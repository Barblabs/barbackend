// Package techniques keeps the ATT&CK catalog whole, as reference data
// (ADR 0023). Its Handle functions have the shape of ingest.Feed.Handle.
package techniques

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"barbackend/internal/postgres"
	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
)

// Service stores the ATT&CK catalog.
type Service struct {
	db *postgres.DB
}

func New(db *postgres.DB) *Service {
	return &Service{db: db}
}

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
		ID: string(p.ID), AttackID: stixext.AttackID(p.ExternalReferences), Name: p.Name, Tactics: tactics,
		Revoked: p.Revoked, Deprecated: mitre.Deprecated, Object: object, Modified: timeOf(p.Modified),
	}, nil
}

func mitigation(c *stix2.CourseOfAction) (postgres.AttackMitigation, error) {
	object, err := json.Marshal(c)
	if err != nil {
		return postgres.AttackMitigation{}, fmt.Errorf("encode mitigation %s: %w", c.ID, err)
	}
	return postgres.AttackMitigation{
		ID: string(c.ID), AttackID: stixext.AttackID(c.ExternalReferences), Name: c.Name, Object: object, Modified: timeOf(c.Modified),
	}, nil
}

// timeOf is t, or now when the Feed gave none.
func timeOf(t *stix2.Timestamp) time.Time {
	if t == nil {
		return time.Now().UTC()
	}
	return t.Time
}
