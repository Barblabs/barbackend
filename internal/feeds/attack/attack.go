// Package attack pulls the MITRE ATT&CK Enterprise catalog: its Techniques,
// its Mitigations and the relationships between them (ADR 0023).
package attack

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"barbackend/internal/feeds"
	"barbackend/internal/feeds/httpx"
	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
)

const defaultURL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

// Adapter fetches the ATT&CK Enterprise bundle.
type Adapter struct {
	httpx.Endpoint
}

// New returns an Adapter, defaulting the client and URL when they are empty.
func New(client *http.Client, url string) *Adapter {
	return &Adapter{Endpoint: httpx.NewEndpoint(client, url, defaultURL)}
}

// Pull fetches the bundle and emits the objects ADR 0023 keeps.
func (a *Adapter) Pull(ctx context.Context, emit feeds.Emit) error {
	resp, err := a.Get(ctx, "attack")
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	return objects(resp.Body, emit)
}

func objects(r io.Reader, emit feeds.Emit) error {
	dec := json.NewDecoder(r)
	if err := expect(dec, '{'); err != nil {
		return fmt.Errorf("attack: %w", err)
	}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return fmt.Errorf("attack: %w", err)
		}
		if key != "objects" {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return fmt.Errorf("attack: %w", err)
			}
			continue
		}
		if err := objectList(dec, emit); err != nil {
			return err
		}
	}
	return nil
}

func objectList(dec *json.Decoder, emit feeds.Emit) error {
	if err := expect(dec, '['); err != nil {
		return fmt.Errorf("attack: %w", err)
	}
	for dec.More() {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return fmt.Errorf("attack: decode object: %w", err)
		}
		if err := object(raw, emit); err != nil {
			return err
		}
	}
	if err := expect(dec, ']'); err != nil {
		return fmt.Errorf("attack: %w", err)
	}
	return nil
}

// revokedBy is the relationship ATT&CK uses to point a revoked object at
// the one that replaced it. The STIX library has no constant for it.
const revokedBy stix2.RelationshipType = "revoked-by"

// head is what object reads of a raw object to decide whether to keep it.
type head struct {
	Type             stix2.STIXType             `json:"type"`
	Name             string                     `json:"name"`
	RelationshipType stix2.RelationshipType     `json:"relationship_type"`
	Source           stix2.Identifier           `json:"source_ref"`
	Target           stix2.Identifier           `json:"target_ref"`
	References       []*stix2.ExternalReference `json:"external_references"`
}

// object emits raw when ADR 0023 keeps it: a Technique or a Mitigation with
// an ATT&CK id, a mitigates relationship, or a revoked-by relationship
// between Techniques. Everything else in the bundle is dropped.
func object(raw json.RawMessage, emit feeds.Emit) error {
	var h head
	if err := json.Unmarshal(raw, &h); err != nil {
		return fmt.Errorf("attack: decode type: %w", err)
	}
	if !kept(h) {
		return nil
	}
	obj, err := decode(raw, h.Type)
	if err != nil {
		return err
	}
	return emit(obj)
}

func kept(h head) bool {
	switch h.Type {
	case stix2.TypeAttackPattern:
		if strings.HasPrefix(stixext.AttackID(h.References), "T") {
			return true
		}
		log.Printf("attack: skipping %q: no ATT&CK id", h.Name)
		return false
	case stix2.TypeCourseOfAction:
		// Course-of-actions with a T id are an old, deprecated form of ATT&CK.
		return strings.HasPrefix(stixext.AttackID(h.References), "M")
	case stix2.TypeRelationship:
		return h.RelationshipType == stix2.RelationshipTypeMitigates ||
			(h.RelationshipType == revokedBy && isType(h.Source, stix2.TypeAttackPattern) && isType(h.Target, stix2.TypeAttackPattern))
	default:
		return false
	}
}

// decode parses raw, a kept object of type typ, with the STIX library.
func decode(raw json.RawMessage, typ stix2.STIXType) (stix2.STIXObject, error) {
	c, err := stix2.FromJSON(append(append([]byte{'['}, raw...), ']'))
	if err != nil {
		return nil, fmt.Errorf("attack: decode %s: %w", typ, err)
	}
	var objs []stix2.STIXObject
	switch typ {
	case stix2.TypeAttackPattern:
		for _, o := range c.AttackPatterns() {
			objs = append(objs, o)
		}
	case stix2.TypeCourseOfAction:
		for _, o := range c.CourseOfActions() {
			objs = append(objs, o)
		}
	default:
		for _, o := range c.Relationships() {
			objs = append(objs, o)
		}
	}
	if len(objs) != 1 {
		return nil, fmt.Errorf("attack: decoded %d objects of type %s from one", len(objs), typ)
	}
	return objs[0], nil
}

func isType(id stix2.Identifier, typ stix2.STIXType) bool {
	return strings.HasPrefix(string(id), string(typ)+"--")
}

func expect(dec *json.Decoder, want json.Delim) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != want {
		return fmt.Errorf("want %q, got %v", want, token)
	}
	return nil
}
