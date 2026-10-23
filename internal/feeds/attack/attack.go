// Package attack pulls the MITRE ATT&CK Enterprise techniques.
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

// Pull fetches the bundle and emits every technique that carries an ATT&CK id.
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

func object(raw json.RawMessage, emit feeds.Emit) error {
	var head struct {
		Type stix2.STIXType `json:"type"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return fmt.Errorf("attack: decode type: %w", err)
	}
	if head.Type != stix2.TypeAttackPattern {
		return nil
	}
	c, err := stix2.FromJSON(append(append([]byte{'['}, raw...), ']'))
	if err != nil {
		return fmt.Errorf("attack: decode attack-pattern: %w", err)
	}
	patterns := c.AttackPatterns()
	if len(patterns) != 1 {
		return fmt.Errorf("attack: decoded %d attack-patterns from one object", len(patterns))
	}
	pattern := patterns[0]
	if !attackID(pattern) {
		log.Printf("attack: skipping %q: no ATT&CK id", pattern.Name)
		return nil
	}
	return emit(pattern)
}

func attackID(pattern *stix2.AttackPattern) bool {
	for _, ref := range pattern.ExternalReferences {
		if ref.Name == "mitre-attack" && strings.TrimSpace(ref.ExternalID) != "" {
			return true
		}
	}
	return false
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
