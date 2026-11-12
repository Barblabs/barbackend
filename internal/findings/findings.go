// Package findings turns Feeds and Syncs into Findings (ADR 0020). It matches
// Vulnerabilities against Software Components with matching, scores the
// matches with scoring and stores them with postgres. Its Handle functions
// have the shape of ingest.Feed.Handle, and AfterSync runs after a Sync.
package findings

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"barbackend/internal/finding"
	"barbackend/internal/inventory"
	"barbackend/internal/postgres"
	"barbackend/internal/scoring"
	"github.com/TcM1911/stix2"
)

// rejected is the vuln_status NVD gives a CVE it withdrew.
const rejected = "Rejected"

// Service reacts to Feeds and Syncs. It keeps no Feed data in memory: a
// Vulnerability first matched between two KEV or EPSS pulls is scored without
// them until the next pull sets them (ADR 0020). It only remembers when KEV
// last arrived, to tell a missing listing from a stale catalog.
type Service struct {
	db        *postgres.DB
	model     scoring.Model
	kevMaxAge time.Duration
	now       func() time.Time

	mu      sync.Mutex
	lastKEV time.Time

	onChanged func()
}

// New scores with model. A KEV catalog not received within kevMaxAge is
// stale, and so is one never received since the Service started (ADR 0009).
func New(db *postgres.DB, model scoring.Model, kevMaxAge time.Duration) *Service {
	return &Service{db: db, model: model, kevMaxAge: kevMaxAge, now: time.Now}
}

// OnChanged has fn called after each batch of a Feed and each AfterSync, which
// may have opened, closed or rescored Findings, so the Prioritizer can place
// them (ADR 0026). fn must return at once. It is meant to be set once, before
// the Service is used.
func (s *Service) OnChanged(fn func()) {
	s.onChanged = fn
}

func (s *Service) changed() {
	if s.onChanged != nil {
		s.onChanged()
	}
}

func (s *Service) kevStale() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastKEV.IsZero() || s.now().Sub(s.lastKEV) > s.kevMaxAge
}

func (s *Service) kevReceived() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastKEV = s.now()
}

// score stores the Score of a Finding of v on an Asset of that Criticality
// and Exposure, unless it equals the latest one.
func (s *Service) score(ctx context.Context, tx *postgres.Tx, id finding.ID, v *stix2.Vulnerability, criticality inventory.Criticality, exposure inventory.Exposure) error {
	score, err := s.model.Compute(finding.ScoreInputs(v, criticality, exposure, s.kevStale()))
	if err != nil {
		return fmt.Errorf("score finding %s: %w", id, err)
	}
	_, err = tx.SaveScoreIfChanged(ctx, id, score)
	return err
}

// stored decodes a stored Vulnerability's STIX object, with every extension
// the Feeds set on it.
func stored(v postgres.StoredVulnerability) (*stix2.Vulnerability, error) {
	var out stix2.Vulnerability
	if err := json.Unmarshal(v.Object, &out); err != nil {
		return nil, fmt.Errorf("decode vulnerability %s: %w", v.CVE, err)
	}
	return &out, nil
}

// each runs fn on every Vulnerability of batch. A failure is logged and the
// rest still run, so one odd CVE does not stop a Feed's pull, which a Handle
// error would (ingest.Feed). Only a cancelled context stops it.
func each(ctx context.Context, feed string, batch []stix2.STIXObject, fn func(*stix2.Vulnerability) error) error {
	for _, obj := range batch {
		v, ok := obj.(*stix2.Vulnerability)
		if !ok {
			continue
		}
		if err := fn(v); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Printf("findings: %s: %s: %v", feed, v.Name, err)
		}
	}
	return ctx.Err()
}
