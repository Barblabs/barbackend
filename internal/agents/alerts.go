package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"barbackend/internal/alert"
	"barbackend/internal/assessment"
	"barbackend/internal/postgres"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

// LinkAlertsTo has every Alert link to the portal at url (ADR 0033). It is
// meant to be set once, before the Service is used.
func (s *Service) LinkAlertsTo(url string) {
	s.portalURL = url
}

// alertsOf is the Slack deliveries of the Alerts of p, the Prioritization r
// made, stored as id (ADR 0033): for each Finding r placed that was never
// placed before, or whose Band rose since it was last placed, one to its Asset
// Owner and one to the Security Team channel, highest Score first, or, during
// the Customer's Initial Load, those in batches of alert.BatchSize per target.
// It reads the Dossier each was last placed with, so it runs in the
// transaction that stores p, before p's placements.
func (s *Service) alertsOf(ctx context.Context, tx *postgres.Tx, customer tenancy.CustomerID, r Round, p Prioritization, id uuid.UUID) ([]postgres.NewSlackDelivery, error) {
	last, err := lastPlaced(ctx, tx, customer, r.Findings)
	if err != nil {
		return nil, err
	}
	var alerts []alert.Finding
	for _, d := range r.Findings {
		was, placed := last[d.Finding]
		reason := alert.New
		switch {
		case placed && assessment.BandRose(was, d):
			reason = alert.BandRose
		case placed:
			continue
		}
		a := s.alertOf(d, p.List, r.owners[d.Finding])
		a.Prioritization, a.Reason = id.String(), reason
		if reason == alert.BandRose {
			a.BandWas = was.Score.Band
		}
		alerts = append(alerts, a)
	}
	if r.initialLoad {
		return batchDeliveries(alerts)
	}
	return findingDeliveries(alerts)
}

// lastPlaced is, by Finding among findings, the Dossier it was last placed
// with in any of the Customer's Prioritizations, so a Finding a change of
// Business Context places again is compared with how it stood before, whatever
// round places it.
func lastPlaced(ctx context.Context, tx *postgres.Tx, customer tenancy.CustomerID, findings []assessment.Dossier) (map[string]assessment.Dossier, error) {
	ids := make([]uuid.UUID, 0, len(findings))
	for _, d := range findings {
		id, err := uuid.Parse(d.Finding)
		if err != nil {
			return nil, fmt.Errorf("%w: finding %q is not a stored Finding", ErrInvalidFindings, d.Finding)
		}
		ids = append(ids, id)
	}
	raw, err := tx.LatestPlacedDossiers(ctx, customer, ids)
	if err != nil {
		return nil, err
	}
	out := make(map[string]assessment.Dossier, len(raw))
	for id, dossier := range raw {
		var d assessment.Dossier
		if err := json.Unmarshal(dossier, &d); err != nil {
			return nil, fmt.Errorf("read the last dossier of %s: %w", id, err)
		}
		out[id.String()] = d
	}
	return out, nil
}

// alertOf is what an Alert says of d, placed in l, whose Asset Owner is owner.
func (s *Service) alertOf(d assessment.Dossier, l assessment.PriorityList, owner string) alert.Finding {
	a := alert.Finding{
		Finding: d.Finding, CVE: d.CVE, Asset: d.Asset.Name,
		Component:  strings.TrimSpace(d.Component.Name + " " + d.Component.Version),
		OwnerEmail: owner, PortalURL: s.portalURL,
		Score: d.Score.Value, Band: d.Score.Band, KEV: d.KEV != nil,
		Criticality: d.Asset.Criticality, Exposure: d.Asset.Exposure,
		Lifecycle: d.Asset.Lifecycle, Classification: d.Asset.Classification,
	}
	if d.NVD != nil {
		if base, ok := d.NVD.BaseScore(); ok {
			a.CVSS = &base
		}
	}
	if d.EPSS != nil {
		a.EPSS = &d.EPSS.Probability
	}
	if position := l.GroupOf(d.Finding); position > 0 {
		g := l.Groups[position-1]
		a.Group = alert.Group{Position: position, Of: len(l.Groups), Title: g.Title}
		for _, part := range g.Parts {
			if slices.Contains(part.Findings, d.Finding) {
				a.Group.Reason = part.Reason
			}
		}
	}
	return a
}

// findingDeliveries is, for each Alert, highest Score first, one delivery to
// its Asset Owner and one to the Security Team channel. An Alert with no Asset
// Owner still gets its DM row, with no target, so it fails where an admin sees
// it (ADR 0029).
func findingDeliveries(alerts []alert.Finding) ([]postgres.NewSlackDelivery, error) {
	var out []postgres.NewSlackDelivery
	for _, a := range slices.SortedFunc(slices.Values(alerts), alert.ByScore) {
		payload, err := json.Marshal(a)
		if err != nil {
			return nil, fmt.Errorf("write the alert of %s: %w", a.Finding, err)
		}
		finding, err := uuid.Parse(a.Finding)
		if err != nil {
			return nil, fmt.Errorf("%w: finding %q is not a stored Finding", ErrInvalidFindings, a.Finding)
		}
		out = append(out,
			postgres.NewSlackDelivery{Kind: alert.KindFinding, TargetKind: alert.TargetEmail, Target: a.OwnerEmail, Payload: payload, Finding: finding},
			postgres.NewSlackDelivery{Kind: alert.KindFinding, TargetKind: alert.TargetChannel, Target: alert.SecurityTeam, Payload: payload, Finding: finding},
		)
	}
	return out, nil
}

// batchDeliveries is the Alerts in batches: every one of them to the
// Security Team channel, and each Asset Owner's own to them, owners in order
// of their email.
func batchDeliveries(alerts []alert.Finding) ([]postgres.NewSlackDelivery, error) {
	byOwner := map[string][]alert.Finding{}
	for _, a := range alerts {
		byOwner[a.OwnerEmail] = append(byOwner[a.OwnerEmail], a)
	}
	out, err := batchesTo(nil, alert.TargetChannel, alert.SecurityTeam, alerts)
	if err != nil {
		return nil, err
	}
	for _, owner := range slices.Sorted(maps.Keys(byOwner)) {
		if out, err = batchesTo(out, alert.TargetEmail, owner, byOwner[owner]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func batchesTo(out []postgres.NewSlackDelivery, targetKind, target string, alerts []alert.Finding) ([]postgres.NewSlackDelivery, error) {
	for _, b := range alert.Batches(alerts) {
		payload, err := json.Marshal(b)
		if err != nil {
			return nil, fmt.Errorf("write a batch of alerts: %w", err)
		}
		out = append(out, postgres.NewSlackDelivery{Kind: alert.KindBatch, TargetKind: targetKind, Target: target, Payload: payload})
	}
	return out, nil
}
