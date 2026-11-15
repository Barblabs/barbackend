package agents

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"barbackend/internal/alert"
	"barbackend/internal/assessment"
	"barbackend/internal/postgres"
	"github.com/google/uuid"
)

// Delivery targets (ADR 0030): an Asset Owner by email, or the Security Team
// channel.
const (
	targetEmail   = "email"
	targetChannel = "channel"
)

// LinkAlertsTo has every Alert link to the portal at url (ADR 0033). It is
// meant to be set once, before the Service is used.
func (s *Service) LinkAlertsTo(url string) {
	s.portalURL = url
}

// alertsOf is the Slack deliveries of the Alerts of p, the Prioritization r
// made, stored as id (ADR 0033): one for each Finding r placed that is new or
// whose Band rose, to its Asset Owner and to the Security Team channel, or,
// during the Customer's Initial Load, those in batches of alert.BatchSize per
// target.
func (s *Service) alertsOf(r Round, p Prioritization, id uuid.UUID) ([]postgres.NewSlackDelivery, error) {
	var alerts []alert.Finding
	for _, d := range r.Findings {
		was, held := r.previous[d.Finding]
		reason, ok := alert.Why(held, was.Score.Band, d.Score.Band)
		if !ok {
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

// findingDeliveries is one delivery per Alert to its Asset Owner and one to
// the Security Team channel. An Alert with no Asset Owner still gets its DM
// row, with no target, so it fails where an admin sees it (ADR 0029).
func findingDeliveries(alerts []alert.Finding) ([]postgres.NewSlackDelivery, error) {
	var out []postgres.NewSlackDelivery
	for _, a := range alerts {
		payload, err := json.Marshal(a)
		if err != nil {
			return nil, fmt.Errorf("write the alert of %s: %w", a.Finding, err)
		}
		finding, err := uuid.Parse(a.Finding)
		if err != nil {
			return nil, fmt.Errorf("%w: finding %q is not a stored Finding", ErrInvalidFindings, a.Finding)
		}
		out = append(out,
			postgres.NewSlackDelivery{Kind: alert.KindFinding, TargetKind: targetEmail, Target: a.OwnerEmail, Payload: payload, Finding: finding},
			postgres.NewSlackDelivery{Kind: alert.KindFinding, TargetKind: targetChannel, Target: alert.SecurityTeam, Payload: payload, Finding: finding},
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
	out, err := batchesTo(nil, targetChannel, alert.SecurityTeam, alerts)
	if err != nil {
		return nil, err
	}
	for _, owner := range slices.Sorted(maps.Keys(byOwner)) {
		if out, err = batchesTo(out, targetEmail, owner, byOwner[owner]); err != nil {
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
