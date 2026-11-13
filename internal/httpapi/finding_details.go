package httpapi

import "barbackend/internal/agents"

func newFindingDetails(d agents.Dossier) findingDetailsResponse {
	out := findingDetailsResponse{
		Description: d.Description,
		Asset: findingAssetResponse{
			Name: d.Asset.Name, Kind: d.Asset.Kind, Criticality: d.Asset.Criticality, Exposure: d.Asset.Exposure,
			LifecycleStage: d.Asset.Lifecycle, CriticalServices: make([]criticalServiceResponse, len(d.Asset.CriticalServices)),
		},
		ComponentRole: d.Component.Role,
		ScoreDetails:  newScoreResponse(d.Score),
		CVSS:             []cvssResponse{},
		References:       []string{},
		UnavailableFeeds: nonNil(d.UnavailableFeeds),
		Advisories:       make([]advisoryResponse, len(d.Advisories)),
		Labeling:         labelingResponse{Outcome: d.Labeling.Outcome, Model: d.Labeling.Model},
		Techniques:       make([]techniqueResponse, len(d.Techniques)),
	}
	for i, c := range d.Asset.CriticalServices {
		out.Asset.CriticalServices[i] = criticalServiceResponse{Name: c.Name, Description: c.Description, Impact: c.Impact, MaxDowntime: c.MaxDowntime}
	}
	if k := d.KEV; k != nil {
		out.KEV = &kevResponse{DateAdded: k.DateAdded, DueDate: k.DueDate, RequiredAction: k.RequiredAction, KnownRansomwareCampaignUse: k.KnownRansomwareCampaignUse}
	}
	if e := d.EPSS; e != nil {
		out.EPSS = &epssResponse{Probability: e.Probability, Percentile: e.Percentile, ScoreDate: e.ScoreDate}
	}
	if n := d.NVD; n != nil {
		for _, m := range n.CVSS {
			out.CVSS = append(out.CVSS, cvssResponse{Version: m.Version, BaseScore: m.BaseScore, Vector: m.Vector, Type: m.Type})
		}
		out.References = nonNil(n.References)
	}
	for i, a := range d.Advisories {
		out.Advisories[i] = advisoryResponse{Title: a.Title, Published: a.Published, Feed: a.Feed, Description: a.Description}
	}
	for i, t := range d.Techniques {
		technique := techniqueResponse{
			AttackID: t.AttackID, LabeledAs: t.LabeledAs, Name: t.Name, Tactics: nonNil(t.Tactics), Role: t.Role,
			Evidence: t.Evidence, Rationale: t.Rationale, Mitigations: make([]mitigationResponse, len(t.Mitigations)),
		}
		for j, m := range t.Mitigations {
			technique.Mitigations[j] = mitigationResponse{AttackID: m.AttackID, Name: m.Name, Advice: m.Advice}
		}
		out.Techniques[i] = technique
	}
	return out
}

func newScoreResponse(s agents.Score) scoreResponse {
	return scoreResponse{
		ScoringModel: s.ScoringModel, Value: s.Value,
		Alpha: s.Alpha, Beta: s.Beta, Gamma: s.Gamma, Vulnerability: s.Vulnerability,
		CriticalityMultiplier: s.CriticalityMultiplier, ExposureMultiplier: s.ExposureMultiplier,
		LifecycleMultiplier: s.LifecycleMultiplier, DataGaps: nonNil(s.DataGaps),
	}
}

// newCurrentResponse is c, nil for a Finding with none.
func newCurrentResponse(c agents.Current, ok bool) *currentResponse {
	if !ok {
		return nil
	}
	return &currentResponse{
		Asset:        currentAssetResponse{Criticality: c.Asset.Criticality, Exposure: c.Asset.Exposure, LifecycleStage: c.Asset.Lifecycle},
		ScoreDetails: newScoreResponse(c.Score),
	}
}
