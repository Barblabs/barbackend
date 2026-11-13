package finding

import (
	"cmp"
	"slices"

	"barbackend/internal/inventory"
	"barbackend/internal/scoring"
	"barbackend/internal/stixext"
	"github.com/TcM1911/stix2"
)

// AssetValues is what the Scoring Model reads of a Finding's Asset: its
// Criticality, its effective Exposure and its Lifecycle Stage (ADR 0009,
// ADR 0028).
type AssetValues struct {
	Criticality inventory.Criticality
	Exposure    inventory.Exposure
	Lifecycle   inventory.LifecycleStage
}

// ScoreInputs is what the Scoring Model reads of a Finding (ADR 0009): its
// Vulnerability's CVSS, EPSS and KEV listing, and its Asset's values.
// kevStale says the KEV catalog was not read recently enough to
// trust a missing listing. A Feed whose value is missing or out of range
// leaves its input nil, which the Scoring Model turns into a Data Gap.
func ScoreInputs(v *stix2.Vulnerability, asset AssetValues, kevStale bool) scoring.Inputs {
	in := scoring.Inputs{Criticality: asset.Criticality, Exposure: asset.Exposure, Lifecycle: asset.Lifecycle, KEVStale: kevStale}
	if nvd, ok := stixext.NVDOf(v); ok {
		if base := baseScore(nvd.CVSS); base != nil && *base >= 0 && *base <= 10 {
			in.CVSS = base
		}
	}
	if epss, ok := stixext.EPSSOf(v); ok && epss.Probability >= 0 && epss.Probability <= 1 {
		in.EPSS = &epss.Probability
	}
	_, in.KEVListed = stixext.KEVOf(v)
	return in
}

// baseScore is the newest CVSS version's base score from NVD's Primary
// metrics, else from the numbering authority's Secondary ones (ADR 0009).
func baseScore(metrics []stixext.CVSS) *float64 {
	for _, kind := range []string{"Primary", "Secondary"} {
		of := slices.DeleteFunc(slices.Clone(metrics), func(m stixext.CVSS) bool { return m.Type != kind })
		if len(of) == 0 {
			continue
		}
		newest := slices.MaxFunc(of, func(a, b stixext.CVSS) int { return cmp.Compare(a.Version, b.Version) })
		return &newest.BaseScore
	}
	return nil
}
