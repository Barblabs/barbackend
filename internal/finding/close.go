package finding

import "fmt"

// CloseReason says why a Finding was closed: its match no longer holds
// (ADR 0020), or a User closed it (ADR 0035).
type CloseReason int

// Stored as catalog ids (ADR 0006): never renumber.
const (
	// NoLongerAffected: a Sync shows the component's version no longer matches.
	NoLongerAffected CloseReason = 1
	// ComponentRemoved: the Asset no longer has a component with the Product.
	ComponentRemoved CloseReason = 2
	// AssetInactive: the Asset became Inactive (ADR 0005).
	AssetInactive CloseReason = 3
	// VulnerabilityRejected: NVD rejected the CVE.
	VulnerabilityRejected CloseReason = 4
	// The reasons a User gives to close a Finding by hand (ADR 0035).
	// Remediated: the User says it was fixed; a match reopens it.
	Remediated CloseReason = 5
	// FalsePositive: it does not apply, whatever the CMDB says; never reopened by a match.
	FalsePositive CloseReason = 6
	// AcceptedRisk: the Customer accepts it until its reopen time.
	AcceptedRisk CloseReason = 7
	// Postponed: it will be attended after its reopen time.
	Postponed CloseReason = 8
	// VulnerabilityRevised: NVD revised the Vulnerability's entries and they no
	// longer match the component (ADR 0038).
	VulnerabilityRevised CloseReason = 9
)

// ByHand reports whether r is a reason a User gives.
func (r CloseReason) ByHand() bool {
	return r >= Remediated && r <= Postponed
}

// Expires reports whether a close for r lasts until a reopen time, after which
// a match reopens the Finding.
func (r CloseReason) Expires() bool {
	return r == AcceptedRisk || r == Postponed
}

func (r CloseReason) String() string {
	switch r {
	case NoLongerAffected:
		return "no_longer_affected"
	case ComponentRemoved:
		return "component_removed"
	case AssetInactive:
		return "asset_inactive"
	case VulnerabilityRejected:
		return "vulnerability_rejected"
	case Remediated:
		return "remediated"
	case FalsePositive:
		return "false_positive"
	case AcceptedRisk:
		return "accepted_risk"
	case Postponed:
		return "postponed"
	case VulnerabilityRevised:
		return "vulnerability_revised"
	default:
		return fmt.Sprintf("CloseReason(%d)", int(r))
	}
}
