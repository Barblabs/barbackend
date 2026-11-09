package matching

import "fmt"

// CloseReason says why a Finding was closed: its match no longer holds
// (ADR 0019).
type CloseReason int

// Stored as catalog ids (ADR 0006): never renumber.
const (
	// NoLongerAffected: the component's version no longer matches, because it
	// changed or because NVD changed the Vulnerability's entries.
	NoLongerAffected CloseReason = 1
	// ComponentRemoved: the Asset no longer has a component with the Product.
	ComponentRemoved CloseReason = 2
	// AssetInactive: the Asset became Inactive (ADR 0005).
	AssetInactive CloseReason = 3
	// VulnerabilityRejected: NVD rejected the CVE.
	VulnerabilityRejected CloseReason = 4
)

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
	default:
		return fmt.Sprintf("CloseReason(%d)", int(r))
	}
}
