// Package finding is the domain of Findings: what identifies one, what a match
// makes of it and why it is closed (ADR 0020). It does no I/O.
package finding

import (
	"errors"
	"fmt"
	"strings"

	"barbackend/internal/inventory"
	"barbackend/internal/matching"
	"barbackend/internal/stixext"
	"github.com/google/uuid"
)

var (
	ErrInvalidCVE   = errors.New("invalid CVE ID")
	ErrNoProduct    = errors.New("finding needs a product")
	ErrInvalidAsset = errors.New("finding needs an asset")
	ErrNotAMatch    = errors.New("result is not a match")
)

// ID identifies a Finding for good: it never changes, even when the Finding
// is closed and reopened, so the Agents can reference it (ADR 0016).
type ID uuid.UUID

func (id ID) String() string { return uuid.UUID(id).String() }

// Key is what makes a Finding unique: the Asset, the Product and the
// Vulnerability. The Product is kept in lower case and trimmed, since Products
// match ignoring case (ADR 0015).
type Key struct {
	Asset   inventory.SourceReference
	Vendor  string
	Product string
	CVE     string
}

// NewKey builds the Key of a Finding of cve on the Product installed on asset.
func NewKey(asset inventory.SourceReference, p inventory.Product, cve string) (Key, error) {
	if asset.RecordID == "" {
		return Key{}, ErrInvalidAsset
	}
	id, ok := stixext.CVEID(cve)
	if !ok {
		return Key{}, fmt.Errorf("%w: %q", ErrInvalidCVE, cve)
	}
	vendor, product := ProductKey(p)
	if vendor == "" || product == "" {
		return Key{}, ErrNoProduct
	}
	return Key{Asset: asset, Vendor: vendor, Product: product, CVE: id}, nil
}

// ProductKey is p as Findings store it: vendor and name in lower case, trimmed.
func ProductKey(p inventory.Product) (vendor, name string) {
	return strings.ToLower(strings.TrimSpace(p.Vendor)), strings.ToLower(strings.TrimSpace(p.Name))
}

// Match is what one match of a Software Component makes of its Finding: the
// component it was matched on, the NVD entry that matched and its Match Flags.
type Match struct {
	Key       Key
	Component inventory.SoftwareComponent
	Evidence  stixext.Affected
	Flags     []matching.Flag
}

// NewMatch builds the Match of r, a matching.Result, for the component c of
// asset and the Vulnerability cve. It fails when r did not match.
func NewMatch(asset inventory.SourceReference, c inventory.SoftwareComponent, cve string, r matching.Result) (Match, error) {
	if !r.Matched {
		return Match{}, ErrNotAMatch
	}
	key, err := NewKey(asset, c.Product, cve)
	if err != nil {
		return Match{}, err
	}
	return Match{Key: key, Component: c, Evidence: r.Evidence, Flags: r.Flags}, nil
}

// Outcome is what saving a Match did to its Finding.
type Outcome int

const (
	// Opened: the Finding did not exist and was opened.
	Opened Outcome = iota + 1
	// Updated: the Finding was open and its component or evidence was updated.
	Updated
	// Reopened: the Finding was closed and is open again.
	Reopened
)

func (o Outcome) String() string {
	switch o {
	case Opened:
		return "opened"
	case Updated:
		return "updated"
	case Reopened:
		return "reopened"
	default:
		return fmt.Sprintf("Outcome(%d)", int(o))
	}
}
