package matching

import (
	"slices"
	"strings"

	"barbackend/internal/inventory"
	"barbackend/internal/stixext"
)

// Result is whether a Vulnerability affects a Software Component.
type Result struct {
	Matched bool
	// Evidence is the entry that matched: one without Flags when there is one.
	Evidence stixext.Affected
	// Flags say why the match is uncertain; none means certain.
	Flags []Flag
}

// Match decides whether the Vulnerability described by n affects c (ADR 0015).
// An Unidentified Component is never matched: callers tell it apart with
// c.Identified(), so it is reported rather than read as not affected. Every
// vulnerable entry is matched on its own, as if AND configurations were plain
// lists, and the component gets one Result for all of them.
func Match(c inventory.SoftwareComponent, n stixext.NVD) Result {
	if !c.Identified() || n.Rejected() {
		return Result{}
	}
	var best Result
	for _, a := range n.Affected {
		if !sameProduct(c.Product, a) {
			continue
		}
		matched, flags := matchEntry(c.Version, a)
		if !matched {
			continue
		}
		if len(flags) == 0 {
			return Result{Matched: true, Evidence: a}
		}
		if !best.Matched {
			best = Result{Matched: true, Evidence: a, Flags: sortedFlags(flags)}
		}
	}
	return best
}

// sameProduct compares the Product with the entry's CPE tokens, ignoring case,
// as a CMDB may write Apache where NVD writes apache.
func sameProduct(p inventory.Product, a stixext.Affected) bool {
	return strings.EqualFold(strings.TrimSpace(p.Vendor), a.Vendor) &&
		strings.EqualFold(strings.TrimSpace(p.Name), a.Product)
}

func sortedFlags(flags []Flag) []Flag {
	out := slices.Clone(flags)
	slices.Sort(out)
	return slices.Compact(out)
}
