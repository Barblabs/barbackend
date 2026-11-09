package matching

import "fmt"

// Flag says why a match is uncertain (ADR 0015). A match carries zero or more
// Flags; none means a certain match.
type Flag int

// Stored as catalog ids (ADR 0006): never renumber.
const (
	// VersionUnparsed: the version could not be read or fully compared.
	VersionUnparsed Flag = 1
	// DistroBackport: only the upstream version was compared; a packaging
	// revision may already include the fix.
	DistroBackport Flag = 2
)

func (f Flag) String() string {
	switch f {
	case VersionUnparsed:
		return "version_unparsed"
	case DistroBackport:
		return "distro_backport"
	default:
		return fmt.Sprintf("Flag(%d)", int(f))
	}
}
