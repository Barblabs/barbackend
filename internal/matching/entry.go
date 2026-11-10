package matching

import "barbackend/internal/stixext"

// matchEntry decides whether a component at version, already known to have
// the entry's Product, is affected by one NVD entry (ADR 0015, rules 2 to 4).
func matchEntry(version string, a stixext.Affected) (bool, []Flag) {
	if hasBounds(a) {
		return matchRange(version, a)
	}
	switch a.Version {
	case "*", "-":
		return true, nil
	case "":
		// Stored before nvd/1 had a version: assume any version, and say so.
		return true, []Flag{VersionUnparsed}
	}
	return matchExact(version, a)
}

func hasBounds(a stixext.Affected) bool {
	return a.VersionStartIncluding != "" || a.VersionStartExcluding != "" ||
		a.VersionEndIncluding != "" || a.VersionEndExcluding != ""
}

// matchExact compares with an exact version. A pre-release update is part of
// it (2.0 with beta9 is 2.0-beta9); any other update (patch1, sp1) cannot be
// compared, so it matches only flagged, when the version is the component's
// own or the leading part of it.
func matchExact(version string, a stixext.Affected) (bool, []Flag) {
	cv, err := ParseVersion(version)
	if err != nil {
		return true, []Flag{VersionUnparsed}
	}
	exact, otherUpdate := a.Version, false
	switch u := a.Update; {
	case u == "" || u == "*" || u == "-":
	case isPreRelease(u):
		exact += "-" + u
	default:
		otherUpdate = true
	}
	ev, err := ParseVersion(exact)
	if err != nil {
		return true, []Flag{VersionUnparsed}
	}
	order, comparable := cv.Compare(ev)
	switch {
	case !comparable:
		return true, []Flag{VersionUnparsed}
	case order == 0 && otherUpdate:
		return true, []Flag{VersionUnparsed}
	case order == 0:
		return true, revisionFlags(cv)
	case ev.isPrefixOf(cv):
		return true, []Flag{VersionUnparsed}
	}
	return false, nil
}

// matchRange checks every bound. A bound that surely excludes the version
// wins over one that cannot be compared: then the component is not affected.
func matchRange(version string, a stixext.Affected) (bool, []Flag) {
	cv, err := ParseVersion(version)
	if err != nil {
		return true, []Flag{VersionUnparsed}
	}
	doubt := false
	for _, b := range []struct {
		bound string
		holds func(order int) bool
	}{
		{a.VersionStartIncluding, func(o int) bool { return o >= 0 }},
		{a.VersionStartExcluding, func(o int) bool { return o > 0 }},
		{a.VersionEndIncluding, func(o int) bool { return o <= 0 }},
		{a.VersionEndExcluding, func(o int) bool { return o < 0 }},
	} {
		if b.bound == "" {
			continue
		}
		bv, err := ParseVersion(b.bound)
		if err != nil {
			doubt = true
			continue
		}
		order, comparable := cv.Compare(bv)
		if !comparable {
			doubt = true
			continue
		}
		if !b.holds(order) {
			return false, nil
		}
	}
	if doubt {
		return true, append([]Flag{VersionUnparsed}, revisionFlags(cv)...)
	}
	return true, revisionFlags(cv)
}

func revisionFlags(v Version) []Flag {
	if v.HasRevision() {
		return []Flag{DistroBackport}
	}
	return nil
}
