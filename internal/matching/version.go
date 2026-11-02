package matching

import (
	"cmp"
	"errors"
	"fmt"
	"strings"
)

var ErrUnparsedVersion = errors.New("version cannot be parsed")

var preReleaseLabels = []string{"alpha", "beta", "pre", "rc"}

var release = preRelease{rank: len(preReleaseLabels)}

// Version is a software version as CMDBs and NVD write it (ADR 0015).
// Its zero value is no version; build one with ParseVersion.
type Version struct {
	upstream []segment
	pre      preRelease
	revision string
}

type segment struct {
	text   string
	number bool
}

type preRelease struct {
	rank   int
	number string
}

// ParseVersion reads s as an upstream version, an optional pre-release
// (alpha, beta, pre, rc) and an optional packaging revision, each after a
// hyphen. A leading "v" and a Debian epoch ("1:") are ignored.
func ParseVersion(s string) (Version, error) {
	upstream, suffix, hasSuffix := strings.Cut(trimPrefixes(strings.TrimSpace(s)), "-")
	segs, ok := segments(upstream)
	if !ok || (hasSuffix && suffix == "") {
		return Version{}, fmt.Errorf("%w: %q", ErrUnparsedVersion, s)
	}
	v := Version{upstream: segs, pre: release}
	label, revision, hasRevision := strings.Cut(suffix, "-")
	if pre, ok := parsePreRelease(label); ok {
		if hasRevision && revision == "" {
			return Version{}, fmt.Errorf("%w: %q", ErrUnparsedVersion, s)
		}
		v.pre, suffix = pre, revision
	}
	v.revision = suffix
	return v, nil
}

// Compare returns -1, 0 or 1 as v is older than, equal to or newer than w,
// ignoring packaging revisions. comparable is false when a number and letters
// meet at the same position, or either Version is the zero value.
func (v Version) Compare(w Version) (order int, comparable bool) {
	if len(v.upstream) == 0 || len(w.upstream) == 0 {
		return 0, false
	}
	for i := range max(len(v.upstream), len(w.upstream)) {
		c, ok := compareAt(v.upstream, w.upstream, i)
		if !ok || c != 0 {
			return c, ok
		}
	}
	return comparePreReleases(v.pre, w.pre), true
}

// HasRevision reports whether v carries a packaging revision, such as
// "1ubuntu2.2" in "1.0.1f-1ubuntu2.2".
func (v Version) HasRevision() bool { return v.revision != "" }

func trimPrefixes(s string) string {
	if epoch, rest, found := strings.Cut(s, ":"); found && allDigits(epoch) {
		s = rest
	}
	if len(s) > 1 && (s[0] == 'v' || s[0] == 'V') && isDigit(s[1]) {
		s = s[1:]
	}
	return s
}

func segments(s string) ([]segment, bool) {
	if s == "" || !isDigit(s[0]) {
		return nil, false
	}
	var segs []segment
	for i := 0; i < len(s); {
		switch c := s[i]; {
		case isDigit(c):
			j := runEnd(s, i, isDigit)
			segs = append(segs, segment{text: strings.TrimLeft(s[i:j], "0"), number: true})
			i = j
		case isLetter(c):
			j := runEnd(s, i, isLetter)
			segs = append(segs, segment{text: strings.ToLower(s[i:j])})
			i = j
		case isSeparator(c) && i+1 < len(s) && !isSeparator(s[i+1]):
			i++
		default:
			return nil, false
		}
	}
	return segs, true
}

func parsePreRelease(s string) (preRelease, bool) {
	lower := strings.ToLower(s)
	for rank, label := range preReleaseLabels {
		number, found := strings.CutPrefix(lower, label)
		if !found {
			continue
		}
		number = strings.TrimPrefix(number, ".")
		if number != "" && !allDigits(number) {
			return preRelease{}, false
		}
		return preRelease{rank: rank, number: strings.TrimLeft(number, "0")}, true
	}
	return preRelease{}, false
}

func compareAt(a, b []segment, i int) (int, bool) {
	switch {
	case i >= len(a):
		return -overAbsent(b[i]), true
	case i >= len(b):
		return overAbsent(a[i]), true
	case a[i].number != b[i].number:
		return 0, false
	case a[i].number:
		return compareNumbers(a[i].text, b[i].text), true
	default:
		return strings.Compare(a[i].text, b[i].text), true
	}
}

func overAbsent(s segment) int {
	if s.number && s.text == "" {
		return 0
	}
	return 1
}

func comparePreReleases(a, b preRelease) int {
	if c := cmp.Compare(a.rank, b.rank); c != 0 {
		return c
	}
	return compareNumbers(a.number, b.number)
}

func compareNumbers(a, b string) int {
	if c := cmp.Compare(len(a), len(b)); c != 0 {
		return c
	}
	return strings.Compare(a, b)
}

func runEnd(s string, i int, in func(byte) bool) int {
	for i < len(s) && in(s[i]) {
		i++
	}
	return i
}

func allDigits(s string) bool {
	return s != "" && runEnd(s, 0, isDigit) == len(s)
}

func isDigit(c byte) bool     { return '0' <= c && c <= '9' }
func isLetter(c byte) bool    { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }
func isSeparator(c byte) bool { return c == '.' || c == '_' }
