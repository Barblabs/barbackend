package news

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"barbackend/internal/stixext"
)

// MaxDigest bounds the News Items of one News Digest; the closest Relevance
// is kept first.
const MaxDigest = 50

// MaxWhy bounds the Editor's reason for one News Item.
const MaxWhy = 320

// PeerLabel is what every attack on a Peer says, written by code so that no
// reader takes it for a sign of exposure.
const PeerLabel = "Ataque a una organización de su sector: es contexto, no indica que ustedes estén expuestos."

// LeakClaimLabel is what every leak-site post says: the attacker's own claim.
func LeakClaimLabel(attacker string) string {
	if attacker == "" {
		return "Publicado en un sitio de filtración: es lo que dice el atacante, sin confirmar."
	}
	return fmt.Sprintf("Reclamado por %s en su sitio de filtración: es lo que dice el atacante, sin confirmar.", attacker)
}

// Entry is one News Item of a News Digest: what it is, what the Reader stated
// of it, nil when it has no Reading, and its Relevance to the Customer.
type Entry struct {
	Item    Item
	Reading *Reading
	Match   Match
}

// Labels are the labels code writes on e.
func (e Entry) Labels() []string {
	var out []string
	if e.Item.IsLeakPost() {
		out = append(out, LeakClaimLabel(e.Item.Attacker))
	}
	if e.Match.Relevance == Peer {
		out = append(out, PeerLabel)
	}
	return out
}

// CVEs are the CVE IDs e names, from its text and from its Reading.
func (e Entry) CVEs() []string {
	out := slices.Clone(e.Item.CVEs)
	if e.Reading != nil {
		for _, v := range e.Reading.Vulnerabilities {
			if !slices.Contains(out, v.CVE) {
				out = append(out, v.CVE)
			}
		}
	}
	return out
}

// Order sorts entries as the rules order a News Digest, without a model: the
// closest Relevance first; among Peers, those that share a country first; then
// the newest. It keeps at most MaxDigest.
func Order(entries []Entry) []Entry {
	out := slices.Clone(entries)
	slices.SortStableFunc(out, func(a, b Entry) int {
		if c := cmp.Compare(a.Match.Relevance.rank(), b.Match.Relevance.rank()); c != 0 {
			return c
		}
		if a.Match.SharesCountry != b.Match.SharesCountry {
			if a.Match.SharesCountry {
				return -1
			}
			return 1
		}
		if c := b.Item.Published.Compare(a.Item.Published); c != 0 {
			return c
		}
		return cmp.Compare(a.Item.ID, b.Item.ID)
	})
	if len(out) > MaxDigest {
		out = out[:MaxDigest]
	}
	return out
}

// Editorial is the Editor's answer for one News Digest: why each News Item
// may matter to the Customer, in the order it would read them within each
// Relevance.
type Editorial struct {
	Items []EditorialItem `json:"items"`
}

// EditorialItem is the Editor's reason for one News Item, by the key the
// Editor was given it under, with what the reason relies on of the Business
// Context.
type EditorialItem struct {
	Key             string            `json:"key"`
	Why             string            `json:"why"`
	ContextEvidence []ContextEvidence `json:"context_evidence"`
}

// ContextEvidence cites one value of the Business Context: Path is an RFC 6901
// pointer into its business_context/1 document.
type ContextEvidence struct {
	Path  string `json:"path"`
	Value string `json:"value"`
}

// MaxContextEvidence bounds what one reason cites of the Business Context.
const MaxContextEvidence = 3

// Key is the key the Editor is given the i-th entry of a digest under.
func Key(i int) string { return fmt.Sprintf("n%d", i+1) }

// keyIndex is the index of the entry given under key, among n, or -1.
func keyIndex(key string, n int) int {
	i, err := strconv.Atoi(strings.TrimPrefix(key, "n"))
	if !strings.HasPrefix(key, "n") || err != nil || i < 1 || i > n || Key(i-1) != key {
		return -1
	}
	return i - 1
}

// filler is wording that says nothing about the Customer, which the Editor
// must not write.
var filler = []string{
	"es importante", "es crucial", "es fundamental", "es vital", "cabe destacar", "cabe señalar",
	"panorama actual", "panorama de amenazas", "era digital", "constante evolución",
	"mantenerse alerta", "mantenerse atent", "estar atentos", "permanecer atentos", "mantenerse informad",
	"sistemas actualizados", "buenas prácticas", "no se debe subestimar", "subraya la importancia",
	"pone de manifiesto", "resalta la importancia", "destaca la importancia", "recordatorio de",
	"ninguna organización está exenta", "cualquier organización",
}

// VerifyEditorial checks the Editor's answer for entries, the News Items it
// was given in the rules' order, against what it was given: every News Item
// exactly once; each reason within bounds, with no URL, no filler and no CVE
// ID its News Item does not name; and every citation of context, the Business
// Context as JSON, at its path.
func VerifyEditorial(entries []Entry, e Editorial, context any) []string {
	var problems []string
	seen := map[string]bool{}
	for i, item := range e.Items {
		field := fmt.Sprintf("items[%d]", i)
		index := keyIndex(item.Key, len(entries))
		if index < 0 {
			problems = append(problems, fmt.Sprintf("%s.key %q is not a news item it was given", field, item.Key))
			continue
		}
		if seen[item.Key] {
			problems = append(problems, fmt.Sprintf("%s.key %q appears twice", field, item.Key))
		}
		seen[item.Key] = true
		problems = append(problems, checkWhy(field+".why", item.Why, entries[index].CVEs())...)
		problems = append(problems, checkContextEvidence(field, item.ContextEvidence, context)...)
	}
	for j := range entries {
		if !seen[Key(j)] {
			problems = append(problems, fmt.Sprintf("news item %q has no item", Key(j)))
		}
	}
	return problems
}

func checkWhy(field, why string, cves []string) []string {
	why = strings.TrimSpace(why)
	switch {
	case why == "":
		return []string{field + " is blank"}
	case utf8.RuneCountInString(why) > MaxWhy:
		return []string{fmt.Sprintf("%s is longer than %d characters", field, MaxWhy)}
	case urlPattern.MatchString(why):
		return []string{field + " has a URL"}
	}
	var problems []string
	lower := strings.ToLower(why)
	for _, f := range filler {
		if strings.Contains(lower, f) {
			problems = append(problems, fmt.Sprintf("%s says %q, which tells the reader nothing about this Customer", field, f))
		}
	}
	for _, cve := range stixext.CVEIDs(why) {
		if !slices.Contains(cves, cve) {
			problems = append(problems, fmt.Sprintf("%s names %s, which its news item does not", field, cve))
		}
	}
	return problems
}

func checkContextEvidence(field string, evidence []ContextEvidence, context any) []string {
	if len(evidence) > MaxContextEvidence {
		return []string{fmt.Sprintf("%s cites %d values of the business context, more than %d", field, len(evidence), MaxContextEvidence)}
	}
	var problems []string
	for i, ev := range evidence {
		node, ok := at(context, ev.Path)
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("%s.context_evidence[%d].path %q is not in the business context", field, i, ev.Path))
		case !cites(node, ev.Value):
			problems = append(problems, fmt.Sprintf("%s.context_evidence[%d] at %q is not %q", field, i, ev.Path, ev.Value))
		}
	}
	return problems
}

func cites(node any, value string) bool {
	value = strings.TrimSpace(value)
	s, ok := node.(string)
	return ok && value != "" && (s == value || utf8.RuneCountInString(value) >= minQuote && strings.Contains(s, value))
}

var pointerToken = strings.NewReplacer("~1", "/", "~0", "~")

// at is the node of root at pointer, an RFC 6901 JSON pointer.
func at(root any, pointer string) (any, bool) {
	if !strings.HasPrefix(pointer, "/") {
		return nil, false
	}
	node := root
	for token := range strings.SplitSeq(pointer[1:], "/") {
		token = pointerToken.Replace(token)
		switch v := node.(type) {
		case map[string]any:
			child, ok := v[token]
			if !ok {
				return nil, false
			}
			node = child
		case []any:
			i, err := strconv.Atoi(token)
			if err != nil || i < 0 || i >= len(v) || strconv.Itoa(i) != token {
				return nil, false
			}
			node = v[i]
		default:
			return nil, false
		}
	}
	return node, true
}

// Apply orders entries, already in the rules' order, as the Editor would read
// them within each Relevance, and gives each its Editorial item. It never
// moves a News Item to another Relevance, adds one or drops one.
func Apply(entries []Entry, e Editorial) []EditedEntry {
	position := map[string]int{}
	byKey := map[string]EditorialItem{}
	for i, item := range e.Items {
		position[item.Key], byKey[item.Key] = i, item
	}
	out := make([]EditedEntry, len(entries))
	for i, entry := range entries {
		item := byKey[Key(i)]
		out[i] = EditedEntry{Entry: entry, Why: item.Why, ContextEvidence: item.ContextEvidence, position: position[Key(i)]}
	}
	slices.SortStableFunc(out, func(a, b EditedEntry) int {
		if c := cmp.Compare(a.Match.Relevance.rank(), b.Match.Relevance.rank()); c != 0 {
			return c
		}
		return cmp.Compare(a.position, b.position)
	})
	return out
}

// EditedEntry is an Entry with the Editor's reason, blank when the Editor had
// no verified answer.
type EditedEntry struct {
	Entry
	Why             string
	ContextEvidence []ContextEvidence

	position int
}

// Since is how far back a Customer's first News Digest reaches.
const Since = 7 * 24 * time.Hour
