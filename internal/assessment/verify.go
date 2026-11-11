package assessment

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"barbackend/internal/stixext"
)

// minQuote is the shortest part of a longer text that evidence may cite, so a
// letter of an id cannot pass for a quote.
const minQuote = 20

var (
	urlPattern     = regexp.MustCompile(`(?i)https?://[^\s<>"')\]]+`)
	versionPattern = regexp.MustCompile(`\d+(?:\.\d+)+`)
	pointerToken   = strings.NewReplacer("~1", "/", "~0", "~")
)

// VerifyPriorityList returns every way l misplaces a Finding of briefs or
// relies on something they do not say, none when it holds: each Finding is in
// exactly one Priority Group, each group cites evidence from its own Findings,
// and its reason names the Data Gaps of their Scores, because an estimated
// Score must not be mistaken for a measured one.
func VerifyPriorityList(briefs []Brief, l PriorityList) []string {
	f, roots, err := briefFacts(briefs)
	if err != nil {
		return []string{err.Error()}
	}
	var violations []string
	if len(l.Groups) == 0 {
		violations = append(violations, "gives no groups")
	}
	placed := map[string]int{}
	for i, g := range l.Groups {
		group := fmt.Sprintf("group %d", i+1)
		violations = append(violations, place(group, i, g.Findings, roots, placed)...)
		violations = append(violations, f.checkProse(group+" title", g.Title)...)
		violations = append(violations, f.checkProse(group+" reason", g.Reason)...)
		violations = append(violations, checkGroupEvidence(group, g, roots)...)
		violations = append(violations, checkGaps(group, g, briefs)...)
	}
	for _, b := range briefs {
		if _, ok := placed[b.Finding]; !ok {
			violations = append(violations, fmt.Sprintf("finding %q is in no group", b.Finding))
		}
	}
	return violations
}

func briefFacts(briefs []Brief) (facts, map[string]any, error) {
	f := facts{source: "the findings", cves: map[string]bool{}, versions: map[string]bool{}, urls: map[string]bool{}}
	roots := make(map[string]any, len(briefs))
	for _, b := range briefs {
		root, err := generic(b)
		if err != nil {
			return facts{}, nil, err
		}
		roots[b.Finding] = root
		f.addMentions(root)
	}
	return f, roots, nil
}

func place(group string, index int, findings []string, roots map[string]any, placed map[string]int) []string {
	if len(findings) == 0 {
		return []string{group + " has no findings"}
	}
	var violations []string
	for _, id := range findings {
		if _, ok := roots[id]; !ok {
			violations = append(violations, fmt.Sprintf("%s has finding %q, which it was not given", group, id))
			continue
		}
		if earlier, ok := placed[id]; ok {
			violations = append(violations, fmt.Sprintf("finding %q is in group %d and %s", id, earlier+1, group))
			continue
		}
		placed[id] = index
	}
	return violations
}

func checkGroupEvidence(group string, g PriorityGroup, roots map[string]any) []string {
	if len(g.Evidence) == 0 {
		return []string{group + " cites no evidence"}
	}
	var violations []string
	for _, e := range g.Evidence {
		if !slices.Contains(g.Findings, e.Finding) {
			violations = append(violations, fmt.Sprintf("%s cites finding %q, which is not in it", group, e.Finding))
			continue
		}
		if problem := evidenceProblem(roots[e.Finding], e.Path, e.Value); problem != "" {
			violations = append(violations, fmt.Sprintf("%s: finding %q: %s", group, e.Finding, problem))
		}
	}
	return violations
}

func checkGaps(group string, g PriorityGroup, briefs []Brief) []string {
	var violations []string
	for _, b := range briefs {
		if !slices.Contains(g.Findings, b.Finding) {
			continue
		}
		for _, gap := range b.Score.DataGaps {
			if !strings.Contains(g.Reason, gap) {
				violations = append(violations, fmt.Sprintf("%s reason does not name the data gap %s of finding %q", group, gap, b.Finding))
			}
		}
	}
	return violations
}

// VerifyPlan returns every way p relies on something the Dossier does not
// say, none when it holds. The versions in it must be ones the Feeds tell to
// remediate with or the Asset runs, not any number the Dossier holds. It cannot
// judge a command written in a step, or a URL without a scheme.
func (d Dossier) VerifyPlan(p ActionPlan) []string {
	f, err := newFacts(d)
	if err != nil {
		return []string{err.Error()}
	}
	var violations []string
	if len(p.Steps) == 0 {
		violations = append(violations, "gives no steps")
	}
	if p.FixedVersion != nil && !f.fixes[*p.FixedVersion] {
		violations = append(violations, fmt.Sprintf("fixed version %q is not one the Feeds name", *p.FixedVersion))
	}
	for _, source := range p.Sources {
		if !f.urls[source] {
			violations = append(violations, fmt.Sprintf("source %q is not a reference of the dossier", source))
		}
	}
	violations = append(violations, f.checkSteps("summary", p.Summary)...)
	violations = append(violations, f.checkSteps("verification", p.Verification)...)
	for _, step := range p.Steps {
		violations = append(violations, f.checkSteps("step", step)...)
	}
	if p.Mitigation != nil {
		violations = append(violations, f.checkSteps("mitigation", *p.Mitigation)...)
	}
	return violations
}

type facts struct {
	// source names what was given, in a violation.
	source   string
	cves     map[string]bool
	versions map[string]bool
	// fixes are the versions the Feeds tell to remediate with, and planVersions
	// those plus the still vulnerable bounds and what the Asset runs.
	fixes        map[string]bool
	planVersions map[string]bool
	urls         map[string]bool
}

func newFacts(d Dossier) (facts, error) {
	root, err := generic(d)
	if err != nil {
		return facts{}, err
	}
	f := facts{source: "the dossier", cves: map[string]bool{}, versions: map[string]bool{}, fixes: map[string]bool{}, planVersions: map[string]bool{}, urls: map[string]bool{}}
	f.addMentions(root)
	fixes, vulnerable := d.versionBounds()
	addAll(f.fixes, fixes)
	for _, text := range d.remediationTexts() {
		addAll(f.fixes, versionPattern.FindAllString(text, -1))
	}
	maps.Copy(f.planVersions, f.fixes)
	addAll(f.planVersions, vulnerable)
	for _, s := range d.Asset.Software {
		addAll(f.planVersions, versionPattern.FindAllString(s.Version, -1))
	}
	if d.NVD != nil {
		addAll(f.urls, d.NVD.References)
	}
	return f, nil
}

// versionBounds splits the bounds of NVD's ranges into those that fix the
// Vulnerability, where an affected range ends or an unaffected one starts, and
// those still vulnerable.
func (d Dossier) versionBounds() (fixes, vulnerable []string) {
	if d.NVD == nil {
		return nil, nil
	}
	for _, a := range d.NVD.Affected {
		fixes = append(fixes, a.VersionEndExcluding)
		vulnerable = append(vulnerable, a.VersionStartIncluding, a.VersionStartExcluding, a.VersionEndIncluding)
	}
	for _, a := range d.NVD.CNAAffected {
		for _, v := range a.Versions {
			switch v.Status {
			case "affected":
				fixes = append(fixes, v.LessThan)
				vulnerable = append(vulnerable, v.Version, v.LessThanOrEqual)
			case "unaffected":
				fixes = append(fixes, v.Version)
				vulnerable = append(vulnerable, v.LessThan, v.LessThanOrEqual)
			}
		}
	}
	return slices.DeleteFunc(fixes, notAVersion), slices.DeleteFunc(vulnerable, notAVersion)
}

func notAVersion(v string) bool {
	v = strings.TrimSpace(v)
	return v == "0" || !strings.ContainsAny(v, "0123456789")
}

// remediationTexts are prose that may name a fixed version, such as "before
// 15.11", which counts only as the versions written in it.
func (d Dossier) remediationTexts() []string {
	texts := []string{d.Description}
	if d.KEV != nil {
		texts = append(texts, d.KEV.RequiredAction)
	}
	return texts
}

func (f facts) addMentions(root any) {
	for _, value := range values(root) {
		addAll(f.cves, stixext.CVEIDs(value))
		addAll(f.versions, versionPattern.FindAllString(value, -1))
	}
}

func addAll(set map[string]bool, items []string) {
	for _, item := range items {
		set[item] = true
	}
}

func generic(v any) (any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("read dossier: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var root any
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("read dossier: %w", err)
	}
	return root, nil
}

func values(node any) []string {
	switch v := node.(type) {
	case map[string]any:
		return slices.Concat(valuesOf(slices.Collect(maps.Values(v)))...)
	case []any:
		return slices.Concat(valuesOf(v)...)
	case string:
		return []string{v}
	case json.Number:
		return []string{v.String()}
	default:
		return nil
	}
}

func valuesOf(nodes []any) [][]string {
	out := make([][]string, len(nodes))
	for i, node := range nodes {
		out[i] = values(node)
	}
	return out
}

func evidenceProblem(root any, path, value string) string {
	node, ok := at(root, path)
	if !ok {
		return fmt.Sprintf("evidence path %q is not in it", path)
	}
	if !matches(node, value) {
		return fmt.Sprintf("evidence at %q is not %q", path, value)
	}
	return ""
}

func at(root any, pointer string) (any, bool) {
	if !strings.HasPrefix(pointer, "/") {
		return nil, false
	}
	node := root
	for token := range strings.SplitSeq(pointer[1:], "/") {
		child, ok := descend(node, pointerToken.Replace(token))
		if !ok {
			return nil, false
		}
		node = child
	}
	return node, true
}

func descend(node any, token string) (any, bool) {
	switch v := node.(type) {
	case map[string]any:
		child, ok := v[token]
		return child, ok
	case []any:
		i, err := strconv.Atoi(token)
		if err != nil || i < 0 || i >= len(v) {
			return nil, false
		}
		return v[i], true
	default:
		return nil, false
	}
}

func matches(node any, value string) bool {
	value = strings.TrimSpace(value)
	switch v := node.(type) {
	case nil:
		return value == "null"
	case string:
		return value != "" && (v == value || utf8.RuneCountInString(value) >= minQuote && strings.Contains(v, value))
	case json.Number:
		want, err := v.Float64()
		got, parseErr := strconv.ParseFloat(value, 64)
		return err == nil && parseErr == nil && want == got
	default:
		return false
	}
}

func (f facts) checkProse(field, text string) []string {
	if strings.TrimSpace(text) == "" {
		return []string{field + " is blank"}
	}
	return f.unknownMentions(text, f.versions)
}

func (f facts) checkSteps(field, text string) []string {
	if strings.TrimSpace(text) == "" {
		return []string{field + " is blank"}
	}
	return f.unknownMentions(text, f.planVersions)
}

func (f facts) unknownMentions(text string, versions map[string]bool) []string {
	var unknown []string
	check := func(known map[string]bool, kind, mention string) {
		if !known[mention] {
			unknown = append(unknown, fmt.Sprintf("%s %q is not in %s", kind, mention, f.source))
		}
	}
	withoutURLs := urlPattern.ReplaceAllStringFunc(text, func(url string) string {
		check(f.urls, "url", strings.TrimRight(url, ".,;:"))
		return " "
	})
	for _, id := range stixext.CVEIDs(withoutURLs) {
		check(f.cves, "cve", id)
	}
	for _, version := range versionPattern.FindAllString(withoutURLs, -1) {
		check(versions, "version", version)
	}
	return unknown
}
