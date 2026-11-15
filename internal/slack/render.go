package slack

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	"barbackend/internal/alert"
	"barbackend/internal/postgres"
)

// Block Kit's limits, in characters: Slack refuses a message over any of
// them with invalid_blocks, which no retry fixes.
const (
	maxHeader  = 150
	maxSection = 3000
	maxField   = 2000
	// maxName bounds one value a line names, such as an Asset or a group's
	// title, so a line of ten of them stays within a section.
	maxName = 200
)

type text struct {
	Type  string `json:"type"`
	Text  string `json:"text"`
	Emoji bool   `json:"emoji,omitempty"`
}

type block struct {
	Type     string  `json:"type"`
	Text     *text   `json:"text,omitempty"`
	Fields   []*text `json:"fields,omitempty"`
	Elements []*text `json:"elements,omitempty"`
}

// bandMarks is the colour mark that leads an Alert of each Score Band
// (ADR 0033).
var bandMarks = map[string]string{
	"critical": ":red_circle:",
	"high":     ":large_orange_circle:",
	"medium":   ":large_yellow_circle:",
	"low":      ":white_circle:",
}

// labels are how a message names the codes an Alert carries; any other code
// is shown capitalised.
var labels = map[string]string{
	"internet_facing": "Internet-facing",
	"unclassified":    "Unclassified",
}

// escaper escapes the characters Slack's mrkdwn reads as markup, so text an
// Alert carries, which can quote a Feed, never mentions a channel or forges a
// link.
var escaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// render turns a delivery's payload into the message both the DM and the
// channel copy carry. It fails when the payload is not an Alert this worker
// knows how to render.
func render(d postgres.SlackDelivery) (Message, error) {
	switch d.Kind {
	case alert.KindFinding:
		var a alert.Finding
		if err := json.Unmarshal(d.Payload, &a); err != nil {
			return Message{}, fmt.Errorf("decode finding payload: %w", err)
		}
		if err := complete(a); err != nil {
			return Message{}, err
		}
		return message(fit(title(a)+": "+score(a.Score), maxSection), findingBlocks(a))
	case alert.KindBatch:
		var b alert.Batch
		if err := json.Unmarshal(d.Payload, &b); err != nil {
			return Message{}, fmt.Errorf("decode batch payload: %w", err)
		}
		if len(b.Findings) == 0 || len(b.Findings) > alert.BatchSize {
			return Message{}, fmt.Errorf("batch of %d findings, want 1 to %d", len(b.Findings), alert.BatchSize)
		}
		for _, a := range b.Findings {
			if err := complete(a); err != nil {
				return Message{}, err
			}
		}
		return message(batchHeader(b), batchBlocks(b))
	default:
		return Message{}, fmt.Errorf("unknown slack delivery kind %q", d.Kind)
	}
}

func complete(a alert.Finding) error {
	if a.CVE == "" || a.Asset == "" {
		return errors.New("finding payload has no CVE or asset")
	}
	return nil
}

func message(fallback string, blocks []block) (Message, error) {
	raw, err := json.Marshal(blocks)
	if err != nil {
		return Message{}, fmt.Errorf("encode slack blocks: %w", err)
	}
	return Message{Text: fallback, Blocks: raw}, nil
}

// title is the Band, the CVE and the Asset an Alert is about, as plain text.
func title(a alert.Finding) string {
	return fmt.Sprintf("%s · %s on %s", strings.ToUpper(orDash(a.Band)), a.CVE, a.Asset)
}

func findingBlocks(a alert.Finding) []block {
	blocks := []block{
		{Type: "header", Text: &text{Type: "plain_text", Text: cut(mark(a.Band)+" "+title(a), maxHeader), Emoji: true}},
		{Type: "section", Text: mrkdwn(why(a))},
		{Type: "section", Fields: []*text{
			field("Score", score(a.Score)),
			field("CVSS", cvss(a.CVSS)),
			field("EPSS", epss(a.EPSS)),
			field("CISA KEV", yesNo(a.KEV)),
		}},
		{Type: "section", Text: mrkdwn("*Asset* · " + fit(orDash(a.Component), maxName)), Fields: []*text{
			field("Criticality", label(a.Criticality)),
			field("Exposure", label(a.Exposure)),
			field("Lifecycle", label(a.Lifecycle)),
			field("Information classification", label(a.Classification)),
		}},
	}
	if g := a.Group; g.Position > 0 {
		head := fmt.Sprintf("*Why it matters* · Priority group %d of %d: %s\n", g.Position, g.Of, fit(g.Title, maxName))
		reason := strings.Join(strings.Fields(g.Reason), " ")
		blocks = append(blocks, block{Type: "section", Text: mrkdwn(head + ">" + fit(reason, maxSection-utf8.RuneCountInString(head)-1))})
	}
	return append(blocks, block{
		Type:     "context",
		Elements: []*text{mrkdwn("Owner: " + fit(orDash(a.OwnerEmail), maxName) + " · " + link(a.PortalURL))},
	})
}

// batchHeader is a batch's count of Findings by Band, highest first.
func batchHeader(b alert.Batch) string {
	counts := map[string]int{}
	for _, a := range b.Findings {
		counts[a.Band]++
	}
	var bands []string
	for _, band := range []string{"critical", "high", "medium", "low"} {
		if counts[band] > 0 {
			bands = append(bands, fmt.Sprintf("%d %s", counts[band], band))
		}
	}
	header := fmt.Sprintf("%d findings · initial load", len(b.Findings))
	if len(b.Findings) == 1 {
		header = "1 finding · initial load"
	}
	if len(bands) > 0 {
		header += " · " + strings.Join(bands, ", ")
	}
	return header
}

func batchBlocks(b alert.Batch) []block {
	blocks := []block{{Type: "header", Text: &text{Type: "plain_text", Text: batchHeader(b), Emoji: true}}}
	for _, a := range b.Findings {
		line := fmt.Sprintf("%s *%d*  *%s* on %s", mark(a.Band), percent(a.Score), fit(a.CVE, maxName), fit(a.Asset, maxName))
		if g := a.Group; g.Position > 0 {
			line += fmt.Sprintf(" · #%d %s", g.Position, fit(g.Title, maxName))
		}
		kev := "no KEV"
		if a.KEV {
			kev = "KEV"
		}
		facts := []string{"CVSS " + cvss(a.CVSS), "EPSS " + epss(a.EPSS), kev,
			label(a.Criticality), label(a.Exposure), label(a.Lifecycle), label(a.Classification), "Owner: " + fit(orDash(a.OwnerEmail), maxName)}
		blocks = append(blocks, block{Type: "section", Text: mrkdwn(line + "\n" + strings.Join(facts, " · "))})
	}
	return append(blocks, block{Type: "context", Elements: []*text{mrkdwn(link(b.Findings[0].PortalURL))}})
}

// why is why the Finding is alerted.
func why(a alert.Finding) string {
	if a.Reason == alert.BandRose {
		return fmt.Sprintf("Band rose from %s to %s", label(a.BandWas), label(a.Band))
	}
	return "New finding"
}

func mark(band string) string {
	if m, ok := bandMarks[band]; ok {
		return m
	}
	return ":white_circle:"
}

// percent is a Score from 0 to 100, as the portal shows it.
func percent(v float64) int {
	return int(math.Round(v * 100))
}

func score(v float64) string {
	return strconv.Itoa(percent(v)) + " / 100"
}

func cvss(v *float64) string {
	if v == nil {
		return "Unknown"
	}
	return strconv.FormatFloat(*v, 'f', 1, 64)
}

func epss(v *float64) string {
	if v == nil {
		return "Pending"
	}
	return strconv.FormatFloat(*v*100, 'f', 1, 64) + "%"
}

// label is how a message names a code, escaped for mrkdwn.
func label(code string) string {
	if l, ok := labels[code]; ok {
		return l
	}
	if code == "" {
		return "—"
	}
	return fit(strings.ToUpper(code[:1])+strings.ReplaceAll(code[1:], "_", " "), maxName)
}

// field is a section field naming a value, the value escaped and within
// Slack's limit.
func field(name, value string) *text {
	return mrkdwn("*" + name + "*\n" + fit(value, maxField-utf8.RuneCountInString(name)-3))
}

// fit is s escaped for mrkdwn, cut with an ellipsis so the escaped text holds
// at most limit characters. It cuts s, not the escaped text, so no escape is
// split.
func fit(s string, limit int) string {
	escaped := escaper.Replace(s)
	if utf8.RuneCountInString(escaped) <= limit {
		return escaped
	}
	var b strings.Builder
	n := 0
	for _, r := range s {
		e := escaper.Replace(string(r))
		if n+utf8.RuneCountInString(e) > limit-1 {
			break
		}
		b.WriteString(e)
		n += utf8.RuneCountInString(e)
	}
	return b.String() + "…"
}

// cut is plain text s within limit characters, ending in an ellipsis when it
// was longer.
func cut(s string, limit int) string {
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	return string([]rune(s)[:limit-1]) + "…"
}

func mrkdwn(s string) *text {
	return &text{Type: "mrkdwn", Text: s}
}

func yesNo(v bool) string {
	if v {
		return "Yes"
	}
	return "No"
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func link(url string) string {
	if url == "" {
		return "barbattack"
	}
	return "<" + url + "|Open in barbattack>"
}
