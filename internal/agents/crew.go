// Package agents holds the use cases of barbattack's Agents: the Prioritizer
// orders a Customer's open Findings, Luna writes the Action Plan of one, the
// Analista talks with a Customer's Users about them (ADR 0016), the Drafter
// drafts a Customer's Business Context from a document (ADR 0017), and the
// Cartógrafo labels Vulnerabilities with ATT&CK Techniques (ADR 0024).
package agents

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"slices"
	"strings"
	"time"

	"barbackend/internal/assessment"
	"barbackend/internal/business"
	"barbackend/internal/claude"
	"github.com/google/uuid"
)

const (
	defaultPrioritizerModel = "claude-haiku-5-5"
	defaultLunaModel        = "claude-haiku-5-5"
	defaultAnalistaModel    = "claude-opus-5-5"
	defaultDrafterModel     = "claude-opus-5-5"
	defaultCartografoModel  = "claude-haiku-5-5"

	// MaxFindings bounds the Findings one round places: the Prioritizer reads
	// them all in one request, to weigh them against each other and against
	// the order that stands (ADR 0026).
	MaxFindings = 100

	maxAttempts        = 2
	prioritizerTimeout = 5 * time.Minute
	lunaTimeout        = 2 * time.Minute
	drafterTimeout     = 3 * time.Minute
	cartografoTimeout  = 2 * time.Minute
)

var (
	// ErrInvalidFindings is a Round that places no Finding or more than
	// MaxFindings, places one twice or one that stands, or holds a Dossier
	// built wrong.
	ErrInvalidFindings = errors.New("invalid findings")
	// ErrFindingNotFound is a Finding that a Prioritization does not hold.
	ErrFindingNotFound = errors.New("finding not found")
)

// Models names the model each Agent runs on.
type Models struct {
	Prioritizer, Luna, Analista, Drafter, Cartografo string
}

// DefaultModels are the models the Agents run on unless told otherwise.
func DefaultModels() Models {
	return Models{
		Prioritizer: defaultPrioritizerModel, Luna: defaultLunaModel, Analista: defaultAnalistaModel,
		Drafter: defaultDrafterModel, Cartografo: defaultCartografoModel,
	}
}

// ModelsFrom takes each Agent's model from getenv's PRIORITIZER_MODEL,
// LUNA_MODEL, ANALISTA_MODEL, DRAFTER_MODEL and CARTOGRAFO_MODEL, or from
// DefaultModels when blank.
func ModelsFrom(getenv func(string) string) Models {
	models := DefaultModels()
	for name, model := range map[string]*string{"PRIORITIZER_MODEL": &models.Prioritizer, "LUNA_MODEL": &models.Luna, "ANALISTA_MODEL": &models.Analista, "DRAFTER_MODEL": &models.Drafter, "CARTOGRAFO_MODEL": &models.Cartografo} {
		if v := strings.TrimSpace(getenv(name)); v != "" {
			*model = v
		}
	}
	return models
}

// Crew is the Prioritizer, Luna, the Drafter and the Cartógrafo. It reads no
// Feed and touches no database: all it knows of a Finding is the Dossier it is
// given, of a Customer's business the Document it is given, and of a
// Vulnerability the LabelingInput it is given.
type Crew struct {
	llm    *claude.Client
	models Models
}

func NewCrew(llm *claude.Client, models Models) *Crew {
	return &Crew{llm: llm, models: models}
}

// Status is how an Agent's run ended.
type Status string

const (
	// Verified is an output that relies on nothing outside what it was given.
	Verified Status = "verified"
	// Rejected is an Agent that kept relying on something it was not given,
	// so its output is dropped.
	Rejected Status = "rejected"
	// Refused is a request the model's safety classifiers declined.
	Refused Status = "refused"
	// Failed is a model that could not be called or did not finish.
	Failed Status = "failed"
)

// Run is one Agent's work. Output is set only when it is Verified, and
// Violations only when it is Rejected.
type Run[T any] struct {
	Status     Status   `json:"status"`
	Model      string   `json:"model"`
	PromptID   string   `json:"prompt_id"`
	Output     *T       `json:"output"`
	Violations []string `json:"violations,omitempty"`
}

// Prioritization is one version of the order of a Customer's open Findings
// (ADR 0026): its Priority Groups, the Dossier of each Finding as it was when
// placed, and what the Prioritizer answered in the round that made it. Only
// Service stores one: the Dossiers with the placements that read them, and
// the rest as content.
type Prioritization struct {
	ID      uuid.UUID `json:"-"`
	Created time.Time `json:"-"`
	// Previous is the Prioritization it was built from, nil for a Customer's
	// first.
	Previous *uuid.UUID `json:"-"`
	// BusinessContext is the version of the Business Context its round read,
	// 0 when the Customer had stated none.
	BusinessContext int `json:"-"`
	// States are what is known of each of its Findings since it was stored.
	States map[string]FindingState `json:"-"`
	// Current is, by open Finding with a Score, its Asset and Score as they
	// are now, which its Dossier keeps as they were when placed. Only Get
	// reads it.
	Current  map[string]Current `json:"-"`
	Plans    []Plan             `json:"-"`
	Feedback []Feedback              `json:"-"`

	Findings    []assessment.Dossier      `json:"findings"`
	List        assessment.PriorityList   `json:"list"`
	Prioritizer Run[assessment.Placement] `json:"prioritizer"`
}

// FindingState is when the chain last placed a Finding of a Prioritization,
// as the round that placed it read it, and when the Finding was closed, nil
// while it is open: a closed Finding leaves the order the next round starts
// from.
type FindingState struct {
	Placed time.Time
	Closed *time.Time

	placement uuid.UUID
}

// Plan is Luna's Action Plan for one Finding of a Prioritization, with the
// Dossier Luna read.
type Plan struct {
	Finding string                     `json:"finding"`
	Created time.Time                  `json:"created"`
	Dossier assessment.Dossier         `json:"dossier"`
	Luna    Run[assessment.ActionPlan] `json:"luna"`
}

// Round is what one request of the Prioritizer places (ADR 0026): Findings,
// in the order that stands, read with the Customer's Business Context.
type Round struct {
	// Previous is the Prioritization the round builds on, nil for a
	// Customer's first.
	Previous *uuid.UUID
	// Context is the Customer's Business Context, and ContextVersion its
	// version, 0 with the zero Context when it has stated none.
	Context        business.Context
	ContextVersion int
	// Standing is the order that stands, and Placed the Dossiers of its
	// Findings as they were placed. Standing is empty for a Customer's first
	// round, and when its Business Context changed since the last one.
	Standing assessment.PriorityList
	Placed   []assessment.Dossier
	// Findings are the Findings to place: new ones, and those that changed
	// since they were placed.
	Findings []assessment.Dossier
	// Feedback is what Users said about where Findings to place should be, by
	// Finding.
	Feedback map[string][]assessment.OrderFeedback

	// read is when the round read what it places, and kept the placement
	// each Finding that stands keeps.
	read time.Time
	kept map[string]uuid.UUID
}

// Finding is the Dossier of the Finding of that id, if p holds it.
func (p Prioritization) Finding(id string) (assessment.Dossier, bool) {
	i := slices.IndexFunc(p.Findings, func(d assessment.Dossier) bool { return d.Finding == id })
	if i < 0 {
		return assessment.Dossier{}, false
	}
	return p.Findings[i], true
}

// GroupOf is the position, from 1, of the Priority Group holding the Finding
// of that id, or 0 when none does.
func (p Prioritization) GroupOf(id string) int { return p.List.GroupOf(id) }

// PlanOf is the newest Action Plan of the Finding of that id, if it has one.
func (p Prioritization) PlanOf(id string) (Plan, bool) {
	i := slices.IndexFunc(p.Plans, func(plan Plan) bool { return plan.Finding == id })
	if i < 0 {
		return Plan{}, false
	}
	return p.Plans[i], true
}

// ScoreRanks is where each Finding would be by its Score alone, 1 the highest,
// so a reader sees which ones the Prioritizer moved and can read why.
func (p Prioritization) ScoreRanks() map[string]int {
	byScore := slices.Clone(p.Findings)
	slices.SortStableFunc(byScore, func(a, b assessment.Dossier) int { return cmp.Compare(b.Score.Value, a.Score.Value) })
	ranks := make(map[string]int, len(byScore))
	for i, d := range byScore {
		ranks[d.Finding] = i + 1
	}
	return ranks
}

// Prioritize runs the Prioritizer on one Round. Its Prioritization holds the
// Dossiers of the Findings that stand and those placed, and its List is the
// order they give when the Prioritizer has a verified answer. It fails with
// ErrInvalidFindings before calling the model. A Prioritizer that cannot
// answer only shows in its Status.
func (c *Crew) Prioritize(ctx context.Context, r Round) (Prioritization, error) {
	if err := checkRound(r); err != nil {
		return Prioritization{}, err
	}
	in := assessment.Round{
		Standing: assessment.NewStanding(r.Standing, r.Placed),
		Briefs:   make([]assessment.Brief, len(r.Findings)),
		Feedback: map[string][]assessment.OrderFeedback{},
	}
	for i, d := range r.Findings {
		in.Briefs[i] = d.Brief()
		if said := r.Feedback[d.Finding]; len(said) > 0 {
			in.Feedback[d.Finding] = said
		}
	}
	var context any
	if r.ContextVersion > 0 {
		context = r.Context.Fields()
		raw, err := json.Marshal(context)
		if err != nil {
			return Prioritization{}, fmt.Errorf("write business context: %w", err)
		}
		in.Context = raw
	}
	prompt, err := sections(
		section{"business_context", context},
		section{"priority_list", in.Standing},
		section{"findings", in.Briefs},
		section{"feedback", in.Feedback},
	)
	if err != nil {
		return Prioritization{}, err
	}
	run := newPrioritizer(c.models.Prioritizer, in).run(ctx, c.llm, prompt)
	p := Prioritization{
		Previous: r.Previous, BusinessContext: r.ContextVersion,
		Findings: slices.Concat(r.Placed, r.Findings), List: assessment.PriorityList{Groups: []assessment.PriorityGroup{}}, Prioritizer: run,
	}
	if run.Output != nil {
		p.List = assessment.Merge(r.Standing, *run.Output)
	}
	return p, nil
}

// checkRound checks that r places from 1 to MaxFindings valid Findings, none
// twice nor one that stands, and that every Finding that stands has its
// Dossier.
func checkRound(r Round) error {
	if len(r.Findings) == 0 || len(r.Findings) > MaxFindings {
		return fmt.Errorf("%w: give from 1 to %d, not %d", ErrInvalidFindings, MaxFindings, len(r.Findings))
	}
	placed := make(map[string]bool, len(r.Placed))
	for _, d := range r.Placed {
		placed[d.Finding] = true
	}
	stands := map[string]bool{}
	for _, g := range r.Standing.Groups {
		for _, id := range g.Findings() {
			if !placed[id] {
				return fmt.Errorf("%w: standing finding %q has no dossier", ErrInvalidFindings, id)
			}
			stands[id] = true
		}
	}
	seen := make(map[string]bool, len(r.Findings))
	for _, d := range r.Findings {
		if err := d.Validate(); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidFindings, err)
		}
		if seen[d.Finding] || stands[d.Finding] {
			return fmt.Errorf("%w: finding %q is repeated", ErrInvalidFindings, d.Finding)
		}
		seen[d.Finding] = true
	}
	return nil
}

// Plan runs Luna on the Dossier of one Finding. Luna not answering only shows
// in the Run's Status.
func (c *Crew) Plan(ctx context.Context, d assessment.Dossier) (Run[assessment.ActionPlan], error) {
	prompt, err := tagged("dossier", d)
	if err != nil {
		return Run[assessment.ActionPlan]{}, err
	}
	return newLuna(c.models.Luna, d).run(ctx, c.llm, prompt), nil
}

// section is one tagged part of a user message.
type section struct {
	tag string
	v   any
}

func sections(parts ...section) (string, error) {
	out := make([]string, len(parts))
	for i, part := range parts {
		text, err := tagged(part.tag, part.v)
		if err != nil {
			return "", err
		}
		out[i] = text
	}
	return strings.Join(out, "\n\n"), nil
}

// json.Marshal escapes < and >, so no text in v can close the tag.
func tagged(tag string, v any) (string, error) {
	raw, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return "", fmt.Errorf("write %s: %w", tag, err)
	}
	return "<" + tag + ">\n" + string(raw) + "\n</" + tag + ">", nil
}

type agent[T any] struct {
	model   string
	system  string
	schema  map[string]any
	timeout time.Duration
	cached  string
	pdfs    [][]byte
	verify  func(T) []string
}

func (a agent[T]) run(ctx context.Context, llm *claude.Client, prompt string) Run[T] {
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	out := Run[T]{Model: a.model, PromptID: promptID(a.system)}
	request := claude.Request{Model: a.model, System: a.system, Cached: a.cached, Prompt: prompt, PDFs: a.pdfs, Schema: a.schema}
	for range maxAttempts {
		raw, err := llm.Structured(ctx, request)
		if err != nil {
			log.Printf("agents: %v", err)
			out.Status, out.Violations = statusOf(err), nil
			return out
		}
		output, violations := a.check(raw)
		if len(violations) == 0 {
			out.Status, out.Output, out.Violations = Verified, &output, nil
			return out
		}
		out.Status, out.Violations = Rejected, violations
		request.Prompt = prompt + rejectedSection(violations)
	}
	return out
}

func (a agent[T]) check(raw []byte) (T, []string) {
	var output T
	if err := json.Unmarshal(raw, &output); err != nil {
		return output, []string{"answer is not the expected JSON: " + err.Error()}
	}
	return output, a.verify(output)
}

func statusOf(err error) Status {
	if errors.Is(err, claude.ErrRefused) {
		return Refused
	}
	return Failed
}

func rejectedSection(violations []string) string {
	raw, err := json.Marshal(violations)
	if err != nil {
		return ""
	}
	return "\n<rejected>\n" + string(raw) + "\n</rejected>"
}

func promptID(system string) string {
	sum := sha256.Sum256([]byte(system))
	return hex.EncodeToString(sum[:6])
}

func object(properties map[string]any) map[string]any {
	return map[string]any{"type": "object", "properties": properties, "required": slices.Sorted(maps.Keys(properties)), "additionalProperties": false}
}

func arrayOf(items map[string]any) map[string]any {
	return map[string]any{"type": "array", "items": items}
}

func oneOf(values ...string) map[string]any {
	return map[string]any{"type": "string", "enum": values}
}

func text() map[string]any {
	return map[string]any{"type": "string"}
}

func nullable(schema map[string]any) map[string]any {
	return map[string]any{"anyOf": []map[string]any{schema, {"type": "null"}}}
}
