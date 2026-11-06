// Package agents holds the use cases of barbattack's Agents: the Prioritizer
// orders a Customer's open Findings, Luna writes the Action Plan of one, the
// Analista talks with a Customer's Users about them (ADR 0016), and the
// Drafter drafts a Customer's Business Context from a document (ADR 0017).
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
	"barbackend/internal/claude"
	"github.com/google/uuid"
)

const (
	defaultPrioritizerModel = "claude-haiku-5-5"
	defaultLunaModel        = "claude-haiku-5-5"
	defaultAnalistaModel    = "claude-opus-5-5"
	defaultDrafterModel     = "claude-opus-5-5"

	// MaxFindings bounds a Prioritization: the Prioritizer reads every Finding
	// in one request, to weigh them against each other.
	MaxFindings = 100

	maxAttempts        = 2
	prioritizerTimeout = 5 * time.Minute
	lunaTimeout        = 2 * time.Minute
	drafterTimeout     = 3 * time.Minute
)

var (
	// ErrInvalidFindings is a list of Findings that is empty, longer than
	// MaxFindings, repeats a Finding or holds a Dossier built wrong.
	ErrInvalidFindings = errors.New("invalid findings")
	// ErrFindingNotFound is a Finding that a Prioritization does not hold.
	ErrFindingNotFound = errors.New("finding not found")
)

// Models names the model each Agent runs on.
type Models struct {
	Prioritizer, Luna, Analista, Drafter string
}

// DefaultModels are the models the Agents run on unless told otherwise.
func DefaultModels() Models {
	return Models{Prioritizer: defaultPrioritizerModel, Luna: defaultLunaModel, Analista: defaultAnalistaModel, Drafter: defaultDrafterModel}
}

// ModelsFrom takes each Agent's model from getenv's PRIORITIZER_MODEL,
// LUNA_MODEL, ANALISTA_MODEL and DRAFTER_MODEL, or from DefaultModels when
// blank.
func ModelsFrom(getenv func(string) string) Models {
	models := DefaultModels()
	for name, model := range map[string]*string{"PRIORITIZER_MODEL": &models.Prioritizer, "LUNA_MODEL": &models.Luna, "ANALISTA_MODEL": &models.Analista, "DRAFTER_MODEL": &models.Drafter} {
		if v := strings.TrimSpace(getenv(name)); v != "" {
			*model = v
		}
	}
	return models
}

// Crew is the Prioritizer, Luna and the Drafter. It reads no Feed and touches
// no database: all it knows of a Finding is the Dossier it is given, and of a
// Customer's business the Document it is given.
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

// Prioritization is what the Prioritizer said about a Customer's open Findings
// at one moment, with the Dossiers it was given. Only Service stores one,
// giving it the fields JSON leaves out.
type Prioritization struct {
	ID       uuid.UUID  `json:"-"`
	Created  time.Time  `json:"-"`
	Plans    []Plan     `json:"-"`
	Feedback []Feedback `json:"-"`

	Findings    []assessment.Dossier         `json:"findings"`
	Prioritizer Run[assessment.PriorityList] `json:"prioritizer"`
}

// Plan is Luna's Action Plan for one Finding of a Prioritization.
type Plan struct {
	Finding string                     `json:"finding"`
	Created time.Time                  `json:"created"`
	Luna    Run[assessment.ActionPlan] `json:"luna"`
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
func (p Prioritization) GroupOf(id string) int {
	if p.Prioritizer.Output == nil {
		return 0
	}
	for i, g := range p.Prioritizer.Output.Groups {
		if slices.Contains(g.Findings, id) {
			return i + 1
		}
	}
	return 0
}

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

// Prioritize runs the Prioritizer on findings, a Customer's open Findings as
// the Findings pipeline built their Dossiers. It fails with ErrInvalidFindings
// before calling the model. A Prioritizer that cannot answer only shows in its
// Status.
func (c *Crew) Prioritize(ctx context.Context, findings []assessment.Dossier) (Prioritization, error) {
	if err := checkFindings(findings); err != nil {
		return Prioritization{}, err
	}
	briefs := make([]assessment.Brief, len(findings))
	for i, d := range findings {
		briefs[i] = d.Brief()
	}
	prompt, err := tagged("findings", briefs)
	if err != nil {
		return Prioritization{}, err
	}
	run := newPrioritizer(c.models.Prioritizer, briefs).run(ctx, c.llm, prompt)
	return Prioritization{Findings: findings, Prioritizer: run}, nil
}

func checkFindings(findings []assessment.Dossier) error {
	if len(findings) == 0 || len(findings) > MaxFindings {
		return fmt.Errorf("%w: give from 1 to %d, not %d", ErrInvalidFindings, MaxFindings, len(findings))
	}
	seen := make(map[string]bool, len(findings))
	for _, d := range findings {
		if err := d.Validate(); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidFindings, err)
		}
		if seen[d.Finding] {
			return fmt.Errorf("%w: finding %q is repeated", ErrInvalidFindings, d.Finding)
		}
		seen[d.Finding] = true
	}
	return nil
}

// Plan runs Luna on the Finding of p with that id. It fails with
// ErrFindingNotFound before calling the model. Luna not answering only shows
// in the Run's Status.
func (c *Crew) Plan(ctx context.Context, p Prioritization, finding string) (Run[assessment.ActionPlan], error) {
	d, ok := p.Finding(finding)
	if !ok {
		return Run[assessment.ActionPlan]{}, fmt.Errorf("%w: %q", ErrFindingNotFound, finding)
	}
	prompt, err := tagged("dossier", d)
	if err != nil {
		return Run[assessment.ActionPlan]{}, err
	}
	return newLuna(c.models.Luna, d).run(ctx, c.llm, prompt), nil
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
	pdfs    [][]byte
	verify  func(T) []string
}

func (a agent[T]) run(ctx context.Context, llm *claude.Client, prompt string) Run[T] {
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	out := Run[T]{Model: a.model, PromptID: promptID(a.system)}
	request := claude.Request{Model: a.model, System: a.system, Prompt: prompt, PDFs: a.pdfs, Schema: a.schema}
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
