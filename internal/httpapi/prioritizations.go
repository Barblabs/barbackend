package httpapi

import (
	"context"
	"net/http"
	"time"

	"barbackend/internal/agents"
	"barbackend/internal/tenancy"
	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
)

type prioritizationHandler struct {
	agents *agents.Service
}

func (h prioritizationHandler) register(api huma.API) {
	register(api, huma.Operation{
		OperationID: "list-prioritizations",
		Method:      http.MethodGet,
		Path:        "/prioritizations",
		Summary:     "List the Prioritizations of the Customer's open Findings, newest first",
		Description: "The Findings pipeline creates them; the newest is the order to follow.",
		Errors:      []int{http.StatusBadRequest},
	}, h.list)
	register(api, huma.Operation{
		OperationID: "get-prioritization",
		Method:      http.MethodGet,
		Path:        "/prioritizations/{id}",
		Summary:     "Read a Prioritization: its Priority Groups in the order to attend them, its Findings, their Action Plans and Feedback",
		Errors:      []int{http.StatusNotFound},
	}, h.get)
	register(api, huma.Operation{
		OperationID:   "create-action-plan",
		Method:        http.MethodPost,
		Path:          "/prioritizations/{id}/plans",
		Summary:       "Ask Luna for the Action Plan of one Finding of a Prioritization",
		Description:   "Runs Luna, which can take a minute. A Finding asked again gets a newer plan.",
		DefaultStatus: http.StatusCreated,
		Errors:        []int{http.StatusBadRequest, http.StatusNotFound, http.StatusBadGateway},
	}, h.plan)
	register(api, huma.Operation{
		OperationID:   "record-prioritization-feedback",
		Method:        http.MethodPost,
		Path:          "/prioritizations/{id}/feedback",
		Summary:       "Record what a User says about a Finding of a Prioritization",
		Description:   "It changes no Score and no order.",
		DefaultStatus: http.StatusCreated,
		Errors:        []int{http.StatusBadRequest, http.StatusNotFound},
	}, h.recordFeedback)
}

type prioritizationSummaryResponse struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Findings  int       `json:"findings" doc:"How many Findings it orders"`
	Groups    int       `json:"groups" doc:"How many Priority Groups it has"`
}

type prioritizationListResponse struct {
	Prioritizations []prioritizationSummaryResponse `json:"prioritizations"`
}

type prioritizationResponse struct {
	ID        string                  `json:"id"`
	CreatedAt time.Time               `json:"created_at"`
	Model     string                  `json:"model"`
	PromptID  string                  `json:"prompt_id"`
	Groups    []priorityGroupResponse `json:"groups" doc:"In the order to attend them"`
	Findings  []findingResponse       `json:"findings"`
	Plans     []planResponse          `json:"plans" doc:"The newest Action Plan of each Finding that has one"`
	Feedback  []feedbackResponse      `json:"feedback"`
}

type priorityGroupResponse struct {
	Position   int                `json:"position" doc:"1 is attended first"`
	Title      string             `json:"title"`
	Reason     string             `json:"reason"`
	FindingIDs []string           `json:"finding_ids" doc:"Findings attended at the same time"`
	Evidence   []evidenceResponse `json:"evidence"`
}

type evidenceResponse struct {
	FindingID string `json:"finding_id"`
	Path      string `json:"path" doc:"RFC 6901 pointer into what the Prioritizer read of the Finding"`
	Value     string `json:"value"`
}

type findingResponse struct {
	FindingID string  `json:"finding_id"`
	CVEID     string  `json:"cve_id"`
	AssetName string  `json:"asset_name"`
	Component string  `json:"component"`
	Version   string  `json:"version"`
	Score     float64 `json:"score"`
	ScoreRank int     `json:"score_rank" doc:"Where the Score alone would put it, 1 the highest"`
	Group     int     `json:"group" doc:"Position of its Priority Group"`
	Dossier   any     `json:"dossier" doc:"What the Agents read, to show as evidence. Its shape is not a contract."`
}

type planResponse struct {
	FindingID string             `json:"finding_id"`
	Model     string             `json:"model"`
	PromptID  string             `json:"prompt_id"`
	CreatedAt time.Time          `json:"created_at"`
	Output    actionPlanResponse `json:"output"`
}

type actionPlanResponse struct {
	Summary      string   `json:"summary"`
	Steps        []string `json:"steps"`
	FixedVersion *string  `json:"fixed_version"`
	Mitigation   *string  `json:"mitigation"`
	Verification string   `json:"verification"`
	Sources      []string `json:"sources"`
}

type feedbackResponse struct {
	ID          string    `json:"id"`
	FindingID   string    `json:"finding_id"`
	AuthorID    string    `json:"author_id"`
	Verdict     string    `json:"verdict"`
	Note        string    `json:"note"`
	ViaAnalista bool      `json:"via_analista"`
	CreatedAt   time.Time `json:"created_at"`
}

type prioritizationPageSize int

func (prioritizationPageSize) Schema(huma.Registry) *huma.Schema {
	return &huma.Schema{Type: huma.TypeInteger, Minimum: ptr(1.0), Maximum: ptr(float64(agents.MaxLimit)), Default: agents.DefaultLimit}
}

type prioritizationListQuery struct {
	Limit prioritizationPageSize `query:"limit" doc:"Page size"`
}

func (h prioritizationHandler) list(ctx context.Context, caller tenancy.User, in *prioritizationListQuery) (*body[prioritizationListResponse], error) {
	list, err := h.agents.List(ctx, caller, int(in.Limit))
	if err != nil {
		return nil, err
	}
	resp := prioritizationListResponse{Prioritizations: make([]prioritizationSummaryResponse, len(list))}
	for i, p := range list {
		resp.Prioritizations[i] = prioritizationSummaryResponse{ID: p.ID.String(), CreatedAt: p.Created, Findings: p.Findings, Groups: p.Groups}
	}
	return &body[prioritizationListResponse]{Body: resp}, nil
}

func (h prioritizationHandler) get(ctx context.Context, caller tenancy.User, in *idPath) (*body[prioritizationResponse], error) {
	p, err := h.agents.Get(ctx, caller, in.ID)
	if err != nil {
		return nil, err
	}
	return &body[prioritizationResponse]{Body: newPrioritizationResponse(p)}, nil
}

type planRequest struct {
	ID   uuid.UUID `path:"id" format:"uuid"`
	Body struct {
		FindingID string `json:"finding_id" minLength:"1"`
	}
}

func (h prioritizationHandler) plan(ctx context.Context, caller tenancy.User, in *planRequest) (*body[planResponse], error) {
	plan, err := h.agents.Plan(ctx, caller, in.ID, in.Body.FindingID)
	if err != nil {
		return nil, err
	}
	return &body[planResponse]{Body: newPlanResponse(plan)}, nil
}

type verdictCode string

func (verdictCode) Schema(huma.Registry) *huma.Schema {
	verdicts := agents.FeedbackVerdicts()
	enum := make([]any, len(verdicts))
	for i, v := range verdicts {
		enum[i] = v
	}
	return &huma.Schema{Type: huma.TypeString, Enum: enum}
}

type noteText string

func (noteText) Schema(huma.Registry) *huma.Schema {
	return &huma.Schema{Type: huma.TypeString, MaxLength: ptr(agents.MaxNoteLength)}
}

type feedbackRequest struct {
	ID   uuid.UUID `path:"id" format:"uuid"`
	Body struct {
		FindingID string      `json:"finding_id" minLength:"1"`
		Verdict   verdictCode `json:"verdict"`
		Note      noteText    `json:"note" required:"false"`
	}
}

func (h prioritizationHandler) recordFeedback(ctx context.Context, caller tenancy.User, in *feedbackRequest) (*body[feedbackResponse], error) {
	stored, err := h.agents.RecordFeedback(ctx, caller, in.ID, in.Body.FindingID, string(in.Body.Verdict), string(in.Body.Note))
	if err != nil {
		return nil, err
	}
	return &body[feedbackResponse]{Body: newFeedbackResponse(stored)}, nil
}

func newPrioritizationResponse(p agents.Prioritization) prioritizationResponse {
	resp := prioritizationResponse{
		ID:        p.ID.String(),
		CreatedAt: p.Created,
		Model:     p.Prioritizer.Model,
		PromptID:  p.Prioritizer.PromptID,
		Groups:    []priorityGroupResponse{},
		Findings:  make([]findingResponse, len(p.Findings)),
		Plans:     make([]planResponse, len(p.Plans)),
		Feedback:  make([]feedbackResponse, len(p.Feedback)),
	}
	if output := p.Prioritizer.Output; output != nil {
		for i, g := range output.Groups {
			evidence := make([]evidenceResponse, len(g.Evidence))
			for j, e := range g.Evidence {
				evidence[j] = evidenceResponse{FindingID: e.Finding, Path: e.Path, Value: e.Value}
			}
			resp.Groups = append(resp.Groups, priorityGroupResponse{Position: i + 1, Title: g.Title, Reason: g.Reason, FindingIDs: nonNil(g.Findings), Evidence: evidence})
		}
	}
	ranks := p.ScoreRanks()
	for i, d := range p.Findings {
		resp.Findings[i] = findingResponse{
			FindingID: d.Finding,
			CVEID:     d.CVE,
			AssetName: d.Asset.Name,
			Component: d.Component.Name,
			Version:   d.Component.Version,
			Score:     d.Score.Value,
			ScoreRank: ranks[d.Finding],
			Group:     p.GroupOf(d.Finding),
			Dossier:   d,
		}
	}
	for i, plan := range p.Plans {
		resp.Plans[i] = newPlanResponse(plan)
	}
	for i, f := range p.Feedback {
		resp.Feedback[i] = newFeedbackResponse(f)
	}
	return resp
}

func newPlanResponse(plan agents.Plan) planResponse {
	resp := planResponse{FindingID: plan.Finding, Model: plan.Luna.Model, PromptID: plan.Luna.PromptID, CreatedAt: plan.Created}
	if o := plan.Luna.Output; o != nil {
		resp.Output = actionPlanResponse{
			Summary:      o.Summary,
			Steps:        nonNil(o.Steps),
			FixedVersion: o.FixedVersion,
			Mitigation:   o.Mitigation,
			Verification: o.Verification,
			Sources:      nonNil(o.Sources),
		}
	}
	return resp
}

func newFeedbackResponse(f agents.Feedback) feedbackResponse {
	return feedbackResponse{
		ID:          f.ID.String(),
		FindingID:   f.Finding,
		AuthorID:    f.Author.String(),
		Verdict:     f.Verdict.Code(),
		Note:        f.Note,
		ViaAnalista: f.ViaAnalista,
		CreatedAt:   f.Created,
	}
}

func nonNil(items []string) []string {
	if items == nil {
		return []string{}
	}
	return items
}
