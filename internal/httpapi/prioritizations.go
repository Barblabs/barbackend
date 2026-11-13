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
		Description: "The Prioritizer creates one each time it places new or changed Findings in the order that stands; the newest is the order to follow.",
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
		Description:   "It changes no Score. should_be_earlier and should_be_later have the Prioritizer place the Finding again, with the note, in its next round.",
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
	ID                     string                  `json:"id"`
	PreviousID             *string                 `json:"previous_id" doc:"The Prioritization this one was built from, null for the Customer's first"`
	BusinessContextVersion *int                    `json:"business_context_version" doc:"The version of the Business Context the Prioritizer read, null when the Customer had stated none"`
	CreatedAt              time.Time               `json:"created_at"`
	Model                  string                  `json:"model"`
	PromptID               string                  `json:"prompt_id"`
	Groups                 []priorityGroupResponse `json:"groups" doc:"In the order to attend them"`
	Findings               []findingResponse       `json:"findings"`
	Plans                  []planResponse          `json:"plans" doc:"The newest Action Plan of each Finding that has one, whichever Prioritization it was asked from"`
	Feedback               []feedbackResponse      `json:"feedback" doc:"What Users said about its Findings, whichever Prioritization they said it on"`
}

type priorityGroupResponse struct {
	Position        int                       `json:"position" doc:"1 is attended first"`
	Title           string                    `json:"title"`
	Reason          string                    `json:"reason"`
	FindingIDs      []string                  `json:"finding_ids" doc:"Findings attended at the same time"`
	Evidence        []evidenceResponse        `json:"evidence"`
	ContextEvidence []contextEvidenceResponse `json:"context_evidence" doc:"What the reason relies on from the Business Context"`
}

type evidenceResponse struct {
	FindingID string `json:"finding_id"`
	Path      string `json:"path" doc:"RFC 6901 pointer into what the Prioritizer read of the Finding"`
	Value     string `json:"value"`
}

type contextEvidenceResponse struct {
	Path  string `json:"path" doc:"RFC 6901 pointer into the business_context/1 document of the version the Prioritizer read"`
	Value string `json:"value"`
}

type findingResponse struct {
	FindingID string                 `json:"finding_id"`
	CVEID     string                 `json:"cve_id"`
	AssetName string                 `json:"asset_name"`
	Component string                 `json:"component"`
	Version   string                 `json:"version"`
	Score     float64                `json:"score"`
	ScoreRank int                    `json:"score_rank" doc:"Where the Score alone would put it, 1 the highest"`
	Group     int                    `json:"group" doc:"Position of its Priority Group"`
	PlacedAt  time.Time              `json:"placed_at" doc:"When the round that last placed it read it: later than the created_at of previous_id when this one placed it"`
	ClosedAt  *time.Time             `json:"closed_at" doc:"When the Finding was closed, null while it is open. A closed Finding leaves the order the next Prioritization starts from."`
	Details   findingDetailsResponse `json:"details" doc:"What the Agents read of the Finding when it was placed. Its text comes from Feeds, the CMDB and the Customer: render it as plain text."`
}

type findingDetailsResponse struct {
	Description      string               `json:"description"`
	Asset            findingAssetResponse `json:"asset"`
	ComponentRole    string               `json:"component_role" doc:"operating_system or application, blank when the Asset no longer runs the component"`
	ScoreDetails     scoreResponse        `json:"score_details"`
	KEV              *kevResponse         `json:"kev" doc:"Null when the KEV catalog does not list the CVE, or could not be read: see unavailable_feeds"`
	EPSS             *epssResponse        `json:"epss" doc:"Null when EPSS has no score for the CVE yet"`
	CVSS             []cvssResponse       `json:"cvss"`
	References       []string             `json:"references" doc:"NVD's references of the CVE"`
	UnavailableFeeds []string             `json:"unavailable_feeds" doc:"Feeds that could not be read, which is not the same as not listing the CVE: kev, epss or nvd"`
	Advisories       []advisoryResponse   `json:"advisories" doc:"Vendor bulletins that name the Vulnerability, newest first"`
	Labeling         labelingResponse     `json:"labeling"`
	Techniques       []techniqueResponse  `json:"techniques" doc:"ATT&CK Techniques the Cartógrafo inferred from the Vulnerability's text: an inference, not MITRE's word"`
}

type findingAssetResponse struct {
	Name             string                    `json:"name"`
	Kind             string                    `json:"kind"`
	Criticality      string                    `json:"criticality" enum:"high,medium,low,unknown"`
	Exposure         string                    `json:"exposure" enum:"internet_facing,internal,unknown"`
	LifecycleStage   string                    `json:"lifecycle_stage" enum:"production,implementation,stock,unknown"`
	CriticalServices []criticalServiceResponse `json:"critical_services" doc:"The Critical Services of the Business Context that name the Asset"`
}

type criticalServiceResponse struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Impact      string `json:"impact" doc:"Blank when the Customer has not stated it"`
	MaxDowntime string `json:"max_downtime" doc:"Blank when the Customer has not stated it"`
}

type scoreResponse struct {
	ScoringModel          int      `json:"scoring_model"`
	Value                 float64  `json:"value"`
	Alpha                 float64  `json:"alpha" doc:"CVSS base score over 10"`
	Beta                  float64  `json:"beta" doc:"EPSS probability"`
	Gamma                 float64  `json:"gamma" doc:"1 when KEV lists the CVE"`
	Vulnerability         float64  `json:"vulnerability" doc:"The Vulnerability's score before the Asset's multipliers"`
	CriticalityMultiplier float64  `json:"criticality_multiplier"`
	ExposureMultiplier    float64  `json:"exposure_multiplier"`
	LifecycleMultiplier   float64  `json:"lifecycle_multiplier" doc:"1 in a Scoring Model without a lifecycle factor"`
	DataGaps              []string `json:"data_gaps" doc:"Inputs a default replaced: the Score is estimated, not measured"`
}

type kevResponse struct {
	DateAdded                  string `json:"date_added"`
	DueDate                    string `json:"due_date"`
	RequiredAction             string `json:"required_action"`
	KnownRansomwareCampaignUse string `json:"known_ransomware_campaign_use"`
}

type epssResponse struct {
	Probability float64 `json:"probability"`
	Percentile  float64 `json:"percentile"`
	ScoreDate   string  `json:"score_date"`
}

type cvssResponse struct {
	Version   string  `json:"version"`
	BaseScore float64 `json:"base_score"`
	Vector    string  `json:"vector"`
	Type      string  `json:"type" doc:"Primary is NVD's; Secondary the numbering authority's"`
}

type advisoryResponse struct {
	Title       string `json:"title"`
	Published   string `json:"published" doc:"YYYY-MM-DD"`
	Feed        string `json:"feed"`
	Description string `json:"description"`
}

type labelingResponse struct {
	Outcome string `json:"outcome" enum:"labeled,none,failed,not_tried" doc:"Only labeled has Techniques; the others say nothing of how it is attacked"`
	Model   string `json:"model"`
}

type techniqueResponse struct {
	AttackID    string               `json:"attack_id"`
	LabeledAs   string               `json:"labeled_as" doc:"The revoked ATT&CK id the Cartógrafo gave, when the catalog replaced it; blank otherwise"`
	Name        string               `json:"name"`
	Tactics     []string             `json:"tactics"`
	Role        string               `json:"role" enum:"exploitation,primary_impact,secondary_impact"`
	Evidence    string               `json:"evidence" doc:"The quote of the Vulnerability's text that supports the label"`
	Rationale   string               `json:"rationale"`
	Mitigations []mitigationResponse `json:"mitigations"`
}

type mitigationResponse struct {
	AttackID string `json:"attack_id"`
	Name     string `json:"name"`
	Advice   string `json:"advice" doc:"MITRE's advice for this Technique"`
}

type planResponse struct {
	FindingID string             `json:"finding_id"`
	Model     string             `json:"model"`
	PromptID  string             `json:"prompt_id"`
	CreatedAt time.Time          `json:"created_at"`
	Output    actionPlanResponse `json:"output"`
}

type actionPlanResponse struct {
	Summary           string                   `json:"summary"`
	Steps             []string                 `json:"steps"`
	FixedVersion      *string                  `json:"fixed_version"`
	Mitigation        *string                  `json:"mitigation"`
	Verification      string                   `json:"verification"`
	Sources           []string                 `json:"sources"`
	AttackMitigations []planMitigationResponse `json:"attack_mitigations" doc:"MITRE's Mitigations of the ATT&CK Techniques the Cartógrafo inferred, against the exploitation first"`
}

type planMitigationResponse struct {
	MitigationID string `json:"mitigation_id" doc:"ATT&CK id of the Mitigation, such as M1051"`
	TechniqueID  string `json:"technique_id" doc:"ATT&CK id of the Technique it mitigates"`
	Step         string `json:"step"`
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
		Groups:    make([]priorityGroupResponse, len(p.List.Groups)),
		Findings:  make([]findingResponse, len(p.Findings)),
		Plans:     make([]planResponse, len(p.Plans)),
		Feedback:  make([]feedbackResponse, len(p.Feedback)),
	}
	if p.Previous != nil {
		resp.PreviousID = ptr(p.Previous.String())
	}
	if p.BusinessContext > 0 {
		resp.BusinessContextVersion = ptr(p.BusinessContext)
	}
	for i, g := range p.List.Groups {
		evidence, context := g.Evidence(), g.ContextEvidence()
		group := priorityGroupResponse{
			Position: i + 1, Title: g.Title, Reason: g.Reason(), FindingIDs: nonNil(g.Findings()),
			Evidence: make([]evidenceResponse, len(evidence)), ContextEvidence: make([]contextEvidenceResponse, len(context)),
		}
		for j, e := range evidence {
			group.Evidence[j] = evidenceResponse{FindingID: e.Finding, Path: e.Path, Value: e.Value}
		}
		for j, e := range context {
			group.ContextEvidence[j] = contextEvidenceResponse{Path: e.Path, Value: e.Value}
		}
		resp.Groups[i] = group
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
			PlacedAt:  p.States[d.Finding].Placed,
			ClosedAt:  p.States[d.Finding].Closed,
			Details:   newFindingDetails(d),
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
		resp.Output.AttackMitigations = make([]planMitigationResponse, len(o.AttackMitigations))
		for i, m := range o.AttackMitigations {
			resp.Output.AttackMitigations[i] = planMitigationResponse{MitigationID: m.Mitigation, TechniqueID: m.Technique, Step: m.Step}
		}
	}
	return resp
}

func newFeedbackResponse(f agents.Feedback) feedbackResponse {
	return feedbackResponse{
		ID:          f.ID.String(),
		FindingID:   f.Finding.String(),
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
