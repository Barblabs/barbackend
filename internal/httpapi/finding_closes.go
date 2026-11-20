package httpapi

import (
	"context"
	"net/http"
	"time"

	"barbackend/internal/finding"
	"barbackend/internal/findings"
	"barbackend/internal/tenancy"
	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
)

// manualCloseReasons are the reasons a User gives to close a Finding
// (ADR 0035).
var manualCloseReasons = []finding.CloseReason{finding.Remediated, finding.FalsePositive, finding.AcceptedRisk, finding.Postponed}

// closeReasonOf is the reason of a code, or 0, which no close accepts.
func closeReasonOf(code closeReasonCode) finding.CloseReason {
	for _, r := range manualCloseReasons {
		if r.String() == string(code) {
			return r
		}
	}
	return 0
}

func (h findingHandler) registerCloses(api huma.API) {
	register(api, huma.Operation{
		OperationID: "close-finding",
		Method:      http.MethodPost,
		Path:        "/findings/{id}/close",
		Summary:     "Close one of the Customer's open Findings by hand",
		Description: "A Customer Admin or a Viewer closes it with a reason and a note saying why. remediated reopens at the next match if the CMDB still shows a vulnerable version; false_positive stays closed until a User reopens it; accepted_risk and postponed need reopen_at, and reopen at the first match after it. It leaves the Prioritizer's order.",
		Errors:      []int{http.StatusBadRequest, http.StatusNotFound, http.StatusConflict},
	}, h.close)
	register(api, huma.Operation{
		OperationID: "reopen-finding",
		Method:      http.MethodPost,
		Path:        "/findings/{id}/reopen",
		Summary:     "Reopen a Finding a User closed",
		Description: "A Customer Admin or a Viewer reopens a Finding closed by hand, whatever its reason. A Finding that closed on its own reopens only when it matches again.",
		Errors:      []int{http.StatusNotFound, http.StatusConflict},
	}, h.reopen)
	register(api, huma.Operation{
		OperationID: "list-closed-findings",
		Method:      http.MethodGet,
		Path:        "/findings/closed",
		Summary:     "List the Customer's Findings closed by hand",
		Description: "Newest close first, so one can be reopened. Findings closed on their own, by a Sync or NVD, are left out.",
	}, h.closed)
}

type closeReasonCode string

func (closeReasonCode) Schema(huma.Registry) *huma.Schema {
	enum := make([]any, len(manualCloseReasons))
	for i, r := range manualCloseReasons {
		enum[i] = r.String()
	}
	return &huma.Schema{Type: huma.TypeString, Enum: enum}
}

type closeNote string

func (closeNote) Schema(huma.Registry) *huma.Schema {
	return &huma.Schema{Type: huma.TypeString, MinLength: ptr(1), MaxLength: ptr(findings.MaxCloseNoteLength)}
}

type closeRequest struct {
	ID   uuid.UUID `path:"id" format:"uuid"`
	Body struct {
		Reason   closeReasonCode `json:"reason"`
		Note     closeNote       `json:"note" doc:"Why, as the User says it"`
		ReopenAt *time.Time      `json:"reopen_at,omitempty" required:"false" doc:"Required for accepted_risk and postponed, and must be ahead; not allowed otherwise"`
	}
}

func (h findingHandler) close(ctx context.Context, caller tenancy.User, in *closeRequest) (*struct{}, error) {
	return &struct{}{}, h.findings.CloseByHand(ctx, caller, finding.ID(in.ID), closeReasonOf(in.Body.Reason), string(in.Body.Note), in.Body.ReopenAt)
}

type findingPath struct {
	ID uuid.UUID `path:"id" format:"uuid"`
}

func (h findingHandler) reopen(ctx context.Context, caller tenancy.User, in *findingPath) (*struct{}, error) {
	return &struct{}{}, h.findings.ReopenByHand(ctx, caller, finding.ID(in.ID))
}

type closedFindingsResponse struct {
	Findings []closedFindingResponse `json:"findings"`
}

type closedFindingResponse struct {
	ID               string     `json:"id"`
	CVEID            string     `json:"cve_id"`
	AssetID          int64      `json:"asset_id" doc:"As in GET /assets"`
	AssetName        string     `json:"asset_name"`
	Vendor           string     `json:"vendor"`
	Product          string     `json:"product"`
	ComponentName    string     `json:"component_name"`
	ComponentVersion string     `json:"component_version"`
	Reason           closeReasonCode `json:"reason"`
	Note             string     `json:"note"`
	ClosedAt         time.Time  `json:"closed_at"`
	ClosedBy         string     `json:"closed_by" doc:"The email of the User who closed it"`
	ReopenAt         *time.Time `json:"reopen_at" doc:"When a match may reopen it; null for remediated and false_positive"`
}

func (h findingHandler) closed(ctx context.Context, caller tenancy.User, _ *struct{}) (*body[closedFindingsResponse], error) {
	closed, err := h.findings.ClosedByHand(ctx, caller)
	if err != nil {
		return nil, err
	}
	resp := closedFindingsResponse{Findings: make([]closedFindingResponse, len(closed))}
	for i, c := range closed {
		resp.Findings[i] = closedFindingResponse{
			ID: c.ID.String(), CVEID: c.CVE, AssetID: c.AssetID, AssetName: c.AssetName,
			Vendor: c.Product.Vendor, Product: c.Product.Name, ComponentName: c.ComponentName, ComponentVersion: c.ComponentVersion,
			Reason: closeReasonCode(c.Reason.String()), Note: c.Note, ClosedAt: c.Closed, ClosedBy: c.ClosedByEmail, ReopenAt: c.ReopenAt,
		}
	}
	return &body[closedFindingsResponse]{Body: resp}, nil
}
