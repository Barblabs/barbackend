package httpapi

import (
	"context"
	"net/http"
	"time"

	"barbackend/internal/areas"
	"barbackend/internal/findings"
	"barbackend/internal/tenancy"
	"github.com/danielgtaylor/huma/v2"
)

type areaHandler struct {
	areas    *areas.Service
	findings *findings.Service
}

func (h areaHandler) register(api huma.API) {
	register(api, huma.Operation{
		OperationID: "list-areas",
		Method:      http.MethodGet,
		Path:        "/areas",
		Summary:     "List the Customer's Areas",
		Description: "Lists every Area imported from the Customer's CMDB Sources, sorted by name. An Area is what iTop calls an Organization. The list is not paged.",
		Errors:      []int{http.StatusBadRequest},
	}, h.list)
	register(api, huma.Operation{
		OperationID: "set-area-owner",
		Method:      http.MethodPut,
		Path:        "/areas/{id}/owner",
		Summary:     "State whom to reach about an Area",
		Description: "Only a Customer Admin states it. A null email clears it. A Sync never changes it, not even when it renames the Area.",
		Errors:      []int{http.StatusBadRequest, http.StatusNotFound},
	}, h.setOwner)
	register(api, huma.Operation{
		OperationID: "get-areas-health",
		Method:      http.MethodGet,
		Path:        "/areas/health",
		Summary:     "Report how each of the Customer's Areas is doing and flag those that need help",
		Description: "One entry per Active Area, and one with a null id for the Assets with no Area when they have open Findings. Inactive Areas, and the Findings of their Assets, are left out. An Area needs help for aging_critical, when an open Finding has been Critical for over 30 days, counted from the start of its latest unbroken run of Critical Scores, and for growing, when each of the last 3 complete ISO weeks, in UTC, first opened more of its Findings than it closed. Flagged Areas come first, then the oldest Critical first, with none last, then the most Critical open, then by name, with no Area last. fixed counts remediated, component_removed and no_longer_affected closes in the last 30 days. A Finding closed and then reopened keeps no record of that close, so it is not counted as closed, and counts as open while it was closed. The list is not paged.",
	}, h.health)
}

type areaQuery struct {
	Active activeFilter `query:"active" enum:"true,false,all" default:"true"`
}

type areaListResponse struct {
	Areas []areaResponse `json:"areas"`
}

type areaResponse struct {
	ID            int64      `json:"id"`
	SourceID      string     `json:"source_id"`
	RecordID      string     `json:"record_id" doc:"The Area's id in its CMDB Source"`
	Name          string     `json:"name"`
	OwnerEmail    *string    `json:"owner_email" doc:"Whom to reach about the Area, as a Customer Admin states it; null until one does"`
	Active        bool       `json:"active" doc:"False once the CMDB Source marks the Area inactive, stops returning it, or is disconnected"`
	InactiveSince *time.Time `json:"inactive_since" doc:"When the Area became Inactive; null while it is Active"`
}

type setAreaOwnerRequest struct {
	_     struct{} `additionalProperties:"true"`
	Email *string  `json:"email" format:"email" doc:"Whom to reach about the Area; null clears it"`
}

type setAreaOwnerInput struct {
	ID   int64 `path:"id"`
	Body setAreaOwnerRequest
}

func (h areaHandler) list(ctx context.Context, caller tenancy.User, in *areaQuery) (*body[areaListResponse], error) {
	stored, err := h.areas.List(ctx, caller, in.Active.keep())
	if err != nil {
		return nil, err
	}
	resp := areaListResponse{Areas: make([]areaResponse, len(stored))}
	for i, a := range stored {
		resp.Areas[i] = newAreaResponse(a)
	}
	return &body[areaListResponse]{Body: resp}, nil
}

func newAreaResponse(stored areas.StoredArea) areaResponse {
	a := stored.Area
	resp := areaResponse{
		ID:            stored.ID,
		SourceID:      a.Ref().Source.String(),
		RecordID:      a.Ref().RecordID,
		Name:          a.Name(),
		Active:        a.Active(),
		InactiveSince: stored.InactiveSince,
	}
	if owner, ok := a.Owner(); ok {
		resp.OwnerEmail = ptr(owner.String())
	}
	return resp
}

func (h areaHandler) setOwner(ctx context.Context, caller tenancy.User, in *setAreaOwnerInput) (*body[areaResponse], error) {
	stored, err := h.areas.SetOwner(ctx, caller, in.ID, in.Body.Email)
	if err != nil {
		return nil, err
	}
	return &body[areaResponse]{Body: newAreaResponse(stored)}, nil
}

type areaHealthListResponse struct {
	Areas []areaHealthResponse `json:"areas"`
}

type areaHealthResponse struct {
	ID                 *int64   `json:"id" doc:"As in GET /areas; null for the Assets with no Area"`
	Name               *string  `json:"name" doc:"Null for the Assets with no Area"`
	OwnerEmail         *string  `json:"owner_email" doc:"Whom to reach about the Area; null until a Customer Admin states it"`
	AssetCount         int      `json:"asset_count" doc:"Active Assets"`
	CriticalOpen       int      `json:"critical_open" doc:"Open Findings whose latest Score is Critical"`
	HighOpen           int      `json:"high_open" doc:"Open Findings whose latest Score is High"`
	OldestCriticalDays *int     `json:"oldest_critical_days" doc:"Whole days since the longest-Critical open Finding's latest unbroken run of Critical Scores began; null when none is Critical"`
	Fixed              int      `json:"fixed" doc:"Findings closed as Fixed in the last 30 days"`
	OpenNow            int      `json:"open_now" doc:"Open scored Findings; summed over the entries, open in GET /findings/summary, but for the Findings of Assets in Inactive Areas"`
	Open30DaysAgo      int      `json:"open_30_days_ago" doc:"Findings open 30 days ago"`
	NeedsHelp          bool     `json:"needs_help" doc:"True exactly when reasons is not empty"`
	Reasons            []string `json:"reasons" enum:"aging_critical,growing"`
}

func (h areaHandler) health(ctx context.Context, caller tenancy.User, _ *struct{}) (*body[areaHealthListResponse], error) {
	health, err := h.findings.AreaHealth(ctx, caller)
	if err != nil {
		return nil, err
	}
	resp := areaHealthListResponse{Areas: make([]areaHealthResponse, len(health))}
	for i, a := range health {
		reasons := make([]string, len(a.Reasons))
		for j, r := range a.Reasons {
			reasons[j] = r.String()
		}
		resp.Areas[i] = areaHealthResponse{
			ID: a.ID, OwnerEmail: a.OwnerEmail, AssetCount: a.AssetCount,
			CriticalOpen: a.Open.Critical, HighOpen: a.Open.High, OldestCriticalDays: a.OldestCriticalDays,
			Fixed: a.Fixed, OpenNow: a.Open.Total(), Open30DaysAgo: a.Open30DaysAgo,
			NeedsHelp: a.NeedsHelp(), Reasons: reasons,
		}
		if a.ID != nil {
			resp.Areas[i].Name = ptr(a.Name)
		}
	}
	return &body[areaHealthListResponse]{Body: resp}, nil
}
