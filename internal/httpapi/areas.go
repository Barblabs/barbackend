package httpapi

import (
	"context"
	"net/http"
	"time"

	"barbackend/internal/areas"
	"barbackend/internal/tenancy"
	"github.com/danielgtaylor/huma/v2"
)

type areaHandler struct {
	areas *areas.Service
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
}

type areaQuery struct {
	Active string `query:"active" enum:"true,false,all" default:"true"`
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
	var active *bool
	switch in.Active {
	case "true":
		active = ptr(true)
	case "false":
		active = ptr(false)
	}
	stored, err := h.areas.List(ctx, caller, active)
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
		Name:          a.Imported().Name(),
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
