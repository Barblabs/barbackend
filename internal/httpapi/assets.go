package httpapi

import (
	"context"
	"net/http"
	"time"

	"barbackend/internal/assets"
	"barbackend/internal/inventory"
	"barbackend/internal/tenancy"
	"github.com/danielgtaylor/huma/v2"
)

type assetHandler struct {
	assets *assets.Service
}

func (h assetHandler) register(api huma.API) {
	register(api, huma.Operation{
		OperationID: "list-assets",
		Method:      http.MethodGet,
		Path:        "/assets",
		Summary:     "List the Customer's Assets",
		Description: "Pages through Assets in a stable order. Pass next_cursor as cursor, with the same filters, to get the next page.",
		Errors:      []int{http.StatusBadRequest},
	}, h.list)
	register(api, huma.Operation{
		OperationID: "declare-asset-exposure",
		Method:      http.MethodPut,
		Path:        "/assets/{id}/exposure",
		Summary:     "Declare an Asset's Exposure",
		Description: "Only a Customer Admin declares it, over the imported Exposure, and only on an Active Asset. Unknown cannot be declared: clear the Declaration instead. The Asset's open Findings are rescored before the response; if that fails, the request fails but the Declaration stands. A Sync never changes it.",
		Errors:      []int{http.StatusBadRequest, http.StatusNotFound, http.StatusConflict},
	}, h.declareExposure)
	register(api, huma.Operation{
		OperationID: "clear-asset-exposure",
		Method:      http.MethodDelete,
		Path:        "/assets/{id}/exposure",
		Summary:     "Clear an Asset's declared Exposure",
		Description: "Only a Customer Admin clears it. The Asset's Exposure falls back to the imported one, and its open Findings are rescored before the response.",
		Errors:      []int{http.StatusNotFound},
	}, h.clearExposure)
}

type assetQuery struct {
	Limit       pageSize        `query:"limit" doc:"Page size"`
	Cursor      string          `query:"cursor" doc:"next_cursor of the previous page"`
	Active      activeFilter    `query:"active" enum:"true,false,all" default:"true"`
	Kind        assetKindCode   `query:"kind" doc:"Asset Kind code"`
	Criticality criticalityCode `query:"criticality" doc:"Criticality code"`
}

type activeFilter string

func (f activeFilter) keep() *bool {
	switch f {
	case "true":
		return ptr(true)
	case "false":
		return ptr(false)
	}
	return nil
}

type pageSize int

func (pageSize) Schema(huma.Registry) *huma.Schema {
	return &huma.Schema{Type: huma.TypeInteger, Minimum: ptr(1.0), Maximum: ptr(float64(assets.MaxLimit)), Default: assets.DefaultLimit}
}

type assetKindCode string

func (assetKindCode) Schema(huma.Registry) *huma.Schema {
	return &huma.Schema{Type: huma.TypeString, Enum: codes(inventory.Server, inventory.VirtualMachine, inventory.Workstation, inventory.NetworkDevice)}
}

type criticalityCode string

func (criticalityCode) Schema(huma.Registry) *huma.Schema {
	return &huma.Schema{Type: huma.TypeString, Enum: codes(inventory.CriticalityHigh, inventory.CriticalityMedium, inventory.CriticalityLow)}
}

func (in assetQuery) query() (assets.Query, error) {
	q := assets.Query{Limit: int(in.Limit), Cursor: in.Cursor, Active: in.Active.keep()}
	if in.Kind != "" {
		kind, err := inventory.ParseAssetKind(string(in.Kind))
		if err != nil {
			return assets.Query{}, err
		}
		q.Kind = &kind
	}
	if in.Criticality != "" {
		criticality, err := inventory.ParseCriticality(string(in.Criticality))
		if err != nil {
			return assets.Query{}, err
		}
		q.Criticality = &criticality
	}
	return q, nil
}

type assetListResponse struct {
	Assets     []assetResponse `json:"assets"`
	NextCursor *string         `json:"next_cursor"`
	Total      int             `json:"total"`
}

type assetResponse struct {
	ID            int64              `json:"id" doc:"The Asset's handle in this API, as in PUT /assets/{id}/exposure"`
	SourceID      string             `json:"source_id"`
	RecordID      string             `json:"record_id"`
	Name          string             `json:"name"`
	Description   string             `json:"description"`
	Kind          string             `json:"kind"`
	Hardware      *hardwareResponse  `json:"hardware"`
	Software      []softwareResponse `json:"software"`
	Criticality   *string            `json:"criticality"`
	Exposure      exposureResponse   `json:"exposure"`
	Owner         *ownerResponse     `json:"owner"`
	Area          *areaRefResponse   `json:"area"`
	Retired       bool               `json:"retired"`
	Active        bool               `json:"active"`
	InactiveSince *time.Time         `json:"inactive_since"`
}

type hardwareResponse struct {
	Vendor string `json:"vendor"`
	Model  string `json:"model"`
}

type softwareResponse struct {
	Role    string           `json:"role"`
	Name    string           `json:"name"`
	Version string           `json:"version"`
	Product *productResponse `json:"product"`
}

type productResponse struct {
	Vendor string `json:"vendor"`
	Name   string `json:"name"`
}

type exposureResponse struct {
	Value      *string    `json:"value" doc:"The effective Exposure, internet_facing or internal: the declared one, otherwise the imported one; null when Unknown"`
	Source     string     `json:"source" enum:"imported,declared" doc:"Whether value is the imported Exposure or a Declaration"`
	Imported   *string    `json:"imported" doc:"The Exposure the CMDB Source gives, internet_facing or internal, also beneath a Declaration; null when Unknown"`
	DeclaredBy *string    `json:"declared_by" doc:"Email of the User who declared it; null without a Declaration"`
	DeclaredAt *time.Time `json:"declared_at" doc:"When it was declared; null without a Declaration"`
}

type exposureCode string

func (exposureCode) Schema(huma.Registry) *huma.Schema {
	return &huma.Schema{Type: huma.TypeString, Enum: codes(inventory.InternetFacing, inventory.Internal)}
}

type declareExposureRequest struct {
	_        struct{}     `additionalProperties:"true"`
	Exposure exposureCode `json:"exposure" doc:"Unknown cannot be declared; clear the Declaration instead"`
}

type declareExposureInput struct {
	ID   int64 `path:"id"`
	Body declareExposureRequest
}

type assetIDInput struct {
	ID int64 `path:"id"`
}

type ownerResponse struct {
	Email  string `json:"email"`
	Source string `json:"source"`
}

type areaRefResponse struct {
	ID   int64  `json:"id" doc:"The Area's id, as in GET /areas"`
	Name string `json:"name"`
}

func (h assetHandler) list(ctx context.Context, caller tenancy.User, in *assetQuery) (*body[assetListResponse], error) {
	q, err := in.query()
	if err != nil {
		return nil, err
	}
	page, err := h.assets.List(ctx, caller, q)
	if err != nil {
		return nil, err
	}
	return &body[assetListResponse]{Body: newAssetListResponse(page)}, nil
}

func newAssetListResponse(page assets.Page) assetListResponse {
	resp := assetListResponse{Assets: make([]assetResponse, len(page.Assets)), Total: page.Total}
	for i, a := range page.Assets {
		resp.Assets[i] = newAssetResponse(a)
	}
	if page.NextCursor != "" {
		resp.NextCursor = &page.NextCursor
	}
	return resp
}

func newAssetResponse(stored assets.StoredAsset) assetResponse {
	a, imported := stored.Asset, stored.Asset.Imported()
	software := imported.Software()
	resp := assetResponse{
		ID:            stored.ID,
		SourceID:      a.Ref().Source.String(),
		RecordID:      a.Ref().RecordID,
		Name:          imported.Name(),
		Description:   imported.Description(),
		Kind:          imported.Kind().Code(),
		Software:      make([]softwareResponse, len(software)),
		Criticality:   code(imported.Criticality().Code()),
		Exposure:      newExposureResponse(stored),
		Retired:       imported.Retired(),
		Active:        a.Active(),
		InactiveSince: stored.InactiveSince,
	}
	if hw, ok := imported.Hardware(); ok {
		resp.Hardware = &hardwareResponse{Vendor: hw.Vendor, Model: hw.Model}
	}
	for i, sc := range software {
		resp.Software[i] = softwareResponse{Role: sc.Role.Code(), Name: sc.Name, Version: sc.Version}
		if sc.Identified() {
			resp.Software[i].Product = &productResponse{Vendor: sc.Product.Vendor, Name: sc.Product.Name}
		}
	}
	if area := stored.Area; area != nil {
		resp.Area = &areaRefResponse{ID: area.ID, Name: area.Name}
	}
	if owner, ok := a.Owner(); ok {
		resp.Owner = &ownerResponse{Email: owner.String(), Source: "imported"}
		if _, declared := a.DeclaredOwner(); declared {
			resp.Owner.Source = "declared"
		}
	}
	return resp
}

func newExposureResponse(stored assets.StoredAsset) exposureResponse {
	a := stored.Asset
	resp := exposureResponse{
		Value:    code(a.Exposure().Code()),
		Source:   "imported",
		Imported: code(a.Imported().Exposure().Code()),
	}
	if a.DeclaredExposure() != inventory.ExposureUnknown {
		resp.Source = "declared"
		if d := stored.ExposureAudit; d != nil {
			resp.DeclaredBy, resp.DeclaredAt = &d.By, &d.At
		}
	}
	return resp
}

func (h assetHandler) declareExposure(ctx context.Context, caller tenancy.User, in *declareExposureInput) (*body[assetResponse], error) {
	e, err := inventory.ParseExposure(string(in.Body.Exposure))
	if err != nil {
		return nil, err
	}
	stored, err := h.assets.DeclareExposure(ctx, caller, in.ID, e)
	if err != nil {
		return nil, err
	}
	return &body[assetResponse]{Body: newAssetResponse(stored)}, nil
}

func (h assetHandler) clearExposure(ctx context.Context, caller tenancy.User, in *assetIDInput) (*body[assetResponse], error) {
	stored, err := h.assets.ClearExposure(ctx, caller, in.ID)
	if err != nil {
		return nil, err
	}
	return &body[assetResponse]{Body: newAssetResponse(stored)}, nil
}

func ptr[T any](v T) *T { return &v }

func code(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
