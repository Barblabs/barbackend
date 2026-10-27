package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"barbackend/internal/cmdb"
	"barbackend/internal/inventory"
	"barbackend/internal/tenancy"
	"github.com/danielgtaylor/huma/v2"
)

type cmdbSourceHandler struct {
	cmdb     *cmdb.Service
	customer tenancy.CustomerID
}

func (h cmdbSourceHandler) register(api huma.API) {
	register(api, huma.Operation{
		OperationID: "get-cmdb-source",
		Method:      http.MethodGet,
		Path:        "/cmdb/source",
		Summary:     "Get the Connected CMDB Source",
		Description: "Returns null when the Customer has no Connected CMDB Source.",
		Responses:   nullableBody[cmdbSourceResponse](api),
		Errors:      []int{http.StatusInternalServerError},
	}, h.get)
	register(api, huma.Operation{
		OperationID: "connect-cmdb-source",
		Method:      http.MethodPost,
		Path:        "/cmdb/source",
		Summary:     "Connect a CMDB Source and run its first Sync",
		Description: "A failed first Sync is reported in lastSyncFailure and leaves the CMDB Source connected.",
		Errors:      []int{http.StatusBadRequest, http.StatusConflict, http.StatusUnprocessableEntity},
	}, h.connect)
	register(api, huma.Operation{
		OperationID: "update-cmdb-source",
		Method:      http.MethodPut,
		Path:        "/cmdb/source",
		Summary:     "Replace the login of the Connected CMDB Source",
		Errors:      []int{http.StatusBadRequest, http.StatusNotFound, http.StatusUnprocessableEntity},
	}, h.update)
	register(api, huma.Operation{
		OperationID: "disconnect-cmdb-source",
		Method:      http.MethodDelete,
		Path:        "/cmdb/source",
		Summary:     "Disconnect the Connected CMDB Source",
		Errors:      []int{http.StatusNotFound},
	}, h.disconnect)
	register(api, huma.Operation{
		OperationID: "test-cmdb-source",
		Method:      http.MethodPost,
		Path:        "/cmdb/source/test",
		Summary:     "Check a CMDB Source login without storing it",
		Description: "A login the CMDB rejects is a 200 with ok false and the reason.",
		Errors:      []int{http.StatusBadRequest},
	}, h.test)
	register(api, huma.Operation{
		OperationID: "sync-cmdb-source",
		Method:      http.MethodPost,
		Path:        "/cmdb/source/sync",
		Summary:     "Sync the Connected CMDB Source",
		Errors:      []int{http.StatusNotFound, http.StatusConflict, http.StatusBadGateway},
	}, h.sync)
}

type cmdbSourceResponse struct {
	Provider        string               `json:"provider"`
	URL             string               `json:"url"`
	User            *string              `json:"user" doc:"Null for a source that authenticates without a user, such as with a token"`
	LastSync        *time.Time           `json:"lastSync"`
	LastSyncFailure *syncFailureResponse `json:"lastSyncFailure"`
}

type syncFailureResponse struct {
	At    time.Time `json:"at"`
	Error string    `json:"error"`
}

func (h cmdbSourceHandler) get(ctx context.Context, _ *struct{}) (*body[*cmdbSourceResponse], error) {
	src, err := h.cmdb.ConnectedSource(ctx, h.customer)
	if errors.Is(err, cmdb.ErrNotConnected) {
		return &body[*cmdbSourceResponse]{}, nil
	}
	if err != nil {
		return nil, apiError(err)
	}
	return newCMDBSourceOutput(src), nil
}

// LoginRequest is exported because Huma leaves unexported embedded structs
// out of connectRequest's schema.
type LoginRequest struct {
	_        struct{} `additionalProperties:"true"`
	URL      string   `json:"url" minLength:"1"`
	User     string   `json:"user" minLength:"1"`
	Password string   `json:"password" minLength:"1"`
}

func (r LoginRequest) login() cmdb.Login {
	return cmdb.Login{URL: r.URL, User: r.User, Password: r.Password}
}

type connectRequest struct {
	_        struct{} `additionalProperties:"true"`
	Provider string   `json:"provider" minLength:"1"`
	LoginRequest
}

type testResponse struct {
	OK    bool   `json:"ok"`
	Code  string `json:"code,omitempty"`
	Error string `json:"error,omitempty"`
}

func (h cmdbSourceHandler) test(ctx context.Context, in *body[connectRequest]) (*body[testResponse], error) {
	err := h.cmdb.TestLogin(ctx, inventory.CMDBProvider(in.Body.Provider), in.Body.login())
	var failure *cmdb.Failure
	switch {
	case err == nil:
		return &body[testResponse]{Body: testResponse{OK: true}}, nil
	case errors.As(err, &failure):
		return &body[testResponse]{Body: testResponse{Code: string(failure.Code), Error: failure.Message}}, nil
	default:
		return nil, apiError(err)
	}
}

func (h cmdbSourceHandler) connect(ctx context.Context, in *body[connectRequest]) (*body[*cmdbSourceResponse], error) {
	src, err := h.cmdb.Connect(ctx, h.customer, inventory.CMDBProvider(in.Body.Provider), in.Body.login())
	if err != nil {
		return nil, apiError(err)
	}
	return newCMDBSourceOutput(src), nil
}

func (h cmdbSourceHandler) update(ctx context.Context, in *body[LoginRequest]) (*body[*cmdbSourceResponse], error) {
	src, err := h.cmdb.UpdateLogin(ctx, h.customer, in.Body.login())
	if err != nil {
		return nil, apiError(err)
	}
	return newCMDBSourceOutput(src), nil
}

func (h cmdbSourceHandler) disconnect(ctx context.Context, _ *struct{}) (*struct{}, error) {
	if err := h.cmdb.Disconnect(ctx, h.customer); err != nil {
		return nil, apiError(err)
	}
	return &struct{}{}, nil
}

func newCMDBSourceOutput(src cmdb.ConnectedSource) *body[*cmdbSourceResponse] {
	resp := &cmdbSourceResponse{Provider: string(src.Provider), URL: src.URL}
	if src.User != "" {
		resp.User = &src.User
	}
	if !src.LastSync.IsZero() {
		resp.LastSync = &src.LastSync
	}
	if f := src.LastSyncFailure; f != nil {
		resp.LastSyncFailure = &syncFailureResponse{At: f.At, Error: f.Error}
	}
	return &body[*cmdbSourceResponse]{Body: resp}
}

type syncResponse struct {
	LastSync    time.Time `json:"lastSync"`
	Created     int       `json:"created"`
	Updated     int       `json:"updated"`
	Deactivated int       `json:"deactivated"`
	Reactivated int       `json:"reactivated"`
	Skipped     int       `json:"skipped"`
}

func (h cmdbSourceHandler) sync(ctx context.Context, _ *struct{}) (*body[syncResponse], error) {
	run, err := h.cmdb.SyncConnected(ctx, h.customer)
	if err != nil {
		return nil, apiError(err)
	}
	return &body[syncResponse]{Body: newSyncResponse(run)}, nil
}

func newSyncResponse(run inventory.SyncRun) syncResponse {
	c := run.Counts()
	return syncResponse{
		LastSync:    run.Finished(),
		Created:     c.Created,
		Updated:     c.Updated,
		Deactivated: c.Deactivated,
		Reactivated: c.Reactivated,
		Skipped:     c.Skipped,
	}
}
