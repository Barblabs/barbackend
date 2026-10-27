package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"barbackend/internal/cmdb"
	"barbackend/internal/inventory"
	"github.com/danielgtaylor/huma/v2"
)

type cmdbSourceHandler struct {
	cmdb     *cmdb.Service
	customer inventory.CustomerID
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

type cmdbSourceOutput struct {
	// Body is null when the Customer has no Connected CMDB Source.
	Body *cmdbSourceResponse
}

type cmdbSourceResponse struct {
	Provider string `json:"provider"`
	URL      string `json:"url"`
	// User is null for a source that authenticates without one, such as
	// with a token.
	User            *string              `json:"user"`
	LastSync        *time.Time           `json:"lastSync"`
	LastSyncFailure *syncFailureResponse `json:"lastSyncFailure"`
}

type syncFailureResponse struct {
	At    time.Time `json:"at"`
	Error string    `json:"error"`
}

func (h cmdbSourceHandler) get(ctx context.Context, _ *struct{}) (*cmdbSourceOutput, error) {
	src, err := h.cmdb.ConnectedSource(ctx, h.customer)
	if errors.Is(err, cmdb.ErrNotConnected) {
		return &cmdbSourceOutput{}, nil
	}
	if err != nil {
		return nil, apiError(err)
	}
	return newCMDBSourceOutput(src), nil
}

// The login requests keep rejecting an empty field as missing, as they did
// before Huma, and tolerate unknown fields. connectRequest repeats the login
// fields because Huma leaves unexported embedded structs out of the schema.
type loginRequest struct {
	_        struct{} `additionalProperties:"true"`
	URL      string   `json:"url" minLength:"1"`
	User     string   `json:"user" minLength:"1"`
	Password string   `json:"password" minLength:"1"`
}

func (r loginRequest) login() cmdb.Login {
	return cmdb.Login{URL: r.URL, User: r.User, Password: r.Password}
}

type connectRequest struct {
	_        struct{} `additionalProperties:"true"`
	Provider string   `json:"provider" minLength:"1"`
	URL      string   `json:"url" minLength:"1"`
	User     string   `json:"user" minLength:"1"`
	Password string   `json:"password" minLength:"1"`
}

func (r connectRequest) login() cmdb.Login {
	return cmdb.Login{URL: r.URL, User: r.User, Password: r.Password}
}

type connectInput struct {
	Body connectRequest
}

type loginInput struct {
	Body loginRequest
}

type testOutput struct {
	Body testResponse
}

type testResponse struct {
	OK    bool   `json:"ok"`
	Code  string `json:"code,omitempty"`
	Error string `json:"error,omitempty"`
}

func (h cmdbSourceHandler) test(ctx context.Context, in *connectInput) (*testOutput, error) {
	err := h.cmdb.TestLogin(ctx, inventory.CMDBProvider(in.Body.Provider), in.Body.login())
	var failure *cmdb.Failure
	switch {
	case err == nil:
		return &testOutput{Body: testResponse{OK: true}}, nil
	case errors.As(err, &failure):
		return &testOutput{Body: testResponse{Code: string(failure.Code), Error: failure.Message}}, nil
	default:
		return nil, apiError(err)
	}
}

func (h cmdbSourceHandler) connect(ctx context.Context, in *connectInput) (*cmdbSourceOutput, error) {
	src, err := h.cmdb.Connect(ctx, h.customer, inventory.CMDBProvider(in.Body.Provider), in.Body.login())
	if err != nil {
		return nil, apiError(err)
	}
	return newCMDBSourceOutput(src), nil
}

func (h cmdbSourceHandler) update(ctx context.Context, in *loginInput) (*cmdbSourceOutput, error) {
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

func newCMDBSourceOutput(src cmdb.ConnectedSource) *cmdbSourceOutput {
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
	return &cmdbSourceOutput{Body: resp}
}

type syncOutput struct {
	Body syncResponse
}

type syncResponse struct {
	LastSync    time.Time `json:"lastSync"`
	Created     int       `json:"created"`
	Updated     int       `json:"updated"`
	Deactivated int       `json:"deactivated"`
	Reactivated int       `json:"reactivated"`
	Skipped     int       `json:"skipped"`
}

func (h cmdbSourceHandler) sync(ctx context.Context, _ *struct{}) (*syncOutput, error) {
	run, err := h.cmdb.SyncConnected(ctx, h.customer)
	var failed *cmdb.SyncError
	switch {
	case err == nil:
		return &syncOutput{Body: newSyncResponse(run)}, nil
	case errors.As(err, &failed):
		return nil, &codedError{status: http.StatusBadGateway, cause: err, Code: failureCode(failed), Message: failed.Error()}
	default:
		return nil, apiError(err)
	}
}

func failureCode(err *cmdb.SyncError) string {
	var failure *cmdb.Failure
	if errors.As(err, &failure) {
		return string(failure.Code)
	}
	return syncFailed
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
