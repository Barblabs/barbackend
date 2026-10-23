package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"barbackend/internal/inventory"
	"barbackend/internal/sources"
	"github.com/gin-gonic/gin"
)

type cmdbSourceHandler struct {
	sources     *sources.Service
	customer    inventory.CustomerID
	lifetime    context.Context
	syncTimeout time.Duration
}

// cmdbSourceResponse never carries credentials: a password sent to the
// dashboard could leak from it.
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

// get answers null rather than 404 when nothing is connected, because that
// is a normal state the dashboard shows the connect flow for.
func (h cmdbSourceHandler) get(ctx *gin.Context) {
	src, err := h.sources.ConnectedSource(ctx, h.customer)
	if errors.Is(err, sources.ErrNotConnected) {
		ctx.JSON(http.StatusOK, nil)
		return
	}
	if err != nil {
		writeError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, newCMDBSourceResponse(src))
}

// loginRequest is the login PUT /cmdb/source takes: it keeps the connected
// source's provider. connectRequest adds the provider for a new source.
type loginRequest struct {
	URL      string `json:"url" binding:"required"`
	User     string `json:"user" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func (r loginRequest) login() sources.Login {
	return sources.Login{URL: r.URL, User: r.User, Password: r.Password}
}

type connectRequest struct {
	Provider string `json:"provider" binding:"required"`
	loginRequest
}

// testResponse carries a failed check with 200, because a CMDB rejecting a
// login is a normal result the dashboard shows inline. Code is stable for
// translation; Error is shown for codes the dashboard does not know.
type testResponse struct {
	OK    bool   `json:"ok"`
	Code  string `json:"code,omitempty"`
	Error string `json:"error,omitempty"`
}

func (h cmdbSourceHandler) test(ctx *gin.Context) {
	var req connectRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		badRequest(ctx, err)
		return
	}
	err := h.sources.TestLogin(ctx.Request.Context(), inventory.CMDBProvider(req.Provider), req.login())
	var failure *sources.Failure
	switch {
	case err == nil:
		ctx.JSON(http.StatusOK, testResponse{OK: true})
	case errors.As(err, &failure):
		ctx.JSON(http.StatusOK, testResponse{Code: string(failure.Code), Error: failure.Message})
	default:
		writeError(ctx, err)
	}
}

// connect runs under the Sync context, not its request, so the first Sync
// is bounded and outlives a closed tab as a manual Sync does.
func (h cmdbSourceHandler) connect(ctx *gin.Context) {
	var req connectRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		badRequest(ctx, err)
		return
	}
	syncCtx, cancel := context.WithTimeout(h.lifetime, h.syncTimeout)
	defer cancel()
	src, err := h.sources.Connect(syncCtx, h.customer, inventory.CMDBProvider(req.Provider), req.login())
	if err != nil {
		writeError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, newCMDBSourceResponse(src))
}

func (h cmdbSourceHandler) update(ctx *gin.Context) {
	var req loginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		badRequest(ctx, err)
		return
	}
	src, err := h.sources.UpdateLogin(ctx.Request.Context(), h.customer, req.login())
	if err != nil {
		writeError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, newCMDBSourceResponse(src))
}

func (h cmdbSourceHandler) disconnect(ctx *gin.Context) {
	if err := h.sources.Disconnect(ctx.Request.Context(), h.customer); err != nil {
		writeError(ctx, err)
		return
	}
	ctx.Status(http.StatusNoContent)
}

func newCMDBSourceResponse(src sources.ConnectedSource) cmdbSourceResponse {
	resp := cmdbSourceResponse{Provider: string(src.Provider), URL: src.URL}
	if src.User != "" {
		resp.User = &src.User
	}
	if !src.LastSync.IsZero() {
		resp.LastSync = &src.LastSync
	}
	if f := src.LastSyncFailure; f != nil {
		resp.LastSyncFailure = &syncFailureResponse{At: f.At, Error: f.Error}
	}
	return resp
}

// syncResponse is the Sync Run of a successful Sync. LastSync is when it
// finished, as GET /cmdb/source then reports it.
type syncResponse struct {
	LastSync    time.Time `json:"lastSync"`
	Created     int       `json:"created"`
	Updated     int       `json:"updated"`
	Deactivated int       `json:"deactivated"`
	Reactivated int       `json:"reactivated"`
	Skipped     int       `json:"skipped"`
}

func (h cmdbSourceHandler) sync(ctx *gin.Context) {
	syncCtx, cancel := context.WithTimeout(h.lifetime, h.syncTimeout)
	defer cancel()
	run, err := h.sources.SyncConnected(syncCtx, h.customer)
	var failed *sources.SyncError
	switch {
	case err == nil:
		ctx.JSON(http.StatusOK, newSyncResponse(run))
	case errors.As(err, &failed):
		_ = ctx.Error(err)
		ctx.JSON(http.StatusBadGateway, codedError{Code: failureCode(failed), Error: failed.Error()})
	default:
		writeError(ctx, err)
	}
}

func failureCode(err *sources.SyncError) string {
	var failure *sources.Failure
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
