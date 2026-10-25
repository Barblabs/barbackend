package httpapi

import (
	"errors"
	"net/http"
	"time"

	"barbackend/internal/inventory"
	"barbackend/internal/sources"
	"github.com/gin-gonic/gin"
)

type cmdbSourceHandler struct {
	sources  *sources.Service
	customer inventory.CustomerID
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

func (h cmdbSourceHandler) connect(ctx *gin.Context) {
	var req connectRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		badRequest(ctx, err)
		return
	}
	src, err := h.sources.Connect(ctx.Request.Context(), h.customer, inventory.CMDBProvider(req.Provider), req.login())
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

type syncResponse struct {
	LastSync    time.Time `json:"lastSync"`
	Created     int       `json:"created"`
	Updated     int       `json:"updated"`
	Deactivated int       `json:"deactivated"`
	Reactivated int       `json:"reactivated"`
	Skipped     int       `json:"skipped"`
}

func (h cmdbSourceHandler) sync(ctx *gin.Context) {
	run, err := h.sources.SyncConnected(ctx.Request.Context(), h.customer)
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
