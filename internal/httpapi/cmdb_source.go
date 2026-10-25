package httpapi

import (
	"errors"
	"net/http"
	"time"

	"barbackend/internal/cmdb"
	"barbackend/internal/inventory"
	"github.com/gin-gonic/gin"
)

type cmdbSourceHandler struct {
	cmdb     *cmdb.Service
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
	src, err := h.cmdb.ConnectedSource(ctx, h.customer)
	if errors.Is(err, cmdb.ErrNotConnected) {
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

func (r loginRequest) login() cmdb.Login {
	return cmdb.Login{URL: r.URL, User: r.User, Password: r.Password}
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
	err := h.cmdb.TestLogin(ctx.Request.Context(), inventory.CMDBProvider(req.Provider), req.login())
	var failure *cmdb.Failure
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
	src, err := h.cmdb.Connect(ctx.Request.Context(), h.customer, inventory.CMDBProvider(req.Provider), req.login())
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
	src, err := h.cmdb.UpdateLogin(ctx.Request.Context(), h.customer, req.login())
	if err != nil {
		writeError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, newCMDBSourceResponse(src))
}

func (h cmdbSourceHandler) disconnect(ctx *gin.Context) {
	if err := h.cmdb.Disconnect(ctx.Request.Context(), h.customer); err != nil {
		writeError(ctx, err)
		return
	}
	ctx.Status(http.StatusNoContent)
}

func newCMDBSourceResponse(src cmdb.ConnectedSource) cmdbSourceResponse {
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
	run, err := h.cmdb.SyncConnected(ctx.Request.Context(), h.customer)
	var failed *cmdb.SyncError
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
