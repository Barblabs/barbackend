// Package httpapi is the HTTP transport: it routes requests to use cases
// (ADR 0008).
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

type Config struct {
	Sources *sources.Service
	// Customer is who every request acts for. It comes from server
	// configuration until authentication exists.
	Customer inventory.CustomerID
	// AllowedOrigins may call the API from a browser.
	AllowedOrigins []string
	// Lifetime ends when the server shuts down. Syncs run under it instead of
	// their request, so a client that disconnects does not fail its Sync.
	Lifetime context.Context
	// SyncTimeout bounds each Sync started over HTTP.
	SyncTimeout time.Duration
}

func New(cfg Config) http.Handler {
	router := gin.Default()
	router.Use(cors(cfg.AllowedOrigins))
	router.GET("/ping", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"message": "pong"})
	})
	h := cmdbSourceHandler{sources: cfg.Sources, customer: cfg.Customer, lifetime: cfg.Lifetime, syncTimeout: cfg.SyncTimeout}
	router.GET("/cmdb/source", h.get)
	router.POST("/cmdb/source", h.connect)
	router.PUT("/cmdb/source", h.update)
	router.DELETE("/cmdb/source", h.disconnect)
	router.POST("/cmdb/source/test", h.test)
	router.POST("/cmdb/source/sync", h.sync)
	return router
}

// codedError is every error body: Code is stable for translation, and Error
// is shown for codes the dashboard does not know.
type codedError struct {
	Code  string `json:"code"`
	Error string `json:"error"`
}

const (
	invalidRequest   = "invalid_request"
	invalidLogin     = "invalid_login"
	notConnected     = "not_connected"
	alreadyConnected = "already_connected"
	syncInProgress   = "sync_in_progress"
	syncFailed       = "sync_failed"
	internalError    = "internal_error"
)

func writeError(ctx *gin.Context, err error) {
	var failure *sources.Failure
	switch {
	case errors.As(err, &failure):
		ctx.JSON(http.StatusUnprocessableEntity, codedError{Code: string(failure.Code), Error: failure.Message})
	case errors.Is(err, sources.ErrInvalidLogin):
		ctx.JSON(http.StatusBadRequest, codedError{Code: invalidLogin, Error: err.Error()})
	case errors.Is(err, sources.ErrNotConnected), errors.Is(err, sources.ErrDisconnected):
		ctx.JSON(http.StatusNotFound, codedError{Code: notConnected, Error: err.Error()})
	case errors.Is(err, sources.ErrAlreadyConnected):
		ctx.JSON(http.StatusConflict, codedError{Code: alreadyConnected, Error: err.Error()})
	case errors.Is(err, sources.ErrSyncInProgress):
		ctx.JSON(http.StatusConflict, codedError{Code: syncInProgress, Error: err.Error()})
	default:
		_ = ctx.Error(err)
		ctx.JSON(http.StatusInternalServerError, codedError{Code: internalError, Error: "internal server error"})
	}
}

func badRequest(ctx *gin.Context, err error) {
	ctx.JSON(http.StatusBadRequest, codedError{Code: invalidRequest, Error: err.Error()})
}
