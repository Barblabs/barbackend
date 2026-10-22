// Package httpapi is the HTTP transport: it routes requests to use cases
// (ADR 0008).
package httpapi

import (
	"net/http"

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
}

func New(cfg Config) http.Handler {
	router := gin.Default()
	router.Use(cors(cfg.AllowedOrigins))
	router.GET("/ping", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"message": "pong"})
	})
	h := cmdbSourceHandler{sources: cfg.Sources, customer: cfg.Customer}
	router.GET("/cmdb/source", h.get)
	router.POST("/cmdb/source/test", h.test)
	return router
}

func badRequest(ctx *gin.Context, err error) {
	ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
}

// internalError hides the cause from the client; gin's logger prints it.
func internalError(ctx *gin.Context, err error) {
	_ = ctx.Error(err)
	ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
}
