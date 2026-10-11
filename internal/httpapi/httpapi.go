// Package httpapi is the HTTP transport: it routes requests to use cases
// (ADR 0008).
package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func New() http.Handler {
	router := gin.Default()
	router.GET("/ping", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"message": "pong"})
	})
	return router
}
