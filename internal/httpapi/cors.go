package httpapi

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// corsMethods lists the methods the router serves. POST is a CORS-safelisted
// method, so a preflight need not list it.
var (
	corsMethods = strings.Join([]string{http.MethodGet, http.MethodPut, http.MethodDelete}, ", ")
	corsMaxAge  = strconv.Itoa(int((10 * time.Minute).Seconds()))
)

func cors(allowed []string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		origin := ctx.GetHeader("Origin")
		allow := origin != "" && slices.Contains(allowed, origin)
		ctx.Writer.Header().Add("Vary", "Origin")
		if allow {
			ctx.Header("Access-Control-Allow-Origin", origin)
		}
		if ctx.Request.Method != http.MethodOptions || ctx.GetHeader("Access-Control-Request-Method") == "" {
			ctx.Next()
			return
		}
		if !allow {
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}
		ctx.Header("Access-Control-Allow-Methods", corsMethods)
		ctx.Header("Access-Control-Allow-Headers", "Content-Type")
		ctx.Header("Access-Control-Max-Age", corsMaxAge)
		ctx.AbortWithStatus(http.StatusNoContent)
	}
}
