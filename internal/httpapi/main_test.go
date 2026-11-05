package httpapi_test

import (
	"os"
	"testing"

	"barbackend/internal/postgres/pgtest"
	"github.com/gin-gonic/gin"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	// claudetest checks no key; the SDK refuses to send a request without one.
	_ = os.Setenv("ANTHROPIC_API_KEY", "test-key")
	pgtest.Main(m)
}
