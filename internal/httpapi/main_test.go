package httpapi_test

import (
	"testing"

	"barbackend/internal/postgres/pgtest"
	"github.com/gin-gonic/gin"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	pgtest.Main(m)
}
