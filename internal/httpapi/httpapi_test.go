package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"barbackend/internal/httpapi"
	"github.com/gin-gonic/gin"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	m.Run()
}

func TestPing(t *testing.T) {
	rec := httptest.NewRecorder()

	httpapi.New().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ping", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got, want := rec.Body.String(), `{"message":"pong"}`; got != want {
		t.Errorf("body = %s, want %s", got, want)
	}
}
