package agents_test

import (
	"os"
	"testing"

	"barbackend/internal/postgres/pgtest"
)

func TestMain(m *testing.M) {
	// claudetest checks no key; the SDK refuses to send a request without one.
	_ = os.Setenv("ANTHROPIC_API_KEY", "test-key")
	pgtest.Main(m)
}
