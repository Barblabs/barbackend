// Package pgtest gives tests a real, isolated Postgres database: each test
// gets its own copy of a migrated template, so tests need no cleanup and can
// run in parallel.
package pgtest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"barbackend/internal/postgres"
	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5"
)

const template = "barb_template"

var (
	port uint32
	// Serializes CREATE DATABASE: concurrent copies of one template can fail.
	createMu sync.Mutex
)

// Main starts a throwaway Postgres for the package's tests. Call it from TestMain.
func Main(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	dir, err := os.MkdirTemp("", "pgtest")
	if err != nil {
		fmt.Fprintln(os.Stderr, "pgtest:", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(dir) }()

	port, err = freePort()
	if err != nil {
		fmt.Fprintln(os.Stderr, "pgtest:", err)
		return 1
	}
	var log bytes.Buffer
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V17).
		Port(port).
		RuntimePath(filepath.Join(dir, "runtime")).
		Logger(&log))
	if err := pg.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "pgtest: start postgres: %v\n%s", err, log.String())
		return 1
	}
	defer func() { _ = pg.Stop() }()

	if err := createTemplate(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "pgtest:", err)
		return 1
	}
	return m.Run()
}

func createTemplate(ctx context.Context) error {
	if err := exec(ctx, "CREATE DATABASE "+template); err != nil {
		return err
	}
	db, err := postgres.Open(ctx, url(template))
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Migrate(ctx)
}

// URL creates a fresh migrated database for the test and returns its connection URL.
func URL(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	name := "t_" + randomHex()

	createMu.Lock()
	err := exec(ctx, fmt.Sprintf("CREATE DATABASE %s TEMPLATE %s", name, template))
	createMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := exec(ctx, fmt.Sprintf("DROP DATABASE %s WITH (FORCE)", name)); err != nil {
			t.Error(err)
		}
	})
	return url(name)
}

// NewDB opens a fresh migrated database for the test.
func NewDB(t *testing.T) *postgres.DB {
	t.Helper()
	db, err := postgres.Open(context.Background(), URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db
}

// Conn opens a raw connection to url, for asserting on rows a store does not expose.
func Conn(t *testing.T, url string) *pgx.Conn {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })
	return conn
}

func exec(ctx context.Context, sql string) error {
	conn, err := pgx.Connect(ctx, url("postgres"))
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, sql); err != nil {
		return fmt.Errorf("%s: %w", sql, err)
	}
	return nil
}

func url(database string) string {
	return fmt.Sprintf("postgres://postgres:postgres@localhost:%d/%s?sslmode=disable", port, database)
}

func freePort() (uint32, error) {
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return 0, fmt.Errorf("find free port: %w", err)
	}
	defer func() { _ = l.Close() }()
	return uint32(l.Addr().(*net.TCPAddr).Port), nil
}

func randomHex() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
