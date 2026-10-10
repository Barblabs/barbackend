package postgres

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"

	"barbackend/internal/postgres/sqlcgen"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

var ErrNotFound = errors.New("not found")

//go:embed migrations/*.sql
var migrations embed.FS

type DB struct {
	pool *pgxpool.Pool
}

func Open(ctx context.Context, url string) (*DB, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return &DB{pool: pool}, nil
}

func (db *DB) Close() { db.pool.Close() }

func (db *DB) Migrate(ctx context.Context) error {
	dir, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return fmt.Errorf("load migrations: %w", err)
	}
	sqlDB := stdlib.OpenDBFromPool(db.pool)
	defer func() { _ = sqlDB.Close() }()
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, dir)
	if err != nil {
		return fmt.Errorf("load migrations: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}

// InTx runs fn in one transaction, committed only if fn returns nil.
func (db *DB) InTx(ctx context.Context, fn func(*Tx) error) error {
	return pgx.BeginFunc(ctx, db.pool, func(tx pgx.Tx) error {
		return fn(&Tx{tx: tx, q: sqlcgen.New(tx)})
	})
}

type Tx struct {
	tx pgx.Tx
	q  *sqlcgen.Queries
}
