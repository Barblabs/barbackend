package postgres

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"barbackend/internal/inventory"
	"barbackend/internal/postgres/sqlcgen"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

var (
	ErrNotFound       = errors.New("not found")
	ErrSuperseded     = errors.New("superseded by a later successful sync")
	ErrSyncInProgress = errors.New("another sync of the cmdb source is running")
)

// lockNotAvailable is the SQLSTATE of a NOWAIT lock that is already held.
const lockNotAvailable = "55P03"

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
	// The advisory lock keeps two processes migrating at once from both applying a migration.
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return fmt.Errorf("create migration lock: %w", err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, dir, goose.WithSessionLocker(locker))
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
		return fn(&Tx{q: sqlcgen.New(tx)})
	})
}

// InLockedSource runs fn in one transaction holding a row lock on the CMDB
// Source, so two Syncs of one source never write at the same time: while the
// lock is held, it fails at once with ErrSyncInProgress. A Sync
// started before the source's latest successful one holds an older snapshot,
// so it fails with ErrSuperseded instead of overwriting newer imported values.
func (db *DB) InLockedSource(ctx context.Context, id inventory.CMDBSourceID, startedAt time.Time, fn func(*SourceTx) error) error {
	return pgx.BeginFunc(ctx, db.pool, func(tx pgx.Tx) error {
		q := sqlcgen.New(tx)
		_, err := q.LockCMDBSource(ctx, uuid.UUID(id))
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("cmdb source %s: %w", id, ErrNotFound)
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == lockNotAvailable {
			return fmt.Errorf("cmdb source %s: %w", id, ErrSyncInProgress)
		}
		if err != nil {
			return fmt.Errorf("lock cmdb source %s: %w", id, err)
		}
		superseded, err := q.SucceededRunStartedAfter(ctx, sqlcgen.SucceededRunStartedAfterParams{
			CmdbSourceID: uuid.UUID(id),
			OutcomeID:    int16(inventory.SyncSucceeded),
			StartedAt:    startedAt,
		})
		if err != nil {
			return fmt.Errorf("check later syncs of %s: %w", id, err)
		}
		if superseded {
			return fmt.Errorf("sync of %s started at %v: %w", id, startedAt, ErrSuperseded)
		}
		return fn(&SourceTx{q: q, source: id})
	})
}

type Tx struct {
	q *sqlcgen.Queries
}
