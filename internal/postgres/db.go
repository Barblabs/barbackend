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
	// ErrDisconnected is a Sync refused because its CMDB Source was
	// disconnected: its Assets stay as the disconnect left them.
	ErrDisconnected = errors.New("cmdb source is disconnected")
	// ErrAlreadyConnected is a Customer that already has a Connected CMDB Source.
	ErrAlreadyConnected = errors.New("customer already has a connected cmdb source")
	// ErrNotConnected is a Customer with no Connected CMDB Source.
	ErrNotConnected = errors.New("customer has no connected cmdb source")
)

const (
	lockNotAvailable = "55P03"
	uniqueViolation  = "23505"
)

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

// CommitSync is the transactional end of a Sync. It locks the CMDB Source,
// passes its stored Assets to reconcile, saves the Reconciliation and records
// its succeeded Sync Run, all in one transaction. reconcile runs while the
// lock is held, so it must do no I/O; its error rolls everything back.
//
// While another Sync holds the lock, CommitSync fails at once with
// ErrSyncInProgress. A Sync of a Disconnected CMDB Source fails with
// ErrDisconnected, even when the source was disconnected after the Sync read
// it, because the disconnect takes the same lock. A Sync started before the
// source's latest successful one holds an older snapshot, so it fails with
// ErrSuperseded instead of overwriting newer imported values. That check reads succeeded Sync Runs,
// which is why only CommitSync records them, together with their changes.
func (db *DB) CommitSync(ctx context.Context, id inventory.CMDBSourceID, started time.Time, reconcile func(existing []*inventory.Asset) (inventory.Reconciliation, error)) (inventory.SyncRun, error) {
	var run inventory.SyncRun
	err := pgx.BeginFunc(ctx, db.pool, func(tx pgx.Tx) error {
		q := sqlcgen.New(tx)
		if err := lockSource(ctx, q, id, started); err != nil {
			return err
		}
		st := &sourceTx{q: q, source: id}
		existing, err := st.assets(ctx)
		if err != nil {
			return err
		}
		r, err := reconcile(existing)
		if err != nil {
			return fmt.Errorf("reconcile %s: %w", id, err)
		}
		if err := st.save(ctx, r); err != nil {
			return err
		}
		// Postgres keeps microseconds; the returned run must match the stored one.
		run, err = inventory.SucceededRun(r, started, time.Now().Truncate(time.Microsecond))
		if err != nil {
			return err
		}
		return recordSyncRun(ctx, q, run)
	})
	if err != nil {
		return inventory.SyncRun{}, err
	}
	return run, nil
}

func lockSource(ctx context.Context, q *sqlcgen.Queries, id inventory.CMDBSourceID, started time.Time) error {
	connected, err := q.LockCMDBSource(ctx, uuid.UUID(id))
	if err != nil {
		return lockError(fmt.Sprintf("cmdb source %s", id), ErrNotFound, err)
	}
	if !connected {
		return fmt.Errorf("cmdb source %s: %w", id, ErrDisconnected)
	}
	superseded, err := q.SucceededRunStartedAfter(ctx, sqlcgen.SucceededRunStartedAfterParams{
		CmdbSourceID: uuid.UUID(id),
		OutcomeID:    int16(inventory.SyncSucceeded),
		StartedAt:    started,
	})
	if err != nil {
		return fmt.Errorf("check later syncs of %s: %w", id, err)
	}
	if superseded {
		return fmt.Errorf("sync of %s started at %v: %w", id, started, ErrSuperseded)
	}
	return nil
}

func lockError(source string, missing, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%s: %w", source, missing)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == lockNotAvailable {
		return fmt.Errorf("%s: %w", source, ErrSyncInProgress)
	}
	return fmt.Errorf("lock %s: %w", source, err)
}

type Tx struct {
	q *sqlcgen.Queries
}
