package postgres

import (
	"context"

	"barbackend/internal/finding"
	"barbackend/internal/matching"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OpenTraced is Open with every query reported to trace.
func OpenTraced(ctx context.Context, url string, trace func(sql string)) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	cfg.ConnConfig.Tracer = queryTracer(trace)
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &DB{pool: pool}, nil
}

type queryTracer func(sql string)

func (f queryTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	f(data.SQL)
	return ctx
}

func (queryTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// MatchFlags is the Match Flags of the Finding's current match, in catalog
// order; none means a certain match.
func (db *DB) MatchFlags(ctx context.Context, id finding.ID) ([]matching.Flag, error) {
	rows, err := db.pool.Query(ctx, "SELECT flag_id FROM finding_match_flags WHERE finding_id = $1 ORDER BY flag_id", uuid.UUID(id))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[matching.Flag])
}

func (db *DB) CreateCustomer(ctx context.Context, id tenancy.CustomerID) error {
	_, err := db.pool.Exec(ctx, "INSERT INTO customers (id, name) VALUES ($1, $2)", uuid.UUID(id), id.String())
	return err
}
