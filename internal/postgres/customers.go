package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"barbackend/internal/postgres/sqlcgen"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const customerNameIndex = "customers_name_key"

var (
	ErrCustomerNotFound = errors.New("customer not found")
	// ErrCustomerNameTaken is a name another Customer has, regardless of case.
	ErrCustomerNameTaken = errors.New("another customer has this name")
)

// StoredCustomer is a Customer with what only the database records about it.
type StoredCustomer struct {
	Customer tenancy.Customer
	Created  time.Time
	// Deactivated is when the Customer was deactivated, zero while it is not.
	Deactivated time.Time
}

func (t *Tx) CreateCustomer(ctx context.Context, c tenancy.Customer) (StoredCustomer, error) {
	created, err := t.q.InsertCustomer(ctx, sqlcgen.InsertCustomerParams{ID: uuid.UUID(c.ID()), Name: c.Name()})
	if err != nil {
		return StoredCustomer{}, customerError("insert", c.ID(), err)
	}
	return StoredCustomer{Customer: c, Created: created}, nil
}

func (t *Tx) Customer(ctx context.Context, id tenancy.CustomerID) (StoredCustomer, error) {
	row, err := t.q.GetCustomer(ctx, uuid.UUID(id))
	if err != nil {
		return StoredCustomer{}, customerError("get", id, err)
	}
	return restoreCustomer(row)
}

// Customers are ordered by name, regardless of case.
func (t *Tx) Customers(ctx context.Context) ([]StoredCustomer, error) {
	rows, err := t.q.ListCustomers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list customers: %w", err)
	}
	customers := make([]StoredCustomer, 0, len(rows))
	for _, row := range rows {
		c, err := restoreCustomer(row)
		if err != nil {
			return nil, err
		}
		customers = append(customers, c)
	}
	return customers, nil
}

// RenameCustomer stores the name of c on the Customer with its id.
func (t *Tx) RenameCustomer(ctx context.Context, c tenancy.Customer) (StoredCustomer, error) {
	row, err := t.q.RenameCustomer(ctx, sqlcgen.RenameCustomerParams{ID: uuid.UUID(c.ID()), Name: c.Name()})
	if err != nil {
		return StoredCustomer{}, customerError("rename", c.ID(), err)
	}
	return restoreCustomer(row)
}

// DeactivateCustomer keeps the time of the first deactivation when the
// Customer is already deactivated.
func (t *Tx) DeactivateCustomer(ctx context.Context, id tenancy.CustomerID) (StoredCustomer, error) {
	row, err := t.q.DeactivateCustomer(ctx, uuid.UUID(id))
	if err != nil {
		return StoredCustomer{}, customerError("deactivate", id, err)
	}
	return restoreCustomer(row)
}

func (t *Tx) ReactivateCustomer(ctx context.Context, id tenancy.CustomerID) (StoredCustomer, error) {
	row, err := t.q.ReactivateCustomer(ctx, uuid.UUID(id))
	if err != nil {
		return StoredCustomer{}, customerError("reactivate", id, err)
	}
	return restoreCustomer(row)
}

func customerError(action string, id tenancy.CustomerID, err error) error {
	var pgErr *pgconn.PgError
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return fmt.Errorf("%s customer %s: %w", action, id, ErrCustomerNotFound)
	case errors.As(err, &pgErr) && pgErr.Code == uniqueViolation && pgErr.ConstraintName == customerNameIndex:
		return fmt.Errorf("%s customer %s: %w", action, id, ErrCustomerNameTaken)
	default:
		return fmt.Errorf("%s customer %s: %w", action, id, err)
	}
}

func restoreCustomer(row sqlcgen.Customer) (StoredCustomer, error) {
	c, err := tenancy.NewCustomer(tenancy.CustomerID(row.ID), row.Name)
	if err != nil {
		return StoredCustomer{}, fmt.Errorf("restore customer %s: %w", row.ID, err)
	}
	stored := StoredCustomer{Customer: c, Created: row.CreatedAt}
	if row.DeactivatedAt != nil {
		stored.Deactivated = *row.DeactivatedAt
	}
	return stored, nil
}
