package assets_test

import (
	"context"
	"errors"
	"testing"

	"barbackend/internal/assets"
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

func TestListRejectsALimitOutOfRange(t *testing.T) {
	svc := assets.New(nil)
	customer := tenancy.CustomerID(uuid.New())
	for _, limit := range []int{-1, assets.MaxLimit + 1} {
		if _, err := svc.List(context.Background(), customer, assets.Query{Limit: limit}); !errors.Is(err, assets.ErrInvalidQuery) {
			t.Errorf("limit %d: err = %v, want ErrInvalidQuery", limit, err)
		}
	}
}
