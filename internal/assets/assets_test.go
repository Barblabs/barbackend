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
	svc := assets.New(nil, nil)
	viewer, err := tenancy.NewUser(tenancy.UserID(uuid.New()), "viewer@example.com", tenancy.Viewer, tenancy.CustomerID(uuid.New()))
	if err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{-1, assets.MaxLimit + 1} {
		if _, err := svc.List(context.Background(), viewer, assets.Query{Limit: limit}); !errors.Is(err, assets.ErrInvalidQuery) {
			t.Errorf("limit %d: err = %v, want ErrInvalidQuery", limit, err)
		}
	}
}
