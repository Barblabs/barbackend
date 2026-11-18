// Package tenancytest builds the Users that tests act as.
package tenancytest

import (
	"barbackend/internal/tenancy"
	"github.com/google/uuid"
)

// Viewer returns a new Viewer of customer.
func Viewer(customer tenancy.CustomerID) tenancy.User {
	return user(customer, tenancy.Viewer)
}

// CustomerAdmin returns a new Customer Admin of customer.
func CustomerAdmin(customer tenancy.CustomerID) tenancy.User {
	return user(customer, tenancy.CustomerAdmin)
}

func user(customer tenancy.CustomerID, role tenancy.Role) tenancy.User {
	u, err := tenancy.NewUser(tenancy.UserID(uuid.New()), "user@example.com", role, customer)
	if err != nil {
		panic(err)
	}
	return u
}
