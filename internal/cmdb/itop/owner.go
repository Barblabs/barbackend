package itop

import (
	"net/mail"
	"strings"

	"barbackend/internal/inventory"
)

func owner(c ci, lk lookups) inventory.OwnerEmail {
	persons := map[string]bool{}
	var only string
	for _, ct := range c.Contacts {
		if ct.Class == "Person" {
			persons[ct.ID] = true
			only = ct.ID
		}
	}
	address := lk.persons[only].Email
	if len(persons) != 1 || !validEmail(address) {
		return inventory.OwnerEmail{}
	}
	email, err := inventory.NewOwnerEmail(address)
	if err != nil {
		return inventory.OwnerEmail{}
	}
	return email
}

// validEmail accepts a bare address only: ParseAddress also takes a display
// name or angle brackets, which an email field should not hold.
func validEmail(s string) bool {
	addr, err := mail.ParseAddress(s)
	return err == nil && addr.Address == strings.TrimSpace(s)
}
