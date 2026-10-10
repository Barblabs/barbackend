package itop

import (
	"net/mail"
	"strings"

	"barbackend/internal/inventory"
)

// owner is the CI's only Person contact (ADR 0003). Persons are counted
// before any email is checked, so a CI with two Persons has no owner even
// when one of them has an invalid email: the valid one is not more likely to
// be the owner.
func owner(c ci, lk lookups) inventory.OwnerEmail {
	persons := map[string]bool{}
	var only string
	for _, ct := range c.contacts {
		if ct.class == "Person" {
			persons[ct.id] = true
			only = ct.id
		}
	}
	if len(persons) != 1 || !validEmail(lk.emails[only]) {
		return inventory.OwnerEmail{}
	}
	email, err := inventory.NewOwnerEmail(lk.emails[only])
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
