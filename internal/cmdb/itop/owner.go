package itop

import (
	"net/mail"
	"strings"

	"barbackend/internal/inventory"
)

func owner(c ci, lk lookups) inventory.OwnerEmail {
	personID, ok := onlyPerson(c.Contacts)
	if !ok {
		return inventory.OwnerEmail{}
	}
	address := lk.persons[personID].Email
	if !validEmail(address) {
		return inventory.OwnerEmail{}
	}
	email, err := inventory.NewOwnerEmail(address)
	if err != nil {
		return inventory.OwnerEmail{}
	}
	return email
}

func onlyPerson(contacts []contact) (string, bool) {
	persons := map[string]bool{}
	var id string
	for _, ct := range contacts {
		if ct.Class == "Person" {
			persons[ct.ID] = true
			id = ct.ID
		}
	}
	return id, len(persons) == 1
}

// validEmail accepts a bare address only: ParseAddress also takes a display
// name or angle brackets, which an email field should not hold.
func validEmail(s string) bool {
	addr, err := mail.ParseAddress(s)
	return err == nil && addr.Address == strings.TrimSpace(s)
}
