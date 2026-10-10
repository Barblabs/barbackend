package itop

import (
	"testing"

	"barbackend/internal/inventory"
)

func TestOwner(t *testing.T) {
	lk := lookups{emails: map[string]string{
		"1": "alice@it.com",
		"2": "bob@it.com",
		"3": "",
		"4": "Test.MixedCase@IT.com",
		"5": "not-an-email",
		"6": "Alice <alice@it.com>",
		"7": "alice@it.com, bob@it.com",
		"8": "alice@",
		"9": " alice@it.com ",
	}}
	person := func(id string) contact { return contact{id: id, class: "Person"} }
	team := contact{id: "50", class: "Team"}
	tests := []struct {
		name     string
		contacts []contact
		want     string
	}{
		{"one Person", []contact{person("1")}, "alice@it.com"},
		{"two Persons", []contact{person("1"), person("2")}, ""},
		{"Person plus Team", []contact{team, person("1")}, "alice@it.com"},
		{"Team only", []contact{team}, ""},
		{"no contacts", nil, ""},
		{"Person with no email", []contact{person("3")}, ""},
		{"mixed-case email is canonicalized", []contact{person("4")}, "test.mixedcase@it.com"},
		{"surrounding space is trimmed", []contact{person("9")}, "alice@it.com"},
		{"same Person linked twice", []contact{person("1"), person("1")}, "alice@it.com"},
		{"Person deleted since the CI was read", []contact{person("99")}, ""},
		{"not an email", []contact{person("5")}, ""},
		{"display name", []contact{person("6")}, ""},
		{"address list", []contact{person("7")}, ""},
		{"no domain", []contact{person("8")}, ""},
		{"invalid Person plus valid Person", []contact{person("5"), person("1")}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var want inventory.OwnerEmail
			if tt.want != "" {
				var err error
				if want, err = inventory.NewOwnerEmail(tt.want); err != nil {
					t.Fatal(err)
				}
			}
			if got := owner(ci{contacts: tt.contacts}, lk); got != want {
				t.Errorf("owner = %q, want %q", got, want)
			}
		})
	}
}
