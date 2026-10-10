package itop

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"barbackend/internal/cmdb/itop/rest"
)

// idsPerQuery bounds the IN list of one lookup query, keeping each request a
// few kilobytes however many records the cis reference.
const idsPerQuery = 200

// blankKey is the value iTop gives an external key that references nothing.
const blankKey = "0"

var ciClasses = []struct {
	name   string
	fields []string
}{
	{"Server", ciFields("brand_name", "model_name", "osfamily_name", "osversion_name")},
	{"VirtualMachine", ciFields("osfamily_name", "osversion_name")},
	{"PC", ciFields("brand_name", "model_name", "osfamily_name", "osversion_name")},
	{"NetworkDevice", ciFields("brand_name", "model_name", "iosversion_id")},
}

func ciFields(classFields ...string) []string {
	return append([]string{"name", "description", "status", "business_criticity", "contacts_list", "softwares_list"}, classFields...)
}

// instanceClasses are the SoftwareInstance classes imported as Software
// Components; any other class in a softwares_list is ignored.
var instanceClasses = map[string]bool{
	"DBServer":      true,
	"WebServer":     true,
	"Middleware":    true,
	"PCSoftware":    true,
	"OtherSoftware": true,
}

type ciDocument struct {
	Name         string  `json:"name"`
	Description  string  `json:"description"`
	Status       string  `json:"status"`
	Criticality  *string `json:"business_criticity"`
	Brand        string  `json:"brand_name"`
	Model        string  `json:"model_name"`
	OSFamily     string  `json:"osfamily_name"`
	OSVersion    string  `json:"osversion_name"`
	IOSVersionID string  `json:"iosversion_id"`
	Contacts     []struct {
		ID    string `json:"contact_id"`
		Class string `json:"contact_id_finalclass_recall"`
	} `json:"contacts_list"`
	Instances []struct {
		Class      string `json:"finalclass"`
		Name       string `json:"name"`
		SoftwareID string `json:"software_id"`
	} `json:"softwares_list"`
}

type personDocument struct {
	Email string `json:"email"`
}

type softwareDocument struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type iosVersionDocument struct {
	Brand string `json:"brand_name"`
	Name  string `json:"name"`
}

// fetch reads every ci of the in-scope classes, then the records they
// reference in bulk, so the number of queries depends on the number of
// distinct references rather than on the number of cis.
func fetch(ctx context.Context, c *rest.Client) ([]ci, lookups, error) {
	var cis []ci
	for _, class := range ciClasses {
		objects, err := c.Get(ctx, rest.Query{Class: class.name, Fields: class.fields})
		if err != nil {
			return nil, lookups{}, err
		}
		for _, o := range objects {
			var doc ciDocument
			if err := decode(o, class.fields, &doc); err != nil {
				return nil, lookups{}, err
			}
			cis = append(cis, newCI(o, doc))
		}
	}
	lk, err := fetchLookups(ctx, c, cis)
	if err != nil {
		return nil, lookups{}, err
	}
	return cis, lk, nil
}

func newCI(o rest.Object, doc ciDocument) ci {
	c := ci{
		key:          o.Key,
		class:        o.Class,
		name:         doc.Name,
		description:  doc.Description,
		status:       doc.Status,
		criticality:  doc.Criticality,
		brand:        doc.Brand,
		model:        doc.Model,
		osFamily:     doc.OSFamily,
		osVersion:    doc.OSVersion,
		iosVersionID: doc.IOSVersionID,
	}
	for _, ct := range doc.Contacts {
		c.contacts = append(c.contacts, contact{id: ct.ID, class: ct.Class})
	}
	for _, in := range doc.Instances {
		if instanceClasses[in.Class] {
			c.instances = append(c.instances, instance{class: in.Class, name: in.Name, softwareID: in.SoftwareID})
		}
	}
	return c
}

func fetchLookups(ctx context.Context, c *rest.Client, cis []ci) (lookups, error) {
	personIDs, softwareIDs, iosVersionIDs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, item := range cis {
		for _, ct := range item.contacts {
			if ct.class == "Person" {
				personIDs[ct.id] = true
			}
		}
		for _, in := range item.instances {
			softwareIDs[in.softwareID] = true
		}
		iosVersionIDs[item.iosVersionID] = true
	}
	var lk lookups
	var err error
	if lk.emails, err = getByID(ctx, c, "Person", []string{"email"}, personIDs,
		func(d personDocument) string { return d.Email }); err != nil {
		return lookups{}, err
	}
	if lk.software, err = getByID(ctx, c, "Software", []string{"name", "version"}, softwareIDs,
		func(d softwareDocument) software { return software{name: d.Name, version: d.Version} }); err != nil {
		return lookups{}, err
	}
	if lk.iosVersions, err = getByID(ctx, c, "IOSVersion", []string{"brand_name", "name"}, iosVersionIDs,
		func(d iosVersionDocument) iosVersion { return iosVersion{brand: d.Brand, version: d.Name} }); err != nil {
		return lookups{}, err
	}
	return lk, nil
}

// getByID reads the objects of class whose keys are in ids, skipping blank
// keys. A referenced object deleted since the cis were read is simply absent.
func getByID[D, T any](ctx context.Context, c *rest.Client, class string, fields []string, ids map[string]bool, convert func(D) T) (map[string]T, error) {
	delete(ids, blankKey)
	delete(ids, "")
	// Sorted so the same instance always produces the same requests.
	keys := slices.Sorted(maps.Keys(ids))
	// The ids are interpolated into OQL, so anything but a number is refused.
	for _, k := range keys {
		if _, err := strconv.ParseUint(k, 10, 64); err != nil {
			return nil, fmt.Errorf("itop: %s id %q is not numeric", class, k)
		}
	}
	byID := make(map[string]T, len(keys))
	for chunk := range slices.Chunk(keys, idsPerQuery) {
		objects, err := c.Get(ctx, rest.Query{Class: class, Where: "id IN (" + strings.Join(chunk, ",") + ")", Fields: fields})
		if err != nil {
			return nil, err
		}
		for _, o := range objects {
			var doc D
			if err := decode(o, fields, &doc); err != nil {
				return nil, err
			}
			byID[o.Key] = convert(doc)
		}
	}
	return byID, nil
}

// decode fails when a requested field is missing, because iTop silently
// drops an output field the class does not have: a renamed or removed field
// would otherwise import as blank on every record.
func decode(o rest.Object, fields []string, v any) error {
	var present map[string]json.RawMessage
	if err := json.Unmarshal(o.Fields, &present); err != nil {
		return fmt.Errorf("itop: decode %s::%s: %w", o.Class, o.Key, err)
	}
	for _, f := range fields {
		if _, ok := present[f]; !ok {
			return fmt.Errorf("itop: %s::%s has no field %s", o.Class, o.Key, f)
		}
	}
	if err := json.Unmarshal(o.Fields, v); err != nil {
		return fmt.Errorf("itop: decode %s::%s: %w", o.Class, o.Key, err)
	}
	return nil
}
