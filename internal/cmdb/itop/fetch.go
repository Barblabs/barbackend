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

var instanceClasses = map[string]bool{
	"DBServer":      true,
	"WebServer":     true,
	"Middleware":    true,
	"PCSoftware":    true,
	"OtherSoftware": true,
}

func fetch(ctx context.Context, c *rest.Client) ([]ci, lookups, error) {
	var cis []ci
	for _, class := range ciClasses {
		objects, err := c.Get(ctx, rest.Query{Class: class.name, Fields: class.fields})
		if err != nil {
			return nil, lookups{}, err
		}
		for _, o := range objects {
			c, err := decodeCI(o, class.fields)
			if err != nil {
				return nil, lookups{}, err
			}
			cis = append(cis, c)
		}
	}
	lk, err := fetchLookups(ctx, c, cis)
	if err != nil {
		return nil, lookups{}, err
	}
	return cis, lk, nil
}

func decodeCI(o rest.Object, fields []string) (ci, error) {
	var c ci
	if err := decode(o, fields, &c); err != nil {
		return ci{}, err
	}
	c.Key, c.Class = o.Key, o.Class
	c.Instances = slices.DeleteFunc(c.Instances, func(in instance) bool { return !instanceClasses[in.Class] })
	return c, nil
}

func fetchLookups(ctx context.Context, c *rest.Client, cis []ci) (lookups, error) {
	personIDs, softwareIDs, iosVersionIDs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, item := range cis {
		for _, ct := range item.Contacts {
			if ct.Class == "Person" {
				personIDs[ct.ID] = true
			}
		}
		for _, in := range item.Instances {
			softwareIDs[in.SoftwareID] = true
		}
		iosVersionIDs[item.IOSVersionID] = true
	}
	var lk lookups
	var err error
	if lk.persons, err = getByID[person](ctx, c, "Person", []string{"email"}, personIDs); err != nil {
		return lookups{}, err
	}
	if lk.software, err = getByID[software](ctx, c, "Software", []string{"name", "version"}, softwareIDs); err != nil {
		return lookups{}, err
	}
	if lk.iosVersions, err = getByID[iosVersion](ctx, c, "IOSVersion", []string{"brand_name", "name"}, iosVersionIDs); err != nil {
		return lookups{}, err
	}
	return lk, nil
}

func getByID[T any](ctx context.Context, c *rest.Client, class string, fields []string, ids map[string]bool) (map[string]T, error) {
	delete(ids, blankKey)
	delete(ids, "")
	keys := slices.Sorted(maps.Keys(ids))
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
			var record T
			if err := decode(o, fields, &record); err != nil {
				return nil, err
			}
			byID[o.Key] = record
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
