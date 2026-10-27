package httpapi

import (
	"context"
	"net/http"
	"reflect"
	"slices"
	"strings"

	"github.com/danielgtaylor/huma/v2"
)

const (
	schemaPrefix = "#/components/schemas/"
	omit422      = "omit422"
)

// register adds an operation whose spec lists only the errors in op.Errors.
// Huma also lists 422 on any operation with parameters or a body, though
// newHumaError answers those failures with 400.
func register[I, O any](api huma.API, op huma.Operation, handler func(context.Context, *I) (*O, error)) {
	if !slices.Contains(op.Errors, http.StatusUnprocessableEntity) {
		op.Metadata = map[string]any{omit422: true}
	}
	huma.Register(api, op, handler)
}

func dropUndeclared422(_ *huma.OpenAPI, op *huma.Operation) {
	if op.Metadata[omit422] == true {
		delete(op.Responses, "422")
	}
}

// markNullableObjects lets a field holding a pointer to a struct be null in
// the spec, as it is on the wire when the pointer is nil: Huma refuses
// nullable on objects and documents them as never null.
func markNullableObjects(api huma.API) {
	registry := api.OpenAPI().Components.Schemas
	for name, schema := range registry.Map() {
		t := registry.TypeFromRef(schemaPrefix + name)
		if t == nil || t.Kind() != reflect.Struct {
			continue
		}
		for _, f := range reflect.VisibleFields(t) {
			if f.Type.Kind() != reflect.Pointer || f.Type.Elem().Kind() != reflect.Struct {
				continue
			}
			jsonName, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if prop := schema.Properties[jsonName]; prop != nil && prop.Ref != "" {
				schema.Properties[jsonName] = orNull(prop)
			}
		}
	}
}

func orNull(s *huma.Schema) *huma.Schema {
	return &huma.Schema{AnyOf: []*huma.Schema{s, {Type: huma.TypeNull}}}
}

// nullableBody documents a 200 response whose body is T or null, for an
// output whose Body is a *T.
func nullableBody[T any](api huma.API) map[string]*huma.Response {
	ref := api.OpenAPI().Components.Schemas.Schema(reflect.TypeFor[T](), true, "")
	return map[string]*huma.Response{
		"200": {Content: map[string]*huma.MediaType{"application/json": {Schema: orNull(ref)}}},
	}
}
