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

type body[T any] struct {
	Body T
}

// Huma lists 422 on any operation with path parameters or a body, though
// newHumaError answers those failures with 400.
func register[I, O any](api huma.API, op huma.Operation, handler func(context.Context, *I) (*O, error)) {
	op.Errors = append(op.Errors, http.StatusUnauthorized, http.StatusForbidden)
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

// Huma refuses nullable on objects and documents a pointer to a struct as
// never null, though a nil pointer is null on the wire.
func markNullableObjects(oapi *huma.OpenAPI, _ *huma.Operation) {
	registry := oapi.Components.Schemas
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
			if prop := schema.Properties[jsonName]; isUnwrappedObjectRef(prop) {
				schema.Properties[jsonName] = orNull(prop)
			}
		}
	}
}

func isUnwrappedObjectRef(s *huma.Schema) bool {
	return s != nil && s.Ref != ""
}

func orNull(s *huma.Schema) *huma.Schema {
	return &huma.Schema{AnyOf: []*huma.Schema{s, {Type: huma.TypeNull}}}
}

func nullableBody[T any](api huma.API) map[string]*huma.Response {
	ref := api.OpenAPI().Components.Schemas.Schema(reflect.TypeFor[T](), true, "")
	return map[string]*huma.Response{
		"200": {Content: map[string]*huma.MediaType{"application/json": {Schema: orNull(ref)}}},
	}
}
