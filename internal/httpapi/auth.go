package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"barbackend/internal/tenancy"
	"barbackend/internal/users"
	"github.com/danielgtaylor/huma/v2"
)

const bearerScheme = "bearer"

type userKey struct{}

func secureByBearer(config *huma.Config) {
	config.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
		bearerScheme: {Type: "http", Scheme: "bearer", BearerFormat: "JWT", Description: "A Cognito access token"},
	}
	config.Security = []map[string][]string{{bearerScheme: {}}}
}

// Huma runs API middleware only around registered operations, so the spec
// and docs routes stay open.
func authenticate(api huma.API, svc *users.Service) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		u, err := svc.Authenticate(ctx.Context(), bearerToken(ctx.Header("Authorization")))
		if err != nil {
			writeError(api, ctx, apiError(err))
			return
		}
		next(huma.WithValue(ctx, userKey{}, u))
	}
}

// The authentication scheme is case-insensitive (RFC 9110, section 11.1).
func bearerToken(header string) string {
	scheme, token, _ := strings.Cut(header, " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}

func writeError(api huma.API, ctx huma.Context, e *codedError) {
	if e.status == http.StatusUnauthorized {
		ctx.SetHeader("WWW-Authenticate", "Bearer")
	}
	v, err := api.Transform(ctx, strconv.Itoa(e.status), e)
	if err != nil {
		e = internal(err)
		v = e
	}
	ctx.SetHeader("Content-Type", "application/json")
	ctx.SetStatus(e.status)
	_ = api.Marshal(ctx.BodyWriter(), "application/json", v)
}

func customerOf(ctx context.Context) (tenancy.CustomerID, error) {
	u, ok := ctx.Value(userKey{}).(tenancy.User)
	if !ok {
		return tenancy.CustomerID{}, internal(errors.New("operation reached without a signed-in user"))
	}
	id, err := u.ActsFor()
	if err != nil {
		return tenancy.CustomerID{}, apiError(err)
	}
	return id, nil
}
