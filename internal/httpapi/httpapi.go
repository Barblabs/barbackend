// Package httpapi is the HTTP transport: it routes requests to use cases
// (ADR 0008).
package httpapi

import (
	"encoding/json"
	"io"
	"net/http"

	"barbackend/internal/cmdb"
	"barbackend/internal/users"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humagin"
	"github.com/gin-gonic/gin"
)

type Config struct {
	CMDB  *cmdb.Service
	Users *users.Service
	// AllowedOrigins may call the API from a browser.
	AllowedOrigins []string
}

func New(cfg Config) http.Handler {
	router := gin.Default()
	router.Use(cors(cfg.AllowedOrigins))
	router.GET("/ping", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"message": "pong"})
	})
	api := humagin.New(router, apiConfig())
	api.UseMiddleware(authenticate(api, cfg.Users))
	cmdbSourceHandler{cmdb: cfg.CMDB}.register(api)
	assetHandler{cmdb: cfg.CMDB}.register(api)
	customerHandler{users: cfg.Users}.register(api)
	userHandler{users: cfg.Users}.register(api)
	return router
}

func apiConfig() huma.Config {
	config := huma.DefaultConfig("barbattack", "1.0.0")
	config.OpenAPIPath = "/openapi"
	config.DocsPath = "/docs"
	// The default hook adds a $schema field to every response body, which
	// would change the wire format.
	config.CreateHooks = nil
	secureByBearer(&config)
	config.Formats = map[string]huma.Format{"application/json": jsonFormat, "json": jsonFormat}
	config.Transformers = []huma.Transformer{logCause}
	config.OnAddOperation = append(config.OnAddOperation, dropUndeclared422, markNullableObjects)
	return config
}

// jsonFormat encodes as Gin does, without Huma's trailing newline, so
// response bodies stay byte for byte what they were.
var jsonFormat = huma.Format{
	Marshal: func(w io.Writer, v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		_, err = w.Write(b)
		return err
	},
	Unmarshal: json.Unmarshal,
}

// Huma builds its own errors, such as for a body that is malformed or misses
// a field, through huma.NewError, and decides array nullability through
// huma.DefaultArrayNullable; both are global.
func init() {
	huma.NewError = newHumaError
	huma.DefaultArrayNullable = false
}
