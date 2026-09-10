// Functions for creating functionality with defaults
package basicauth

import (
	"net/http"

	"github.com/markusnieminen1/basic-auth/handlers"
	"github.com/markusnieminen1/basic-auth/internal"
	"github.com/markusnieminen1/basic-auth/internal/validating"
	"github.com/markusnieminen1/basic-auth/models"
	"github.com/markusnieminen1/basic-auth/service"
)

const ()

type Application struct {
	UserManager       models.UserManager
	HashManager       models.HashingManager
	PermissionManager models.PermissionsManager
	CookieManager     models.CookieManager
	AuthManager       models.AuthManager

	LoginHandler        http.Handler
	LogoutHandler       http.Handler
	RegisterUserHandler http.Handler

	ExtractCookiesMidWare func(http.Handler) http.Handler
	RatelimitMidWare      func(http.Handler) http.Handler
	ValidateTokenMidWare  func(http.Handler) http.Handler
}

// Basic config
func NewBaseConfigApp() Application {

	return Application{
		UserManager: &service.UserManagerService{UserValidator: validating.NewUserValidator()},

		LoginHandler:        &handlers.LoginHandler{},
		LogoutHandler:       &handlers.LogoutHandler{},
		RegisterUserHandler: &handlers.RegisterHandler{},

		ExtractCookiesMidWare: handlers.ExtractHeaders(func(h http.Header) models.ToExtract {
			return models.ToExtract{
				AccessToken:  h.Get(internal.ACCESS_TOKEN_NAME),
				RefreshToken: h.Get(internal.REFRESH_TOKEN_NAME),
			}
		}),

		RatelimitMidWare:     handlers.Ratelimiting,
		ValidateTokenMidWare: handlers.ValidateToken,
	}
}

// Custom config
func NewCustomConfigApp(cfg Application) Application {
	app := NewBaseConfigApp()

	mux := http.NewServeMux()
	mux.Handle("/something", app.ExtractCookiesMidWare(app.LoginHandler))

	return Application{}
}
