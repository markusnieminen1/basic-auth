// Functions for creating functionality with defaults
package auth

import (
	"net/http"

	"github.com/markusnieminen1/basic-auth/handlers"
	"github.com/markusnieminen1/basic-auth/internal"
	"github.com/markusnieminen1/basic-auth/internal/validating"
	"github.com/markusnieminen1/basic-auth/models"
	"github.com/markusnieminen1/basic-auth/repository/database/dummydbfortest"
	"github.com/markusnieminen1/basic-auth/service"
)

type Application struct {
	UserManager       models.UserManager
	HashManager       models.HashingManager
	PermissionManager models.PermissionsManager
	CookieManager     models.CookieManager
	AuthManager       models.AuthManager

	Handlers AuthHandlers
}

type AuthHandlers struct {
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

		UserManager: &service.UserManagerService{
			UserValidator:  validating.NewUserValidator(),
			UserRepository: &dummydbfortest.UserManagerRepo{},
		},

		Handlers: AuthHandlers{
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
		},
	}
}

// Custom config
func NewCustomConfigApp(cfg Application) Application {
	app := NewBaseConfigApp()

	if cfg.UserManager != nil {
		app.UserManager = cfg.UserManager
	}

	return app
}
