// Functions for creating functionality with defaults
package basicauth

import (
	"github.com/markusnieminen1/basic-auth/handlers"
	"github.com/markusnieminen1/basic-auth/models"
)

// Basic config

// Custom config

type Config struct {
	UserManager       models.UserManager
	HashManager       models.HashingManager
	PermissionManager models.PermissionsManager
	CookieManager     models.CookieManager
	AuthManager       models.AuthManager
}

type Application struct {
	Login        *handlers.LoginHandler
	Logout       *handlers.LogoutHandler
	RegisterUser *handlers.RegisterHandler
	// DataExtractMidWare *handlers.ExtractHeaders
	// RatelimitMidWare
	// ValidateRequestMidWare
}

func New(cfg Config) *Application {
	return &Application{}
}
