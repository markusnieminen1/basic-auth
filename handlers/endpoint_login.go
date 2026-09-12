package handlers

import (
	"net/http"

	"github.com/markusnieminen1/basic-auth/models"
)

// LoginHandler provides Auth headers for the client.
// It checks the login credentials are correct and returns tokens to the client.
// It does not serve any html.
type LoginHandler struct {
	AuthService *models.AuthManager
}

func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// check request type

	//
}
