package handlers

import (
	"net/http"

	"github.com/markusnieminen1/basic-auth/models"
)

// LogoutHandler expires Auth headers from the client.
// Handler also invalidates sessions from the database.
type LogoutHandler struct {
	AuthService *models.AuthManager
}

func (h *LogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

}
