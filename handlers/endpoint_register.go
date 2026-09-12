package handlers

import (
	"net/http"

	"github.com/markusnieminen1/basic-auth/models"
)

// RegisterHandler provides handler for registering new user.
// It validates data, saves the data if accible and returns new login tokens to the client.
// It does not serve any html.
type RegisterHandler struct {
	UserService models.UserManager
}

func (h *RegisterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	// parse etc
	var userdata models.AllUserProfileAuthData

	err := GeneralDecoder(r, &userdata)

	if err != nil {
		// handle error
	}

	// user_id, err := h.UserService.NewUser(r.Context(), userdata)

	if err != nil {
		// handle error
	}

	// Get cookie

	// Write cookie

	// Respond with 201

}
