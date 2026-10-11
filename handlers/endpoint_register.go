package handlers

import (
	"net/http"

	"github.com/markusnieminen1/basic-auth/domain/sharedmodels"
	"github.com/markusnieminen1/basic-auth/service"
)

// RegisterHandler provides handler for registering new user.
// It validates data, saves the data if accible and returns new login tokens to the client.
// It does not serve any html.
type RegisterHandler struct {
	AccountService service.AccountService
}

func (h *RegisterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	var input sharedmodels.RegisterInput

	err := GeneralDecoder(r, &input)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := h.AccountService.Register(r.Context(), input)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	_ = user
	w.WriteHeader(http.StatusCreated)

}
