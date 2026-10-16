package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/markusnieminen1/basic-auth/domain/customerrors"
	"github.com/markusnieminen1/basic-auth/domain/sharedmodels"
	"github.com/markusnieminen1/basic-auth/service"
)

// RegisterHandler provides handler for registering new user.
// It validates the data, saves it and answers 201 with the new user. The user is not logged
// in: the client logs in next.
// It does not serve any html.
type RegisterHandler struct {
	AccountService service.AccountService
}

func (h *RegisterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteErrorHttp(w, customerrors.ErrMethodNotApplicable)
		return
	}

	var input sharedmodels.RegisterInput
	if err := GeneralDecoder(r, &input); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := h.AccountService.Register(r.Context(), input)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(user)
}
