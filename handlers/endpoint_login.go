package handlers

import (
	"net/http"

	"github.com/markusnieminen1/basic-auth/domain/customerrors"
	"github.com/markusnieminen1/basic-auth/domain/sharedmodels"
	"github.com/markusnieminen1/basic-auth/service"
)

// LoginHandler provides Auth headers for the client.
// It checks the login credentials are correct and returns tokens to the client.
// It does not serve any html.
type LoginHandler struct {
	AuthenticationService service.AuthenticationService
}

func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteErrorHttp(w, customerrors.ErrMethodNotApplicable)
		return
	}

	var input sharedmodels.LoginInput
	if err := GeneralDecoder(r, &input); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	authCookies, err := h.AuthenticationService.Login(r.Context(), input)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if authCookies.AccessToken != nil {
		http.SetCookie(w, authCookies.AccessToken)
	}
	if authCookies.RefreshToken != nil {
		http.SetCookie(w, authCookies.RefreshToken)
	}
	w.WriteHeader(http.StatusOK)
}
