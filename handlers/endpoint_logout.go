package handlers

import (
	"net/http"

	"github.com/markusnieminen1/basic-auth/domain/customerrors"
	"github.com/markusnieminen1/basic-auth/domain/sharedmodels"
	"github.com/markusnieminen1/basic-auth/service"
	"github.com/markusnieminen1/basic-auth/setup"
)

// LogoutHandler ends the session of the request's tokens and answers with expired
// cookies that overwrite them in the client. It needs no middleware and works for
// anonymous requests too, which simply have nothing to revoke.
// It does not serve any html.
type LogoutHandler struct {
	AuthenticationService service.AuthenticationService
}

func (h *LogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteErrorHttp(w, customerrors.ErrMethodNotApplicable)
		return
	}

	var cookies sharedmodels.AuthCookies
	if c, err := r.Cookie(setup.ACCESS_TOKEN_NAME); err == nil {
		cookies.AccessToken = c
	}
	if c, err := r.Cookie(setup.REFRESH_TOKEN_NAME); err == nil {
		cookies.RefreshToken = c
	}

	expired, err := h.AuthenticationService.Logout(r.Context(), cookies)
	if err != nil {
		http.Error(w, "logout failed", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, expired.AccessToken)
	http.SetCookie(w, expired.RefreshToken)
	w.WriteHeader(http.StatusOK)
}
