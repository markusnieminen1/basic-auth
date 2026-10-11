package handlers

import (
	"context"
	"net/http"

	"github.com/markusnieminen1/basic-auth/domain/sharedmodels"
	"github.com/markusnieminen1/basic-auth/setup"
)

type AuthCookiesCtxKey struct{}

// ExtractCookies first tries to read
//
//	r.Cookie(setup.REFRESH_TOKEN_NAME)
//
// and if it exists, then
//
//	r.Cookie(setup.ACCESS_TOKEN_NAME).
//
// If refresh token does not exist, then nothing is added to the context.
func ExtractCookies(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		authCookieCtx := sharedmodels.AuthCookies{}
		refresh_token, err := r.Cookie(setup.REFRESH_TOKEN_NAME)

		if err == nil {
			authCookieCtx.RefreshToken = refresh_token

			access_token, err := r.Cookie(setup.ACCESS_TOKEN_NAME)

			if err == nil {
				authCookieCtx.AccessToken = access_token
			}
		}

		ctx := context.WithValue(r.Context(), AuthCookiesCtxKey{}, authCookieCtx)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
