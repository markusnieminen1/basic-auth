package handlers

import (
	"context"
	"net/http"

	"github.com/markusnieminen1/basic-auth/domain/sharedmodels"
	"github.com/markusnieminen1/basic-auth/service"
)

// NewValidateTokenMiddleware sets AuthCookies.UserID in the context when the request is
// authenticated. A valid access token is enough. Otherwise the refresh token is used to
// issue new tokens, which also covers the access cookie being gone: the browser drops it
// as soon as it expires. If neither works the request continues with UserID nil.
func NewValidateTokenMiddleware(authenticator service.Authenticator) func(http.Handler) http.Handler {

	return func(next http.Handler) http.Handler {

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			authCookieCtx, ok := r.Context().Value(AuthCookiesCtxKey{}).(sharedmodels.AuthCookies)

			if !ok {
				next.ServeHTTP(w, r)
				return
			}

			if authCookieCtx.AccessToken != nil {
				if userID, err := authenticator.Authenticate(r.Context(), authCookieCtx); err == nil {
					authCookieCtx.UserID = &userID
					next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), AuthCookiesCtxKey{}, authCookieCtx)))
					return
				}
			}

			if authCookieCtx.RefreshToken == nil {
				next.ServeHTTP(w, r)
				return
			}

			refreshedSession, err := authenticator.Refresh(r.Context(), authCookieCtx)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			if refreshedSession.AccessToken != nil {
				http.SetCookie(w, refreshedSession.AccessToken)
			}
			if refreshedSession.RefreshToken != nil {
				http.SetCookie(w, refreshedSession.RefreshToken)
			}

			// Refresh sets the user ID of the renewed session.
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), AuthCookiesCtxKey{}, refreshedSession)))
		})

	}
}
