package handlers

import "net/http"

func ExtractHeaders[T any](next http.Handler, model T) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})

}
