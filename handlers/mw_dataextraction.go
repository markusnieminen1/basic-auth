package handlers

import (
	"context"
	"net/http"
)

type contextKey string

const HeaderContextKey contextKey = "extracted_headers"

func ExtractHeaders[T any](extractor func(http.Header) T) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			extractedValue := extractor(r.Header)

			ctx := context.WithValue(r.Context(), HeaderContextKey, extractedValue)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
