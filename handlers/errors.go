package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/markusnieminen1/basic-auth/domain/customerrors"
	"github.com/markusnieminen1/basic-auth/service"
	"github.com/markusnieminen1/basic-auth/store/user"
)

// WriteErrorHttp sends a CustomError to the client as JSON with its own status code.
// Only the public message and fields are written, never the private message.
func WriteErrorHttp(w http.ResponseWriter, err customerrors.CustomError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.Code)
	_ = json.NewEncoder(w).Encode(err)
}

// writeServiceError answers with the status that fits an error from the services: validation
// errors carry their own, bad credentials are 401, taken names are 409, and anything else is
// an internal failure whose details stay in the server and never reach the client.
func writeServiceError(w http.ResponseWriter, err error) {
	var custom customerrors.CustomError
	switch {
	case errors.As(err, &custom):
		WriteErrorHttp(w, custom)
	case errors.Is(err, service.ErrInvalidCredentials):
		WriteErrorHttp(w, customerrors.ErrInvalidCredentials)
	case errors.Is(err, user.ErrUsernameTaken):
		WriteErrorHttp(w, customerrors.ErrUsernameTaken)
	case errors.Is(err, user.ErrEmailTaken):
		WriteErrorHttp(w, customerrors.ErrEmailTaken)
	default:
		WriteErrorHttp(w, customerrors.ErrInternal)
	}
}
