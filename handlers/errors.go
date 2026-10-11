package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/markusnieminen1/basic-auth/domain/customerrors"
)

// WriteErrorHttp sends a CustomError to the client as JSON with its own status code.
// Only the public message and fields are written, never the private message.
func WriteErrorHttp(w http.ResponseWriter, err customerrors.CustomError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.Code)
	_ = json.NewEncoder(w).Encode(err)
}
