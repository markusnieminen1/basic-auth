package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/markusnieminen1/basic-auth/repository/customerrors"
)

func GeneralDecoder[T any](r *http.Request, obj *T) error {

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	err := decoder.Decode(obj)

	if err != nil {

		var unmarshalTypeError *json.UnmarshalTypeError
		if errors.As(err, &unmarshalTypeError) {
			return customerrors.ErrJsonWrongDataType
		}

		var syntaxError *json.SyntaxError
		if errors.As(err, &syntaxError) {
			return customerrors.ErrJsonInvalidBody
		}

		if strings.Contains(err.Error(), "unknown field") {
			return customerrors.ErrJsonUnknownFieldsProvided
		}

		return customerrors.ErrJsonInvalidBody
	}

	return nil
}
