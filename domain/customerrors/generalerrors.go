package customerrors

import (
	"errors"
	"net/http"
)

var (
	ErrMultipleRegisterValidationProblems = CustomError{Code: http.StatusBadRequest, PublicMessage: "Multiple issues with validating data."}

	ErrEmailEmpty   = CustomError{Code: http.StatusBadRequest, PublicMessage: "email address cannot be empty"}
	ErrEmailTooLong = CustomError{Code: http.StatusBadRequest, PublicMessage: "email address exceeds maximum length of 254 characters"}
	ErrEmailInvalid = CustomError{Code: http.StatusBadRequest, PublicMessage: "invalid email address format"}

	ErrPasswordEmpty         = CustomError{Code: http.StatusBadRequest, PublicMessage: "password cannot be empty"}
	ErrPasswordTooShort      = CustomError{Code: http.StatusBadRequest, PublicMessage: "password does not meet the minimum length requirement"}
	ErrPasswordTooLong       = CustomError{Code: http.StatusBadRequest, PublicMessage: "password cannot exceed 72 bytes"}
	ErrPasswordNeedsUpper    = CustomError{Code: http.StatusBadRequest, PublicMessage: "password does not contain enough uppercase letters"}
	ErrPasswordNeedsLower    = CustomError{Code: http.StatusBadRequest, PublicMessage: "password does not contain enough lowercase letters"}
	ErrPasswordNeedsDigit    = CustomError{Code: http.StatusBadRequest, PublicMessage: "password does not contain enough numbers"}
	ErrPasswordForbiddenChar = CustomError{Code: http.StatusBadRequest, PublicMessage: "password contains a forbidden character"}
	ErrPasswordNeedsSymbol   = CustomError{Code: http.StatusBadRequest, PublicMessage: "password does not contain enough special characters"}

	ErrUsernameEmpty         = CustomError{Code: http.StatusBadRequest, PublicMessage: "username cannot be empty"}
	ErrUsernameTooShort      = CustomError{Code: http.StatusBadRequest, PublicMessage: "username is below the minimum length"}
	ErrUsernameTooLong       = CustomError{Code: http.StatusBadRequest, PublicMessage: "username exceeds the maximum length"}
	ErrUsernameInvalidChar   = CustomError{Code: http.StatusBadRequest, PublicMessage: "username contains invalid characters (only alphanumeric, underscores, or hyphens allowed)"}
	ErrUsernameForbiddenChar = CustomError{Code: http.StatusBadRequest, PublicMessage: "username contains a forbidden character"}
	ErrIDNegative            = CustomError{Code: http.StatusBadRequest, PublicMessage: "user id cannot be negative"}

	ErrJsonInvalidBody           = CustomError{Code: http.StatusBadRequest, PublicMessage: "Invalid JSON body. Check field names and required data types / formats "}
	ErrJsonUnknownFieldsProvided = CustomError{Code: http.StatusBadRequest, PublicMessage: "Json body contains unknown fields"}
	ErrJsonWrongDataType         = CustomError{Code: http.StatusBadRequest, PublicMessage: "One or more of the JSON body items contain invalid data formats. e.g. '10' when 10 is required "}

	ErrTooManyRequests = CustomError{Code: http.StatusTooManyRequests, PublicMessage: "Too many requests within time window"}

	ErrInvalidCredentials = CustomError{Code: http.StatusUnauthorized, PublicMessage: "invalid credentials"}
	ErrUsernameTaken      = CustomError{Code: http.StatusConflict, PublicMessage: "username is already taken"}
	ErrEmailTaken         = CustomError{Code: http.StatusConflict, PublicMessage: "email address is already registered"}
	ErrInternal           = CustomError{Code: http.StatusInternalServerError, PublicMessage: "internal error"}

	ErrUnauthorized = CustomError{Code: http.StatusUnauthorized, PublicMessage: "authentication required"}

	ErrMethodNotApplicable = CustomError{Code: http.StatusMethodNotAllowed, PublicMessage: "method not allowed"}
)

type CustomError struct {
	Code           int               `json:"code"`             // HTTP status code
	PublicMessage  string            `json:"message"`          // Message sent to the client
	PrivateMessage string            `json:"-"`                // Used only for debugging, json:"-" blocks from writing the value into a JSON.
	Fields         map[string]string `json:"fields,omitempty"` // If multiple problems occur, Fields will be populated and sent as JSON
}

func (e CustomError) Error() string {
	return e.PublicMessage
}

// Is Makes it possible to compare error with
//
//	errors.is(err, target)
func (e CustomError) Is(target error) bool {
	if target == nil {
		return false
	}

	var targetCustom CustomError

	if !errors.As(target, &targetCustom) {
		return false
	}
	// In the end, error messages are what determines if its the same exact error
	return e.PublicMessage == targetCustom.PublicMessage
}
