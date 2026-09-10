package validating

import (
	"net/mail"
	"strings"

	"github.com/markusnieminen1/basic-auth/repository/customerrors"
)

func (u *UserDataValidator) ValidateEmail(email string) error {
	trimmed := strings.TrimSpace(email)

	if trimmed == "" {
		return customerrors.ErrEmailEmpty
	}
	if len(trimmed) > 254 {
		return customerrors.ErrEmailTooLong
	}

	_, err := mail.ParseAddress(trimmed)
	if err != nil {
		return customerrors.ErrEmailInvalid
	}

	return nil
}
