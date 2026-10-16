package validating

import (
	"net/mail"
	"strings"

	"github.com/markusnieminen1/basic-auth/domain/customerrors"
)

func (u *UserDataValidator) ValidateEmail(email string) error {
	trimmed := strings.TrimSpace(email)

	if trimmed == "" {
		return customerrors.ErrEmailEmpty
	}
	if len(trimmed) > 254 {
		return customerrors.ErrEmailTooLong
	}

	// ParseAddress also accepts "Name <a@b.com>", but only the bare address may be stored.
	parsed, err := mail.ParseAddress(trimmed)
	if err != nil || parsed.Address != trimmed {
		return customerrors.ErrEmailInvalid
	}

	return nil
}
