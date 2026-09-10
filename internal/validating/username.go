package validating

import (
	"strings"
	"unicode"

	"github.com/markusnieminen1/basic-auth/repository/customerrors"
)

func (u *UserDataValidator) ValidateUsername(username string) error {
	trimmed := strings.TrimSpace(username)
	if trimmed == "" {
		return customerrors.ErrUsernameEmpty
	}

	runeCount := strings.Count(trimmed, "") - 1
	if runeCount < u.usernamerules.MinLength {
		return customerrors.ErrUsernameTooShort
	}
	if runeCount > u.usernamerules.MaxLength {
		return customerrors.ErrUsernameTooLong
	}

	for _, r := range trimmed {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}

		if u.usernamerules.AllowSpecialChars && (r == '_' || r == '-') {
			continue
		}

		return customerrors.ErrUsernameInvalidChar
	}

	return nil
}
