package validating

import (
	"unicode"

	"github.com/markusnieminen1/basic-auth/repository/customerrors"
)

func (u *UserDataValidator) ValidatePassword(password string) error {
	if password == "" {
		return customerrors.ErrPasswordEmpty
	}

	if len(password) < u.passwordrules.MinLength {
		return customerrors.ErrPasswordTooShort
	}
	if len(password) > 72 {
		return customerrors.ErrPasswordTooLong
	}

	var (
		upperCount  int
		lowerCount  int
		digitCount  int
		symbolCount int
	)

	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			upperCount++
		case unicode.IsLower(r):
			lowerCount++
		case unicode.IsDigit(r):
			digitCount++
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			symbolCount++
		}
	}

	if upperCount < u.passwordrules.MinUppercase {
		return customerrors.ErrPasswordNeedsUpper
	}
	if lowerCount < u.passwordrules.MinLowercase {
		return customerrors.ErrPasswordNeedsLower
	}
	if digitCount < u.passwordrules.MinDigits {
		return customerrors.ErrPasswordNeedsDigit
	}
	if symbolCount < u.passwordrules.MinSymbols {
		return customerrors.ErrPasswordNeedsSymbol
	}

	return nil
}
