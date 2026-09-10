package validating

import (
	"github.com/markusnieminen1/basic-auth/internal"
	"github.com/markusnieminen1/basic-auth/models"
)

func DefaultPasswordRules() models.PasswordRules {
	return models.PasswordRules{
		MinLength:    internal.PWD_MinLength,
		MinUppercase: internal.PWD_MinUppercase,
		MinLowercase: internal.PWD_MinLowercase,
		MinDigits:    internal.PWD_MinDigits,
		MinSymbols:   internal.PWD_MinSymbols,
	}
}

func DefaultUsernameRules() models.UsernameRules {
	return models.UsernameRules{
		MinLength:         internal.UName_MinLength,
		MaxLength:         internal.UName_MaxLength,
		AllowSpecialChars: internal.UName_AllowSpecialChars,
	}
}
