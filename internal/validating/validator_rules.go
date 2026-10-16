package validating

import (
	"github.com/markusnieminen1/basic-auth/setup"
)

type PasswordRules struct {
	MinLength    int
	MinUppercase int
	MinLowercase int
	MinDigits    int
	MinSymbols   int

	ForbiddenChars string // every character in the string is rejected
}

type UsernameRules struct {
	MinLength         int
	MaxLength         int
	AllowSpecialChars bool

	ForbiddenChars string // every character in the string is rejected
}

// Creates validation rules based on the setup file. Before using the struct
// in the validator, you can change the default values by either changing
// setup values or
//
//	rules := NewDefaultPasswordRules()
//	rules.MinLength=12
func NewDefaultPasswordRules() PasswordRules {
	return PasswordRules{
		MinLength:    setup.PWD_MinLength,
		MinUppercase: setup.PWD_MinUppercase,
		MinLowercase: setup.PWD_MinLowercase,
		MinDigits:    setup.PWD_MinDigits,
		MinSymbols:   setup.PWD_MinSymbols,

		ForbiddenChars: setup.PWD_ForbiddenChars,
	}
}

// Creates validation rules based on the setup file. Before using the struct
// in the validator, you can change the default values by either changing
// setup values or
//
//	rules := NewDefaultUsernameRules()
//	rules.MaxLength=15
func NewDefaultUsernameRules() UsernameRules {
	return UsernameRules{
		MinLength:         setup.UName_MinLength,
		MaxLength:         setup.UName_MaxLength,
		AllowSpecialChars: setup.UName_AllowSpecialChars,

		ForbiddenChars: setup.UName_ForbiddenChars,
	}
}
