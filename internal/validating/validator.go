package validating

import "github.com/markusnieminen1/basic-auth/models"

type UserDataValidator struct {
	passwordrules models.PasswordRules
	usernamerules models.UsernameRules
}

func NewUserValidator() UserDataValidator {
	return UserDataValidator{
		passwordrules: DefaultPasswordRules(),
		usernamerules: DefaultUsernameRules(),
	}
}
