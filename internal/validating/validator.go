package validating

type UserDataValidator struct {
	passwordrules PasswordRules
	usernamerules UsernameRules
}

func NewUserValidatorDefaultSetup() UserDataValidator {
	return UserDataValidator{
		passwordrules: NewDefaultPasswordRules(),
		usernamerules: NewDefaultUsernameRules(),
	}
}
