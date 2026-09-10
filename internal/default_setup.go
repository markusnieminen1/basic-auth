package internal

const (
	// --------------
	// Headers
	// --------------
	ACCESS_TOKEN_NAME  = "Authorization"
	REFRESH_TOKEN_NAME = "X-Refresh-Token"

	// --------------
	// Password
	// --------------
	PWD_MinLength    = 10
	PWD_MinUppercase = 1
	PWD_MinLowercase = 1
	PWD_MinDigits    = 1
	PWD_MinSymbols   = 1

	// --------------
	// Username
	// --------------
	UName_MinLength         = 3
	UName_MaxLength         = 30
	UName_AllowSpecialChars = true
)
