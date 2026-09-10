package models

type PasswordRules struct {
	MinLength    int
	MinUppercase int
	MinLowercase int
	MinDigits    int
	MinSymbols   int
}
