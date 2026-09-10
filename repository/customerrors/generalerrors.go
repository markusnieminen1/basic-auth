package customerrors

import "errors"

var (
	// ----------------
	// VALIDATOR ERRORS
	// ----------------
	// Email
	ErrEmailEmpty   = errors.New("email address cannot be empty")
	ErrEmailTooLong = errors.New("email address exceeds maximum length of 254 characters")
	ErrEmailInvalid = errors.New("invalid email address format")
	// Password
	ErrPasswordEmpty       = errors.New("password cannot be empty")
	ErrPasswordTooShort    = errors.New("password does not meet the minimum length requirement")
	ErrPasswordTooLong     = errors.New("password cannot exceed 72 bytes")
	ErrPasswordNeedsUpper  = errors.New("password does not contain enough uppercase letters")
	ErrPasswordNeedsLower  = errors.New("password does not contain enough lowercase letters")
	ErrPasswordNeedsDigit  = errors.New("password does not contain enough numbers")
	ErrPasswordNeedsSymbol = errors.New("password does not contain enough special characters")
	// Username
	ErrUsernameEmpty       = errors.New("username cannot be empty")
	ErrUsernameTooShort    = errors.New("username is below the minimum length")
	ErrUsernameTooLong     = errors.New("username exceeds the maximum length")
	ErrUsernameInvalidChar = errors.New("username contains invalid characters (only alphanumeric, underscores, or hyphens allowed)")
	// User ID
	ErrIDNegative = errors.New("user id cannot be negative")
)
