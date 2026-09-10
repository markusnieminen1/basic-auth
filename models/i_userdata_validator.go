package models

type UserDataValidator interface {
	VerifyEmail(string) error
	VerifyUsername(string) error
	VerifyPassword(string) error
}
