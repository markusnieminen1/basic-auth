package models

type HashingManager interface {
	HashPassword(pwd string) (result string, err error)
	HashRefreshToken(token string) (result string, err error)
}
