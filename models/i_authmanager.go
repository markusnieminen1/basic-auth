package models

type AuthManager interface {
	Login(email, password string) (refresh_token string, err error)
	Logout(refresh_token string) (err error)
	ValidateAccessToken(accessToken string) (valid bool, err error)
}
