package models

type CookieManager interface {
	NewRefreshToken(userId int) (token string, err error)
	NewAccessToken(userId int) (token string, err error)
	RevokeRefreshToken(token string) (err error)
	RevokeAllRefreshTokens(userId int) (err error)
}
