package database

import "github.com/markusnieminen1/basic-auth/models"

type GeneralManager interface {
	PermissionsManager
	CookieManager
	UserManager
	Auth
}

type PermissionsManager interface {
	ListAllPermissions(userId int) (permissions []models.Permission, err error)
	Add(userId int, permissionToAdd models.Permission) (err error)
	Remove(userId int, permissionToRemove models.Permission) (err error)
}

type CookieManager interface {
	NewRefreshToken(userId int) (token string, err error)
	NewAccessToken(userId int) (token string, err error)
	RevokeRefreshToken(token string) (err error)
	RevokeAllRefreshTokens(userId int) (err error)
}

type UserManager interface {
	NewUser(username, email, password string) (userId int, err error)
	ChangePassword(userId int, newPassword string) (err error)
	ChangeEmail(userId int, newEmail string) (err error)
	ChangeUsername(userId int, newUsername string) (err error)
}

type Auth interface {
	Login(email, password string) (refresh_token string, err error)
	Logout(refresh_token string) (err error)
	ValidateAccessToken(accessToken string) (valid bool, err error)
}
