package models

type SessionByUsers struct {
	Session RefreshToken
	User    LimitedUserAuthData
}
