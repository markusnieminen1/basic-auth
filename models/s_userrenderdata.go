package models

type LimitedUserAuthData struct {
	UserID   int64  `json:"user_id"`
	Email    string `json:"user_email"`
	Username string `json:"user_username"`
}
