package models

type AllUserProfileAuthData struct {
	UserID        int64  `json:"user_id"`
	Email         string `json:"user_email"`
	PasswordPlain string `json:"user_pwd"`
	PasswordHash  string `json:"user_pwd_hash"`
	Username      string `json:"user_username"`
}
