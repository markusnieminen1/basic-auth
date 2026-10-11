package sharedmodels

import "net/http"

// AllUserProfileAuthData is the full stored user. It is never sent to clients,
// and only the password hash is kept, never the plain password.
type AllUserProfileAuthData struct {
	UserID       int64  `json:"user_id"`
	Email        string `json:"user_email"`
	PasswordHash string `json:"-"`
	Username     string `json:"user_username"`
}

type LimitedUserAuthData struct {
	UserID   int64  `json:"user_id"`
	Email    string `json:"user_email"`
	Username string `json:"user_username"`
}

type AuthCookies struct {
	AccessToken  *http.Cookie
	RefreshToken *http.Cookie
	UserID       *int64
}

// Inputs. These are decoded straight from request bodies, so a UserID is tagged
// json:"-": it comes from the validated access token, never from the client.

type RegisterInput struct {
	Email    string `json:"register_email"`
	Username string `json:"register_username"`
	Password string `json:"register_password"`
}

type LoginInput struct {
	Username string `json:"login_username"`
	Password string `json:"login_password"`
}

type UpdateEmailInput struct {
	UserID   int64  `json:"-"`
	Email    string `json:"update_email_email"`
	Password string `json:"update_email_password"` // current password, required to change account information
}

type UpdateUsernameInput struct {
	UserID   int64  `json:"-"`
	Username string `json:"update_username_username"`
	Password string `json:"update_username_password"` // current password, required to change account information
}

type ChangePasswordInput struct {
	UserID      int64  `json:"-"`
	Current     string `json:"change_password_current"`
	Replacement string `json:"change_password_new"`
}
