package models

type UserManager interface {
	NewUser(username, email, password string) (userId int, err error)
	ChangePassword(userId int, newPassword string) (err error)
	ChangeEmail(userId int, newEmail string) (err error)
	ChangeUsername(userId int, newUsername string) (err error)
}
