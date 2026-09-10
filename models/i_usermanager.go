package models

type UserManager interface {
	NewUser(user User) (userId int, err error)
	ChangePassword(user User) (err error)
	ChangeEmail(user User) (err error)
	ChangeUsername(user User) (err error)
}
