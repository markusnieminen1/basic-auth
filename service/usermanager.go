package service

import (
	"github.com/markusnieminen1/basic-auth/internal/validating"
	"github.com/markusnieminen1/basic-auth/models"
)

type UserManagerService struct {
	UserValidator  validating.UserDataValidator
	UserRepository string
}

func (u *UserManagerService) NewUser(user models.User) (userId int, err error) {

	if err = u.UserValidator.ValidateEmail(user.Email); err != nil {
		return
	}

	if err = u.UserValidator.ValidatePassword(user.Password); err != nil {
		return
	}

	if err = u.UserValidator.ValidateUsername(user.Username); err != nil {
		return
	}

	// Call repo layer

	return 1, nil

}

func (u *UserManagerService) ChangePassword(user models.User) (err error) {

	if err = u.UserValidator.ValidateUserID(user.UserID); err != nil {
		return
	}

	if err = u.UserValidator.ValidatePassword(user.Password); err != nil {
		return
	}

	// Call repo layer

	return nil

}

func (u *UserManagerService) ChangeEmail(user models.User) (err error) {

	if err = u.UserValidator.ValidateUserID(user.UserID); err != nil {
		return
	}

	if err = u.UserValidator.ValidateEmail(user.Email); err != nil {
		return
	}

	// Call repo layer

	return nil

}

func (u *UserManagerService) ChangeUsername(user models.User) (err error) {

	if err = u.UserValidator.ValidateUserID(user.UserID); err != nil {
		return
	}

	if err = u.UserValidator.ValidateUsername(user.Username); err != nil {
		return
	}

	// Call repo layer

	return nil

}
