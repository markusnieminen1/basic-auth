package service

import (
	"context"

	"github.com/markusnieminen1/basic-auth/internal/validating"
	"github.com/markusnieminen1/basic-auth/models"
)

type UserManagerService struct {
	UserValidator  validating.UserDataValidator
	UserRepository models.UserManagerDatabase
	Crypto         string // Interface for hashing
}

func (u *UserManagerService) NewUser(ctx context.Context, user models.AllUserProfileAuthData) (userId int64, err error) {

	if err = u.UserValidator.ValidateEmail(user.Email); err != nil {
		return
	}

	if err = u.UserValidator.ValidatePassword(user.PasswordPlain); err != nil {
		return
	}

	if err = u.UserValidator.ValidateUsername(user.Username); err != nil {
		return
	}

	user.PasswordHash = "reallygoodhashyesyes" // TODO: Add crypto and Hash password here
	user.PasswordPlain = ""

	userId, err = u.UserRepository.CreateUser(ctx, user)

	return

}

func (u *UserManagerService) ChangePassword(ctx context.Context, user models.AllUserProfileAuthData) (err error) {

	if err = u.UserValidator.ValidateUserID(user.UserID); err != nil {
		return
	}

	if err = u.UserValidator.ValidatePassword(user.PasswordPlain); err != nil {
		return
	}

	err = u.UserRepository.ChangePwd(ctx, user)

	return

}

func (u *UserManagerService) ChangeEmail(ctx context.Context, user models.AllUserProfileAuthData) (err error) {

	if err = u.UserValidator.ValidateUserID(user.UserID); err != nil {
		return
	}

	if err = u.UserValidator.ValidateEmail(user.Email); err != nil {
		return
	}

	err = u.UserRepository.ChangeEmail(ctx, user)

	return

}

func (u *UserManagerService) ChangeUsername(ctx context.Context, user models.AllUserProfileAuthData) (err error) {

	if err = u.UserValidator.ValidateUserID(user.UserID); err != nil {
		return
	}

	if err = u.UserValidator.ValidateUsername(user.Username); err != nil {
		return
	}

	err = u.UserRepository.ChangeUsername(ctx, user)

	return

}

func (u *UserManagerService) GetUserByID(ctx context.Context, user_id int64) (user *models.LimitedUserAuthData, err error) {

	if err = u.UserValidator.ValidateUserID(user_id); err != nil {
		return
	}

	user, err = u.UserRepository.GetUserByID(ctx, user_id)

	return

}

func (u *UserManagerService) DeleteUser(ctx context.Context, user_id int64) (err error) {

	if err = u.UserValidator.ValidateUserID(user_id); err != nil {
		return
	}

	err = u.UserRepository.DeleteUser(ctx, user_id)

	return

}
