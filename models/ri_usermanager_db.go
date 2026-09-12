package models

import (
	"context"
)

type UserManagerDatabase interface {
	// Usermanager
	CreateUser(ctx context.Context, user AllUserProfileAuthData) (userID int64, err error)
	GetUserByID(ctx context.Context, userID int64) (user *LimitedUserAuthData, err error)
	DeleteUser(ctx context.Context, userID int64) (err error)

	ChangePwd(ctx context.Context, user AllUserProfileAuthData) (err error)
	ChangeEmail(ctx context.Context, user AllUserProfileAuthData) (err error)
	ChangeUsername(ctx context.Context, user AllUserProfileAuthData) (err error)
}
