package models

import "context"

type UserManager interface {
	NewUser(ctx context.Context, user AllUserProfileAuthData) (userId int64, err error)
	ChangePassword(ctx context.Context, user AllUserProfileAuthData) (err error)
	ChangeEmail(ctx context.Context, user AllUserProfileAuthData) (err error)
	ChangeUsername(ctx context.Context, user AllUserProfileAuthData) (err error)
}
