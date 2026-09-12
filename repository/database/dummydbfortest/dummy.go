package dummydbfortest

import (
	"context"
	"database/sql"

	"github.com/markusnieminen1/basic-auth/models"
)

type UserManagerRepo struct {
	db *sql.DB
}

func (umr *UserManagerRepo) CreateUser(ctx context.Context, user models.AllUserProfileAuthData) (userID int64, err error) {
	return 1, nil
}

func (umr *UserManagerRepo) GetUserByID(ctx context.Context, userID int64) (user *models.LimitedUserAuthData, err error) {
	return &models.LimitedUserAuthData{UserID: 1, Email: "Yes@hive.com", Username: "HiveStudent"}, nil
}

func (umr *UserManagerRepo) DeleteUser(ctx context.Context, userID int64) (err error) {
	return nil
}

func (umr *UserManagerRepo) ChangePwd(ctx context.Context, user models.AllUserProfileAuthData) (err error) {
	return nil
}

func (umr *UserManagerRepo) ChangeEmail(ctx context.Context, user models.AllUserProfileAuthData) (err error) {
	return nil
}

func (umr *UserManagerRepo) ChangeUsername(ctx context.Context, user models.AllUserProfileAuthData) (err error) {
	return nil
}
