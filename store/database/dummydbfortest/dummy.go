package dummydbfortest

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/markusnieminen1/basic-auth/domain/sharedmodels"
	"github.com/markusnieminen1/basic-auth/setup"
)

type UserManagerRepo struct {
	db *sql.DB
}

func (umr *UserManagerRepo) NewUser(ctx context.Context, user sharedmodels.AllUserProfileAuthData) (session sharedmodels.AuthCookies, err error) {

	refresh := http.Cookie{
		Name:     setup.REFRESH_TOKEN_NAME,
		Value:    "long_value_yes",
		Path:     "/",
		Expires:  time.Time.Add(time.Now(), time.Hour*24*time.Duration(setup.REFRESH_TOKEN_EXPIRY_DAYS)),
		HttpOnly: true,
		Secure:   true}

	access := http.Cookie{
		Name:     setup.ACCESS_TOKEN_NAME,
		Value:    "long_JWT_value_yes",
		Path:     "/",
		Expires:  time.Time.Add(time.Now(), time.Minute*5),
		HttpOnly: true,
		Secure:   true}

	userID := int64(123)

	return sharedmodels.AuthCookies{AccessToken: &access, RefreshToken: &refresh, UserID: &userID}, nil
}

func (umr *UserManagerRepo) GetUserByID(ctx context.Context, userID int64) (user sharedmodels.LimitedUserAuthData, err error) {
	return sharedmodels.LimitedUserAuthData{UserID: 123, Email: "Yes@hive.com", Username: "HiveStudent"}, nil
}

func (umr *UserManagerRepo) DeleteUser(ctx context.Context, userID int64) (session sharedmodels.AuthCookies, err error) {
	refresh := http.Cookie{
		Name:     setup.REFRESH_TOKEN_NAME,
		Value:    "long_UUID_value_yes",
		Path:     "/",
		Expires:  time.Time.Add(time.Now(), -time.Hour*24*time.Duration(setup.REFRESH_TOKEN_EXPIRY_DAYS)),
		HttpOnly: true,
		Secure:   true}

	access := http.Cookie{
		Name:     setup.ACCESS_TOKEN_NAME,
		Value:    "long_JWT_value_yes",
		Path:     "/",
		Expires:  time.Time.Add(time.Now(), -time.Minute*5),
		HttpOnly: true,
		Secure:   true}

	return sharedmodels.AuthCookies{AccessToken: &access, RefreshToken: &refresh}, nil
}

func (umr *UserManagerRepo) ChangePassword(ctx context.Context, user sharedmodels.AllUserProfileAuthData) (session sharedmodels.AuthCookies, err error) {

	refresh := http.Cookie{
		Name:     setup.REFRESH_TOKEN_NAME,
		Value:    "long_value_yes",
		Path:     "/",
		Expires:  time.Time.Add(time.Now(), time.Hour*24*time.Duration(setup.REFRESH_TOKEN_EXPIRY_DAYS)),
		HttpOnly: true,
		Secure:   true}

	access := http.Cookie{
		Name:     setup.ACCESS_TOKEN_NAME,
		Value:    "long_JWT_value_yes",
		Path:     "/",
		Expires:  time.Time.Add(time.Now(), time.Minute*5),
		HttpOnly: true,
		Secure:   true}

	userID := int64(123)

	return sharedmodels.AuthCookies{AccessToken: &access, RefreshToken: &refresh, UserID: &userID}, nil
}

func (umr *UserManagerRepo) ChangeEmail(ctx context.Context, user sharedmodels.AllUserProfileAuthData) (session sharedmodels.AuthCookies, err error) {

	refresh := http.Cookie{
		Name:     setup.REFRESH_TOKEN_NAME,
		Value:    "long_value_yes",
		Path:     "/",
		Expires:  time.Time.Add(time.Now(), time.Hour*24*time.Duration(setup.REFRESH_TOKEN_EXPIRY_DAYS)),
		HttpOnly: true,
		Secure:   true}

	access := http.Cookie{
		Name:     setup.ACCESS_TOKEN_NAME,
		Value:    "long_JWT_value_yes",
		Path:     "/",
		Expires:  time.Time.Add(time.Now(), time.Minute*5),
		HttpOnly: true,
		Secure:   true}

	userID := int64(123)

	return sharedmodels.AuthCookies{AccessToken: &access, RefreshToken: &refresh, UserID: &userID}, nil
}

func (umr *UserManagerRepo) ChangeUsername(ctx context.Context, user sharedmodels.AllUserProfileAuthData) (session sharedmodels.AuthCookies, err error) {

	refresh := http.Cookie{
		Name:     setup.REFRESH_TOKEN_NAME,
		Value:    "long_value_yes",
		Path:     "/",
		Expires:  time.Time.Add(time.Now(), time.Hour*24*time.Duration(setup.REFRESH_TOKEN_EXPIRY_DAYS)),
		HttpOnly: true,
		Secure:   true}

	access := http.Cookie{
		Name:     setup.ACCESS_TOKEN_NAME,
		Value:    "long_JWT_value_yes",
		Path:     "/",
		Expires:  time.Time.Add(time.Now(), time.Minute*5),
		HttpOnly: true,
		Secure:   true}

	userID := int64(123)

	return sharedmodels.AuthCookies{AccessToken: &access, RefreshToken: &refresh, UserID: &userID}, nil
}

func NewUserManagerRepo() *UserManagerRepo {
	return &UserManagerRepo{}
}
