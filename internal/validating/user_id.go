package validating

import "github.com/markusnieminen1/basic-auth/repository/customerrors"

func (u *UserDataValidator) ValidateUserID(id int64) error {
	if id < 1 {
		return customerrors.ErrIDNegative
	}

	return nil
}
