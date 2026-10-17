package validating

import (
	"errors"
	"testing"

	"github.com/markusnieminen1/basic-auth/domain/customerrors"
)

func TestPasswordForbiddenChars(t *testing.T) {
	v := NewUserValidatorDefaultSetup()
	v.passwordrules.ForbiddenChars = " <>"

	for _, bad := range []string{"Sup3r secret!", "Sup3r-secret!<", "Sup3r>secret!"} {
		if err := v.ValidatePassword(bad); !errors.Is(err, customerrors.ErrPasswordForbiddenChar) {
			t.Errorf("%q: got %v, want ErrPasswordForbiddenChar", bad, err)
		}
	}
	if err := v.ValidatePassword("Sup3r-secret!"); err != nil {
		t.Errorf("valid password rejected: %v", err)
	}

	v.passwordrules.ForbiddenChars = ""
	if err := v.ValidatePassword("Sup3r secret!"); err != nil {
		t.Errorf("with nothing forbidden a space is fine, got %v", err)
	}
}

func TestPasswordDefaultsForbidSpaces(t *testing.T) {
	v := NewUserValidatorDefaultSetup()
	if err := v.ValidatePassword("Sup3r secret!"); !errors.Is(err, customerrors.ErrPasswordForbiddenChar) {
		t.Errorf("got %v, want ErrPasswordForbiddenChar", err)
	}
}

func TestUsernameForbiddenChars(t *testing.T) {
	v := NewUserValidatorDefaultSetup()
	v.usernamerules.ForbiddenChars = "-x"

	for _, bad := range []string{"al-ice", "alxce"} {
		if err := v.ValidateUsername(bad); !errors.Is(err, customerrors.ErrUsernameForbiddenChar) {
			t.Errorf("%q: got %v, want ErrUsernameForbiddenChar", bad, err)
		}
	}
	// "_" is allowed by the character rules and not forbidden, so it still passes.
	if err := v.ValidateUsername("al_ice"); err != nil {
		t.Errorf("valid username rejected: %v", err)
	}
	// Characters outside the allowed set keep their own error.
	if err := v.ValidateUsername("al ice"); !errors.Is(err, customerrors.ErrUsernameInvalidChar) {
		t.Errorf("got %v, want ErrUsernameInvalidChar", err)
	}
}
