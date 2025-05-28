package validation

import (
	"regexp"
	"strings"

	"github.com/Businge931/sba-user-accounts/internal/core/errors"
)

type Validator struct{}

func NewValidator() *Validator {
	return &Validator{}
}

func (v *Validator) ValidateEmail(email string) error {
	email = strings.TrimSpace(email)
	if email == "" {
		return errors.NewInvalidInputError("email is required", nil)
	}

	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return errors.NewInvalidInputError("invalid email format", nil)
	}

	return nil
}

func (v *Validator) ValidatePassword(password string) error {
	if len(password) < 8 {
		return errors.NewInvalidInputError("password must be at least 8 characters", nil)
	}

	// Check for at least one uppercase letter
	uppercaseRegex := regexp.MustCompile(`[A-Z]`)
	if !uppercaseRegex.MatchString(password) {
		return errors.NewInvalidInputError("password must contain at least one uppercase letter", nil)
	}

	// Check for at least one lowercase letter
	lowercaseRegex := regexp.MustCompile(`[a-z]`)
	if !lowercaseRegex.MatchString(password) {
		return errors.NewInvalidInputError("password must contain at least one lowercase letter", nil)
	}

	// Check for at least one digit
	digitRegex := regexp.MustCompile(`\d`)
	if !digitRegex.MatchString(password) {
		return errors.NewInvalidInputError("password must contain at least one digit", nil)
	}

	return nil
}

func (v *Validator) ValidateName(name, fieldName string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.NewInvalidInputError(fieldName+" is required", nil)
	}

	if len(name) < 2 {
		return errors.NewInvalidInputError(fieldName+" must be at least 2 characters", nil)
	}

	return nil
}
