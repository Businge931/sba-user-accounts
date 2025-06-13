package validation

import (
	"regexp"
	"strings"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/Businge931/sba-user-accounts/internal/core/errors"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type Validator struct{}

func NewValidator() *Validator {
	return &Validator{}
}

func (v *Validator) ValidateRegisterRequest(req domain.RegisterRequest) error {
	if err := v.ValidateEmail(req.Email); err != nil {
		return err
	}
	if err := v.ValidatePassword(req.Password); err != nil {
		return err
	}
	if err := v.ValidateName(req.FirstName, "first name"); err != nil {
		return err
	}
	if err := v.ValidateName(req.LastName, "last name"); err != nil {
		return err
	}
	return nil
}

func (v *Validator) ValidateLoginRequest(req domain.LoginRequest) error {
	if err := v.ValidateEmail(req.Email); err != nil {
		return err
	}
	if err := v.ValidatePassword(req.Password); err != nil {
		return err
	}
	return nil
}

func (v *Validator) ValidateEmail(email string) error {
	email = strings.TrimSpace(email)
	err := validation.Validate(email,
		validation.Required.Error("email is required"),
		is.EmailFormat.Error("invalid email format"),
	)
	if err != nil {
		return errors.NewInvalidInputError(err.Error(), nil)
	}
	return nil
}

func (v *Validator) ValidatePassword(password string) error {
	err := validation.Validate(password,
		validation.Required.Error("password is required"),
		validation.Length(8, 0).Error("password must be at least 8 characters"),
		validation.Match(regexp.MustCompile(`[A-Z]`)).Error("password must contain at least one uppercase letter"),
		validation.Match(regexp.MustCompile(`[a-z]`)).Error("password must contain at least one lowercase letter"),
		validation.Match(regexp.MustCompile(`\d`)).Error("password must contain at least one digit"),
	)
	if err != nil {
		return errors.NewInvalidInputError(err.Error(), nil)
	}
	return nil
}

func (v *Validator) ValidateName(name, fieldName string) error {
	name = strings.TrimSpace(name)
	err := validation.Validate(name,
		validation.Required.Error(fieldName+" is required"),
		validation.Length(2, 0).Error(fieldName+" must be at least 2 characters"),
	)
	if err != nil {
		return errors.NewInvalidInputError(err.Error(), nil)
	}
	return nil
}
