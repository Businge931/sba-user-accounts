package validation

import (
	"regexp"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type Validator struct{}

func NewValidator() *Validator {
	return &Validator{}
}

func (v *Validator) ValidateRegisterRequest(req domain.RegisterRequest) error {
	return req.Validate()
}

func (v *Validator) ValidateLoginRequest(req domain.LoginRequest) error {
	return req.Validate()
}

func (v *Validator) ValidateEmail(email string) error {
	return validation.Validate(
		email,
		validation.Required,
		validation.Length(5, 255),
		is.Email,
	)
}

func (v *Validator) ValidatePassword(password string) error {
	return validation.Validate(
		password,
		validation.Required,
		validation.Length(8, 72),
	)
}

func (v *Validator) ValidateName(name, fieldName string) error {
	return validation.Validate(
		name,
		validation.Required.Error(fieldName+" is required"),
		validation.Length(2, 50).Error(fieldName+" must be between 2 and 50 characters"),
		validation.Match(regexp.MustCompile(`^[\p{L} -]+$`)).Error(fieldName+" contains invalid characters"),
	)
}
