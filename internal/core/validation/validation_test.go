package validation

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidator_ValidateEmail(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		hasError bool
		errMsg   string
	}{
		{
			name:     "valid email",
			email:    "test@example.com",
			hasError: false,
			errMsg:   "",
		},
		{
			name:     "empty email",
			email:    "",
			hasError: true,
			errMsg:   "email is required",
		},
		{
			name:     "invalid email format - missing @",
			email:    "testexample.com",
			hasError: true,
			errMsg:   "invalid email format",
		},
		{
			name:     "invalid email format - missing domain",
			email:    "test@",
			hasError: true,
			errMsg:   "invalid email format",
		},
	}

	v := NewValidator()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateEmail(tt.email)
			if tt.hasError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		errMsg   string
		hasError bool
	}{
		{
			name:     "valid password",
			password: "ValidPass123",
			errMsg:   "",
			hasError: false,
		},
		{
			name:     "password too short",
			password: "Short1",
			errMsg:   "password must be at least 8 characters",
			hasError: true,
		},
		{
			name:     "missing uppercase",
			password: "lowercase123",
			errMsg:   "password must contain at least one uppercase letter",
			hasError: true,
		},
		{
			name:     "missing lowercase",
			password: "UPPERCASE123",
			errMsg:   "password must contain at least one lowercase letter",
			hasError: true,
		},
		{
			name:     "missing digit",
			password: "NoDigitsHere",
			errMsg:   "password must contain at least one digit",
			hasError: true,
		},
	}

	v := NewValidator()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidatePassword(tt.password)
			if tt.hasError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidateName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		field    string
		errMsg   string
		hasError bool
	}{
		{
			name:     "valid name",
			input:    "John",
			field:    "first_name",
			errMsg:   "",
			hasError: false,
		},
		{
			name:     "empty name",
			input:    "",
			field:    "last_name",
			errMsg:   "last_name is required",
			hasError: true,
		},
		{
			name:     "name too short",
			input:    "A",
			field:    "username",
			errMsg:   "username must be at least 2 characters",
			hasError: true,
		},
		{
			name:     "name with spaces",
			input:    "  John  ",
			field:    "display_name",
			errMsg:   "",
			hasError: false,
		},
	}

	v := NewValidator()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateName(tt.input, tt.field)
			if tt.hasError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
