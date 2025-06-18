package validation

import (
	"testing"

	"github.com/stretchr/testify/assert"
)



type emailTestCase struct {
	name   string
	email  string
	expect func(*testing.T, error)
}

func TestValidator_ValidateEmail(t *testing.T) {
	tests := []emailTestCase{
		{
			name:  "valid email",
			email: "test@example.com",
			expect: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:  "empty email",
			email: "",
			expect: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "email is required")
			},
		},
		{
			name:  "invalid email format - missing @",
			email: "testexample.com",
			expect: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid email format")
			},
		},
		{
			name:  "invalid email format - missing domain",
			email: "test@",
			expect: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid email format")
			},
		},
	}

	v := NewValidator()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := v.ValidateEmail(tc.email)
			tc.expect(t, err)
		})
	}
}

type passwordTestCase struct {
	name     string
	password string
	expect   func(*testing.T, error)
}

func TestValidator_ValidatePassword(t *testing.T) {
	tests := []passwordTestCase{
		{
			name:     "valid password",
			password: "ValidPass123",
			expect: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:     "password too short",
			password: "Short1",
			expect: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "password must be at least 8 characters")
			},
		},
		{
			name:     "missing uppercase",
			password: "lowercase123",
			expect: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "password must contain at least one uppercase letter")
			},
		},
		{
			name:     "missing lowercase",
			password: "UPPERCASE123",
			expect: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "password must contain at least one lowercase letter")
			},
		},
		{
			name:     "missing digit",
			password: "NoDigitsHere",
			expect: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "password must contain at least one digit")
			},
		},
	}

	v := NewValidator()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := v.ValidatePassword(tc.password)
			tc.expect(t, err)
		})
	}
}

type nameTestCase struct {
	name   string
	input  string
	field  string
	expect func(*testing.T, error)
}

func TestValidator_ValidateName(t *testing.T) {
	tests := []nameTestCase{
		{
			name:  "valid name",
			input: "John",
			field: "first_name",
			expect: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:  "empty name",
			input: "",
			field: "last_name",
			expect: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "last_name is required")
			},
		},
		{
			name:  "name too short",
			input: "A",
			field: "username",
			expect: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "username must be at least 2 characters")
			},
		},
		{
			name:  "name with spaces",
			input: "  John  ",
			field: "display_name",
			expect: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
	}

	v := NewValidator()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := v.ValidateName(tc.input, tc.field)
			tc.expect(t, err)
		})
	}
}
