package validation

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidator_ValidateEmail(t *testing.T) {
	// Define test arguments
	type args struct {
		email string
	}

	tests := []struct {
		name     string
		args     args
		wantErr  bool
		errMsg   string
	}{
		{
			name: "valid email",
			args: args{
				email: "test@example.com",
			},
			wantErr: false,
			errMsg:   "",
		},
		{
			name: "empty email",
			args: args{
				email: "",
			},
			wantErr: true,
			errMsg:   "email is required",
		},
		{
			name: "invalid email format - missing @",
			args: args{
				email: "testexample.com",
			},
			wantErr: true,
			errMsg:   "invalid email format",
		},
		{
			name: "invalid email format - missing domain",
			args: args{
				email: "test@",
			},
			wantErr: true,
			errMsg:   "invalid email format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize validator
			v := NewValidator()
			// Execute
			err := v.ValidateEmail(tt.args.email)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidatePassword(t *testing.T) {
	// Define test arguments
	type args struct {
		password string
	}

	tests := []struct {
		name     string
		args     args
		wantErr  bool
		errMsg   string
	}{
		{
			name: "valid password",
			args: args{
				password: "ValidPass123",
			},
			wantErr: false,
			errMsg:   "",
		},
		{
			name: "password too short",
			args: args{
				password: "Short1",
			},
			wantErr: true,
			errMsg:   "password must be at least 8 characters",
		},
		{
			name: "missing uppercase",
			args: args{
				password: "lowercase123",
			},
			wantErr: true,
			errMsg:   "password must contain at least one uppercase letter",
		},
		{
			name: "missing lowercase",
			args: args{
				password: "UPPERCASE123",
			},
			wantErr: true,
			errMsg:   "password must contain at least one lowercase letter",
		},
		{
			name: "missing digit",
			args: args{
				password: "NoDigitsHere",
			},
			wantErr: true,
			errMsg:   "password must contain at least one digit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize validator
			v := NewValidator()
			// Execute
			err := v.ValidatePassword(tt.args.password)
			if tt.wantErr {
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
