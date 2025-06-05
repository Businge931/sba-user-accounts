package env

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)


func TestGetEnv(t *testing.T) {
	tests := []struct {
		name     string
		envKey   string
		envValue string
		fallback string
		expected string
	}{
		{
			name:     "environment variable exists",
			envKey:   "TEST_KEY",
			envValue: "test_value",
			fallback: "default_value",
			expected: "test_value",
		},
		{
			name:     "environment variable does not exist",
			envKey:   "NON_EXISTENT_KEY",
			envValue: "",
			fallback: "default_value",
			expected: "default_value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				os.Setenv(tt.envKey, tt.envValue)
				defer os.Unsetenv(tt.envKey)
			}

			result := GetEnv(tt.envKey, tt.fallback)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetInt(t *testing.T) {
	tests := []struct {
		name     string
		envKey   string
		envValue string
		fallback int
		expected int
	}{
		{
			name:     "valid integer environment variable",
			envKey:   "TEST_INT",
			envValue: "42",
			fallback: 0,
			expected: 42,
		},
		{
			name:     "invalid integer environment variable",
			envKey:   "INVALID_INT",
			envValue: "not_an_int",
			fallback: 100,
			expected: 100,
		},
		{
			name:     "environment variable does not exist",
			envKey:   "NON_EXISTENT_INT",
			envValue: "",
			fallback: 200,
			expected: 200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				os.Setenv(tt.envKey, tt.envValue)
				defer os.Unsetenv(tt.envKey)
			}

			result := GetInt(tt.envKey, tt.fallback)
			assert.Equal(t, tt.expected, result)
		})
	}
}