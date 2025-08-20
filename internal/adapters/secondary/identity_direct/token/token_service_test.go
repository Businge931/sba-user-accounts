package token

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestJWTTokenService(t *testing.T) {
	// Set up common test data
	secret := []byte("test-jwt-secret-for-unit-tests")
	tokenExpiry := 1 * time.Hour

	// Create the standard token service for most tests
	tokenService := NewJWTTokenService(secret, tokenExpiry)

	// Create a token service with very short expiry for expiration tests
	shortExpiryTokenService := NewJWTTokenService(secret, 1*time.Nanosecond)

	// Test cases for token generation and validation
	tokenTests := []struct {
		name string
		deps struct {
			service interface {
				GenerateToken(userID string) (string, error)
				ValidateToken(token string) (string, error)
			}
		}
		args struct {
			userID string
		}
		before   func() (string, error)
		expected struct {
			token    string
			userID   string
			hasError bool
		}
	}{
		{
			name: "GenerateToken",
			deps: struct {
				service interface {
					GenerateToken(userID string) (string, error)
					ValidateToken(token string) (string, error)
				}
			}{service: tokenService},
			args: struct {
				userID string
			}{userID: "user123"},
			before: func() (string, error) {
				return tokenService.GenerateToken("user123")
			},
			expected: struct {
				token    string
				userID   string
				hasError bool
			}{
				token:    "",
				userID:   "",
				hasError: false,
			},
		},
		{
			name: "ValidateToken",
			deps: struct {
				service interface {
					GenerateToken(userID string) (string, error)
					ValidateToken(token string) (string, error)
				}
			}{service: tokenService},
			args: struct {
				userID string
			}{userID: "user123"},
			before: func() (string, error) {
				return tokenService.GenerateToken("user123")
			},
			expected: struct {
				token    string
				userID   string
				hasError bool
			}{
				token:    "",
				userID:   "user123",
				hasError: false,
			},
		},
		{
			name: "ValidateInvalidToken",
			deps: struct {
				service interface {
					GenerateToken(userID string) (string, error)
					ValidateToken(token string) (string, error)
				}
			}{service: tokenService},
			args: struct {
				userID string
			}{userID: ""},
			before: func() (string, error) {
				return "invalid.token.string", nil
			},
			expected: struct {
				token    string
				userID   string
				hasError bool
			}{
				token:    "",
				userID:   "",
				hasError: true,
			},
		},
		{
			name: "ValidateExpiredToken",
			deps: struct {
				service interface {
					GenerateToken(userID string) (string, error)
					ValidateToken(token string) (string, error)
				}
			}{service: shortExpiryTokenService},
			args: struct {
				userID string
			}{userID: "user123"},
			before: func() (string, error) {
				token, err := shortExpiryTokenService.GenerateToken("user123")
				time.Sleep(1 * time.Millisecond) // Let the token expire
				return token, err
			},
			expected: struct {
				token    string
				userID   string
				hasError bool
			}{
				token:    "",
				userID:   "",
				hasError: true,
			},
		},
	}

	// Run the token generation and validation tests
	for _, tc := range tokenTests {
		t.Run(tc.name, func(t *testing.T) {
			// Generate the token using the before function
			token, err := tc.before()

			if !tc.expected.hasError {
				assert.NoError(t, err)
				assert.NotEmpty(t, token)
			}

			// Validate the token if we have one
			if token != "" {
				userID, err := tc.deps.service.ValidateToken(token)

				if tc.expected.hasError {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
					if tc.expected.userID != "" {
						assert.Equal(t, tc.expected.userID, userID)
					}
				}
			}
		})
	}

	// Table-driven tests for utility token generation
	utilityTokenTests := []struct {
		name string
		deps struct {
			service interface {
				GenerateVerificationToken() string
				GenerateResetToken() string
			}
		}
		args     struct{}
		before   func() string
		expected struct {
			tokenNotEmpty bool
		}
	}{
		{
			name: "GenerateVerificationToken",
			deps: struct {
				service interface {
					GenerateVerificationToken() string
					GenerateResetToken() string
				}
			}{service: tokenService},
			args: struct{}{},
			before: func() string {
				return tokenService.GenerateVerificationToken()
			},
			expected: struct {
				tokenNotEmpty bool
			}{
				tokenNotEmpty: true,
			},
		},
		{
			name: "GenerateResetToken",
			deps: struct {
				service interface {
					GenerateVerificationToken() string
					GenerateResetToken() string
				}
			}{service: tokenService},
			args: struct{}{},
			before: func() string {
				return tokenService.GenerateResetToken()
			},
			expected: struct {
				tokenNotEmpty bool
			}{
				tokenNotEmpty: true,
			},
		},
	}

	// Run the utility token tests
	for _, tc := range utilityTokenTests {
		t.Run(tc.name, func(t *testing.T) {
			// Generate the token
			token := tc.before()

			// Assert token is not empty if expected
			if tc.expected.tokenNotEmpty {
				assert.NotEmpty(t, token)
			}
		})
	}
}
