package unit

import (
	"testing"
	"time"

	"github.com/Businge931/sba-user-accounts/internal/core/services"
	"github.com/stretchr/testify/assert"
)

func TestJWTTokenService(t *testing.T) {
	// Set up common test data
	secret := []byte("test-jwt-secret-for-unit-tests")
	tokenExpiry := 1 * time.Hour
	
	// Create the standard token service for most tests
	tokenService := services.NewJWTTokenService(secret, tokenExpiry)
	
	// Create a token service with very short expiry for expiration tests
	shortExpiryTokenService := services.NewJWTTokenService(secret, 1*time.Nanosecond)
	
	// Test cases for token generation and validation
	tokenTests := []struct {
		name           string
		action         func() (string, error)
		validation     func(string) (string, error)
		expectError    bool
		expectedUserID string
	}{
		{
			name: "GenerateToken",
			action: func() (string, error) {
				return tokenService.GenerateToken("user123")
			},
			validation: func(token string) (string, error) {
				// For generation test, we don't need to validate
				return "", nil
			},
			expectError:    false,
			expectedUserID: "",
		},
		{
			name: "ValidateToken",
			action: func() (string, error) {
				return tokenService.GenerateToken("user123")
			},
			validation: func(token string) (string, error) {
				return tokenService.ValidateToken(token)
			},
			expectError:    false,
			expectedUserID: "user123",
		},
		{
			name: "ValidateInvalidToken",
			action: func() (string, error) {
				return "invalid.token.string", nil
			},
			validation: func(token string) (string, error) {
				return tokenService.ValidateToken(token)
			},
			expectError:    true,
			expectedUserID: "",
		},
		{
			name: "ValidateExpiredToken",
			action: func() (string, error) {
				token, err := shortExpiryTokenService.GenerateToken("user123")
				time.Sleep(1 * time.Millisecond) // Let the token expire
				return token, err
			},
			validation: func(token string) (string, error) {
				return shortExpiryTokenService.ValidateToken(token)
			},
			expectError:    true,
			expectedUserID: "",
		},
	}
	
	// Run the token generation and validation tests
	for _, tc := range tokenTests {
		t.Run(tc.name, func(t *testing.T) {
			// Generate the token
			token, err := tc.action()
			
			if !tc.expectError {
				assert.NoError(t, err)
				assert.NotEmpty(t, token)
			}
			
			// If a validation function is provided, use it
			if tc.validation != nil && token != "" {
				// Validate the token
				userID, err := tc.validation(token)
				
				if tc.expectError {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
					if tc.expectedUserID != "" {
						assert.Equal(t, tc.expectedUserID, userID)
					}
				}
			}
		})
	}
	
	// Table-driven tests for utility token generation
	utilityTokenTests := []struct {
		name       string
		generation func() string
	}{
		{
			name: "GenerateVerificationToken",
			generation: func() string {
				return tokenService.GenerateVerificationToken()
			},
		},
		{
			name: "GenerateResetToken",
			generation: func() string {
				return tokenService.GenerateResetToken()
			},
		},
	}
	
	// Run the utility token tests
	for _, tc := range utilityTokenTests {
		t.Run(tc.name, func(t *testing.T) {
			// Generate the token
			token := tc.generation()
			
			// Assert token is not empty
			assert.NotEmpty(t, token)
		})
	}
}
