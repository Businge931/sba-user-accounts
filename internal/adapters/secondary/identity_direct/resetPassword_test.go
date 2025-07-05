package identity

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestIdentityProvider_ResetPasswordSvc(t *testing.T) {
	// Save original hash function
	oldHashPassword := hashPassword
	t.Cleanup(func() { hashPassword = oldHashPassword })

	// Helper to generate a bcrypt hash for test passwords
	hashPasswordHelper := func(password string) string {
		hash, err := hashPassword(password)
		require.NoError(t, err)
		return hash
	}

	tests := []resetPasswordTestCase{
		{
			name: "successful password reset",
			args: resetPasswordArgs{
				token:       "valid-reset-token",
				newPassword: "new-secure-password",
			},
			expect: resetPasswordExpectations{
				hashedPassword: hashPasswordHelper("new-secure-password"),
				userID:         "user-123",
			},
			before: func(t *testing.T, d *resetPasswordDependencies, args resetPasswordArgs) {
				d.authRepo.On("GetUserIDByResetToken", args.token).
					Return("user-123", nil).
					Once()
			},
			after: func(t *testing.T, d *resetPasswordDependencies) {
				d.authRepo.AssertExpectations(t)
			},
		},
		{
			name: "returns error when token is invalid",
			args: resetPasswordArgs{
				token:       "invalid-token",
				newPassword: "new-password",
			},
			expect: resetPasswordExpectations{
				err: errors.New("invalid or expired token"),
			},
			before: func(t *testing.T, d *resetPasswordDependencies, args resetPasswordArgs) {
				d.authRepo.On("GetUserIDByResetToken", args.token).
					Return("", errors.New("token not found")).
					Once()
				d.logger.On("Warnf", "Password reset failed due to invalid token: %v", mock.Anything).Once()
			},
			after: func(t *testing.T, d *resetPasswordDependencies) {
				d.authRepo.AssertExpectations(t)
				d.logger.AssertExpectations(t)
			},
		},
		{
			name: "returns error when password hashing fails",
			args: resetPasswordArgs{
				token:       "valid-reset-token",
				newPassword: "new-password",
			},
			expect: resetPasswordExpectations{
				err: errors.New("failed to hash password"),
			},
			before: func(t *testing.T, d *resetPasswordDependencies, args resetPasswordArgs) {
				d.authRepo.On("GetUserIDByResetToken", args.token).
					Return("user-123", nil).
					Once()
				// Replace the hash function with one that returns an error
				hashPassword = func(string) (string, error) {
					return "", errors.New("hashing error")
				}
				t.Cleanup(func() { hashPassword = oldHashPassword })
			},
			after: func(t *testing.T, d *resetPasswordDependencies) {
				d.authRepo.AssertExpectations(t)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, deps := setupResetPasswordTest(t)

			// Setup test case
			if tt.before != nil {
				tt.before(t, deps, tt.args)
			}

			// Execute the function under test
			hashedPassword, userID, err := svc.ResetPasswordSvc(tt.args.token, tt.args.newPassword)

			// Verify expectations
			if tt.expect.err != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expect.err.Error())
			} else {
				require.NoError(t, err)

				// Verify the password was hashed correctly
				err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(tt.args.newPassword))
				assert.NoError(t, err, "Password was not hashed correctly")

				// Verify the user ID is correct
				assert.Equal(t, tt.expect.userID, userID)
			}

			// Verify mocks
			if tt.after != nil {
				tt.after(t, deps)
			}
		})
	}
}
