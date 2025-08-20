package identity

import (
	"errors"
	"testing"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestIdentityProvider_ChangePasswordSvc(t *testing.T) {
	// Helper to generate a bcrypt hash for test passwords
	hashPassword := func(password string) string {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		require.NoError(t, err)
		return string(hash)
	}

	tests := []changePasswordTestCase{
		{
			name: "successful password change",
			args: changePasswordArgs{
				userID:      "user-123",
				oldPassword: "old-password",
				newPassword: "new-password",
			},
			expect: changePasswordExpectations{
				hashedPassword: hashPassword("new-password"),
			},
			before: func(t *testing.T, d *changePasswordDependencies, args changePasswordArgs) {
				d.userRepo.On("GetByID", args.userID).
					Return(&domain.User{
						ID:             args.userID,
						HashedPassword: hashPassword(args.oldPassword),
					}, nil).
					Once()
			},
			after: func(t *testing.T, d *changePasswordDependencies) {
				d.userRepo.AssertExpectations(t)
			},
		},
		{
			name: "returns error when user not found",
			args: changePasswordArgs{
				userID:      "nonexistent-user",
				oldPassword: "old-password",
				newPassword: "new-password",
			},
			expect: changePasswordExpectations{
				err: errors.New("user not found"),
			},
			before: func(t *testing.T, d *changePasswordDependencies, args changePasswordArgs) {
				d.userRepo.On("GetByID", args.userID).
					Return(nil, errors.New("user not found")).
					Once()
				d.logger.On("Warnf", "Password change failed, user not found: %v", mock.Anything).Once()
			},
			after: func(t *testing.T, d *changePasswordDependencies) {
				d.userRepo.AssertExpectations(t)
				d.logger.AssertExpectations(t)
			},
		},
		{
			name: "returns error when current password is invalid",
			args: changePasswordArgs{
				userID:      "user-123",
				oldPassword: "wrong-password",
				newPassword: "new-password",
			},
			expect: changePasswordExpectations{
				err: errors.New("invalid current password"),
			},
			before: func(t *testing.T, d *changePasswordDependencies, args changePasswordArgs) {
				d.userRepo.On("GetByID", args.userID).
					Return(&domain.User{
						ID:             args.userID,
						HashedPassword: hashPassword("correct-password"),
					}, nil).
					Once()
				d.logger.On("Warnf", "Password change failed due to invalid current password", mock.Anything).Once()
			},
			after: func(t *testing.T, d *changePasswordDependencies) {
				d.userRepo.AssertExpectations(t)
				d.logger.AssertExpectations(t)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, deps := setupChangePasswordTest(t)

			// Setup test case
			if tt.before != nil {
				tt.before(t, deps, tt.args)
			}

			// Execute the function under test
			result, err := svc.ChangePasswordSvc(tt.args.userID, tt.args.oldPassword, tt.args.newPassword)

			// Verify expectations
			if tt.expect.err != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expect.err.Error())
			} else {
				require.NoError(t, err)

				// Verify the password was hashed correctly
				err := bcrypt.CompareHashAndPassword([]byte(result), []byte(tt.args.newPassword))
				assert.NoError(t, err, "Password was not hashed correctly")
			}

			// Verify mocks
			if tt.after != nil {
				tt.after(t, deps)
			}
		})
	}
}
