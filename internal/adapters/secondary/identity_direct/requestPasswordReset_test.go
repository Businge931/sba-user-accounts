package identity

import (
	"errors"
	"testing"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestIdentityProvider_RequestPasswordResetSvc(t *testing.T) {
	tests := []requestPasswordResetTestCase{
		{
			name: "successful password reset request",
			args: requestPasswordResetArgs{
				email: "user@example.com",
			},
			expect: requestPasswordResetExpectations{
				result: "test-reset-token",
			},
			before: func(t *testing.T, d *requestPasswordResetDependencies, args requestPasswordResetArgs) {
				d.tokenSvc.On("GenerateResetToken").Return("test-reset-token").Once()
				d.userRepo.On("GetByEmail", args.email).
					Return(&domain.User{ID: "user-123"}, nil).
					Once()
				d.authRepo.On("StoreResetToken", "user-123", "test-reset-token").
					Return(nil).
					Once()
				email := args.email
				d.logger.On("Infof", "Password reset attempted for non-existent email: %s", mock.MatchedBy(func(args []interface{}) bool {
					return len(args) == 1 && args[0] == email
				})).Maybe()
			},
			after: func(t *testing.T, d *requestPasswordResetDependencies) {
				d.userRepo.AssertExpectations(t)
				d.authRepo.AssertExpectations(t)
				d.tokenSvc.AssertExpectations(t)
				d.logger.AssertExpectations(t)
			},
		},
		{
			name: "returns empty token when user not found",
			args: requestPasswordResetArgs{
				email: "nonexistent@example.com",
			},
			expect: requestPasswordResetExpectations{
				result: "",
				err:    nil,
			},
			before: func(t *testing.T, d *requestPasswordResetDependencies, args requestPasswordResetArgs) {
				d.tokenSvc.On("GenerateResetToken").Return("test-reset-token").Once()
				d.userRepo.On("GetByEmail", args.email).
					Return(nil, errors.New("user not found")).
					Once()
				email := args.email
				d.logger.On("Infof", "Password reset attempted for non-existent email: %s", mock.MatchedBy(func(args []interface{}) bool {
					return len(args) == 1 && args[0] == email
				})).Once()
			},
			after: func(t *testing.T, d *requestPasswordResetDependencies) {
				d.userRepo.AssertExpectations(t)
				d.logger.AssertExpectations(t)
			},
		},
		{
			name: "returns error when token storage fails",
			args: requestPasswordResetArgs{
				email: "user@example.com",
			},
			expect: requestPasswordResetExpectations{
				result: "",
				err:    errors.New("failed to process password reset"),
			},
			before: func(t *testing.T, d *requestPasswordResetDependencies, args requestPasswordResetArgs) {
				d.tokenSvc.On("GenerateResetToken").Return("test-reset-token").Once()
				d.userRepo.On("GetByEmail", args.email).
					Return(&domain.User{ID: "user-123"}, nil).
					Once()
				d.authRepo.On("StoreResetToken", "user-123", "test-reset-token").
					Return(errors.New("storage error")).
					Once()
				d.logger.On("Errorf", "Failed to store reset token: %v", mock.Anything).Once()
			},
			after: func(t *testing.T, d *requestPasswordResetDependencies) {
				d.userRepo.AssertExpectations(t)
				d.authRepo.AssertExpectations(t)
				d.logger.AssertExpectations(t)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, deps := setupRequestPasswordResetTest(t)

			// Setup test case
			if tt.before != nil {
				tt.before(t, deps, tt.args)
			}

			// Execute the function under test
			result, err := svc.RequestPasswordResetSvc(tt.args.email)

			// Verify expectations
			if tt.expect.err != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expect.err.Error())
			} else {
				require.NoError(t, err)
			}

			if tt.expect.result != "" {
				assert.Equal(t, tt.expect.result, result)
			}

			// Verify mocks
			if tt.after != nil {
				tt.after(t, deps)
			}
		})
	}
}
