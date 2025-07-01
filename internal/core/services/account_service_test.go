package services

import (
	"errors"
	"testing"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	cerrors "github.com/Businge931/sba-user-accounts/internal/core/errors"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

func TestAccountService_verifyEmail(t *testing.T) {
	// Setup test dependencies
	deps := setUpTestDeps()
	setupLoggerExpectations(deps.logger)

	type args struct {
		token string
	}

	tests := []struct {
		name      string
		args      args
		before    func(*testDeps)
		afterFunc func(*testing.T, *testDeps, error)
	}{
		{
			name: "VerifyEmail_Success",
			args: args{
				token: "valid-verification-token",
			},
			before: func(d *testDeps) {
				userID := "user-id-123"
				d.identityProvider.On("VerifyEmailSvc", "valid-verification-token").Return(userID, nil).Once()
				d.userRepo.On("GetByID", userID).Return(&domain.User{
					ID:              userID,
					Email:           "test@example.com",
					IsEmailVerified: false,
				}, nil).Once()
				d.userRepo.On("Update", mock.MatchedBy(func(u *domain.User) bool {
					return u.ID == userID && u.IsEmailVerified == true
				})).Return(nil).Once()
			},
			afterFunc: func(t *testing.T, d *testDeps, err error) {
				assert.NoError(t, err)
				d.identityProvider.AssertExpectations(t)
				d.userRepo.AssertExpectations(t)
			},
		},
		{
			name: "VerifyEmail_InvalidToken",
			args: args{
				token: "invalid-verification-token",
			},
			before: func(d *testDeps) {
				d.identityProvider.On("VerifyEmailSvc", "invalid-verification-token").
					Return("", errors.New("invalid or expired token")).Once()
			},
			afterFunc: func(t *testing.T, d *testDeps, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid or expired token")
				d.identityProvider.AssertExpectations(t)
			},
		},
		{
			name: "VerifyEmail_UserNotFound",
			args: args{
				token: "valid-but-user-not-found",
			},
			before: func(d *testDeps) {
				userID := "non-existent-user"
				d.identityProvider.On("VerifyEmailSvc", "valid-but-user-not-found").Return(userID, nil).Once()
				d.userRepo.On("GetByID", userID).Return(nil, errors.New("user not found")).Once()
			},
			afterFunc: func(t *testing.T, d *testDeps, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "user not found")
				d.identityProvider.AssertExpectations(t)
				d.userRepo.AssertExpectations(t)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Reset mocks before each test case
			deps = setUpTestDeps()
			setupLoggerExpectations(deps.logger)

			// Setup mocks for this test case
			tc.before(deps)

			// Create service with test dependencies
			service := newTestAccountService(deps)

			// Execute the test
			err := service.VerifyEmail(tc.args.token)

			// Run assertions
			tc.afterFunc(t, deps, err)
		})
	}
}

func TestAccountService_RequestPasswordReset(t *testing.T) {
	// Setup test dependencies
	deps := setUpTestDeps()
	setupLoggerExpectations(deps.logger)

	type args struct {
		email string
	}

	tests := []struct {
		name      string
		args      args
		before    func(*testDeps)
		afterFunc func(*testing.T, *testDeps, error)
	}{
		{
			name: "RequestPasswordReset_Success",
			args: args{
				email: "test@example.com",
			},
			before: func(d *testDeps) {
				token := "reset-token-123"
				d.identityProvider.On("RequestPasswordResetSvc", "test@example.com").Return(token, nil).Once()
				d.emailSvc.On("SendPasswordResetEmail", "test@example.com", token).Return(nil).Once()
				d.logger.On("Infof", mock.Anything, mock.Anything).Maybe()
			},
			afterFunc: func(t *testing.T, d *testDeps, err error) {
				assert.NoError(t, err)
				d.identityProvider.AssertExpectations(t)
				d.emailSvc.AssertExpectations(t)
			},
		},
		{
			name: "RequestPasswordReset_UserNotFound",
			args: args{
				email: "nonexistent@example.com",
			},
			before: func(d *testDeps) {
				d.identityProvider.On("RequestPasswordResetSvc", "nonexistent@example.com").Return("", nil).Once()
				d.logger.On("Infof", mock.Anything, mock.Anything).Maybe()
			},
			afterFunc: func(t *testing.T, d *testDeps, err error) {
				assert.NoError(t, err) // Should not return error for non-existent user (security measure)
				d.identityProvider.AssertExpectations(t)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Reset mocks before each test case
			deps = setUpTestDeps()
			setupLoggerExpectations(deps.logger)

			// Setup mocks for this test case
			tc.before(deps)

			// Create service with test dependencies
			service := newTestAccountService(deps)

			// Execute the test
			err := service.RequestPasswordReset(tc.args.email)

			// Run assertions
			tc.afterFunc(t, deps, err)
		})
	}
}

func TestAccountService_ResetPassword(t *testing.T) {
	// Setup test dependencies
	deps := setUpTestDeps()
	setupLoggerExpectations(deps.logger)

	type args struct {
		token    string
		password string
	}

	tests := []struct {
		name      string
		args      args
		before    func(*testDeps)
		afterFunc func(*testing.T, *testDeps, error)
	}{
		{
			name: "ResetPassword_Success",
			args: args{
				token:    "valid-reset-token",
				password: "NewPassword123!"},
			before: func(d *testDeps) {
				hashedPassword := "$2a$10$hashedpassword12345678901234567890123456789012345678901234567890"
				d.identityProvider.On("ResetPasswordSvc", "valid-reset-token", "NewPassword123!").
					Return(hashedPassword, "user-id-123", nil).Once()
				d.userRepo.On("GetByID", "user-id-123").Return(&domain.User{
					ID:             "user-id-123",
					HashedPassword: "old-hashed-password",
				}, nil)
				d.userRepo.On("Update", mock.AnythingOfType("*domain.User")).
					Run(func(args mock.Arguments) {
						user := args.Get(0).(*domain.User)
						assert.Equal(t, hashedPassword, user.HashedPassword)
					}).
					Return(nil).Once()
			},
			afterFunc: func(t *testing.T, d *testDeps, err error) {
				assert.NoError(t, err)
				d.identityProvider.AssertExpectations(t)
				d.userRepo.AssertExpectations(t)
			},
		},
		{
			name: "ResetPassword_InvalidToken",
			args: args{
				token:    "invalid-reset-token",
				password: "NewPassword123!",
			},
			before: func(d *testDeps) {
				d.identityProvider.On("ResetPasswordSvc", "invalid-reset-token", "NewPassword123!").
					Return("", "", cerrors.NewError(cerrors.ErrorTypeInvalidInput, "invalid or expired token", nil)).Once()
				d.logger.On("Infof", mock.Anything, mock.Anything).Maybe()
			},
			afterFunc: func(t *testing.T, d *testDeps, err error) {
				assert.Error(t, err)
				domainErr, ok := err.(*cerrors.DomainError)
				assert.True(t, ok)
				assert.Equal(t, cerrors.ErrorTypeInvalidInput, domainErr.Type)
				d.identityProvider.AssertExpectations(t)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Reset mocks before each test case
			deps = setUpTestDeps()
			setupLoggerExpectations(deps.logger)

			// Setup mocks for this test case
			tc.before(deps)

			// Create service with test dependencies
			service := newTestAccountService(deps)

			// Execute the test
			err := service.ResetPassword(tc.args.token, tc.args.password)

			// Run assertions
			tc.afterFunc(t, deps, err)
		})
	}
}

func TestAccountService_ChangePassword(t *testing.T) {
	// Setup test dependencies
	deps := setUpTestDeps()
	setupLoggerExpectations(deps.logger)

	type args struct {
		userID      string
		oldPassword string
		newPassword string
	}

	tests := []struct {
		name      string
		args      args
		before    func(*testDeps)
		afterFunc func(*testing.T, *testDeps, error)
	}{
		{
			name: "ChangePassword_Success",
			args: args{
				userID:      "user-id-123",
				oldPassword: "OldPassword123!",
				newPassword: "NewPassword123!",
			},

			before: func(d *testDeps) {
				// Generate a proper bcrypt hash with MinCost for test speed
				hashedOldPassword, _ := bcrypt.GenerateFromPassword([]byte("OldPassword123!"), bcrypt.MinCost)

				// Setup expectations with fresh hash
				hashedNewPassword := "hashed-new-password-123"
				user := &domain.User{
					ID:             "user-id-123",
					Email:          "test@example.com",
					HashedPassword: string(hashedOldPassword),
				}
				d.userRepo.On("GetByID", "user-id-123").Return(user, nil)
				d.identityProvider.On("ChangePasswordSvc", "user-id-123", "OldPassword123!", "NewPassword123!").
					Return(hashedNewPassword, nil).Once()
				d.userRepo.On("Update", mock.MatchedBy(func(u *domain.User) bool {
					// Check that the password was updated
					return u.ID == "user-id-123" && u.HashedPassword == hashedNewPassword
				})).Return(nil).Once()
			},
			afterFunc: func(t *testing.T, d *testDeps, err error) {
				assert.NoError(t, err)
				d.userRepo.AssertExpectations(t)
				d.identityProvider.AssertExpectations(t)
			},
		},
		{
			name: "ChangePassword_WrongOldPassword",
			args: args{
				userID:      "user-id-123",
				oldPassword: "WrongOldPassword123!",
				newPassword: "NewPassword123!"},
			before: func(d *testDeps) {
				hashedOldPassword, _ := bcrypt.GenerateFromPassword([]byte("OldPassword123!"), bcrypt.DefaultCost)

				// Setup expectations
				user := &domain.User{
					ID:             "user-id-123",
					Email:          "test@example.com",
					HashedPassword: string(hashedOldPassword),
				}
				d.userRepo.On("GetByID", "user-id-123").Return(user, nil)
				err := errors.New("invalid current password")
				d.identityProvider.On("ChangePasswordSvc", "user-id-123", "WrongOldPassword123!", "NewPassword123!").
					Return("", err).Once()
				d.logger.On("Infof", mock.Anything, mock.Anything).Maybe()
			},
			afterFunc: func(t *testing.T, d *testDeps, err error) {
				assert.Error(t, err)
				domainErr, ok := err.(*cerrors.DomainError)
				assert.True(t, ok)
				assert.Equal(t, cerrors.ErrorTypeInvalidAuth, domainErr.Type)
				d.userRepo.AssertExpectations(t)
				d.identityProvider.AssertExpectations(t)
			},
		},
		{
			name: "ChangePassword_UserNotFound",
			args: args{
				userID:      "nonexistent-user-id",
				oldPassword: "OldPassword123!",
				newPassword: "NewPassword123!"},
			before: func(d *testDeps) {
				d.userRepo.On("GetByID", "nonexistent-user-id").Return(nil, errors.New("user not found"))
				d.logger.On("Infof", mock.Anything, mock.Anything).Maybe()
			},
			afterFunc: func(t *testing.T, d *testDeps, err error) {
				assert.Error(t, err)
				domainErr, ok := err.(*cerrors.DomainError)
				assert.True(t, ok)
				assert.Equal(t, cerrors.ErrorTypeNotFound, domainErr.Type)
				d.userRepo.AssertExpectations(t)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Reset mocks before each test case
			deps = setUpTestDeps()
			setupLoggerExpectations(deps.logger)

			// Setup mocks for this test case
			tc.before(deps)

			// Create service with test dependencies
			service := newTestAccountService(deps)

			// Execute the test
			err := service.ChangePassword(tc.args.userID, tc.args.oldPassword, tc.args.newPassword)

			// Run assertions
			tc.afterFunc(t, deps, err)
		})
	}
}
