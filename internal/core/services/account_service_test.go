package services

import (
	"errors"
	"testing"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	cerrors "github.com/Businge931/sba-user-accounts/internal/core/errors"
	"github.com/Businge931/sba-user-accounts/internal/core/services/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

func TestAccountService_verifyEmail(t *testing.T) {
	type dependencies struct {
		userRepo         *mocks.MockUserRepository
		authRepo         *mocks.MockAuthRepository
		tokenSvc         *mocks.MockTokenService
		identityProvider *mocks.MockIdentityService
	}

	type args struct {
		token string
	}

	tests := []struct {
		name      string
		deps      dependencies
		args      args
		before    func(deps *testDeps)
		after     func(t *testing.T, deps *testDeps)
		wantErr   bool
		errorType cerrors.ErrorType
	}{
		{
			name: "VerifyEmail_Success",
			deps: dependencies{
				userRepo:         new(mocks.MockUserRepository),
				authRepo:         new(mocks.MockAuthRepository),
				tokenSvc:         new(mocks.MockTokenService),
				identityProvider: new(mocks.MockIdentityService),
			},
			args: args{
				token: "valid-verification-token",
			},
			before: func(deps *testDeps) {
				userID := "user-id-123"
				deps.identityProvider.On("VerifyEmail", "valid-verification-token").Return(userID, nil)
				deps.userRepo.On("GetByID", userID).Return(&domain.User{
					ID:              userID,
					Email:           "test@example.com",
					IsEmailVerified: false,
				}, nil)
				deps.userRepo.On("Update", mock.MatchedBy(func(u *domain.User) bool {
					return u.ID == userID && u.IsEmailVerified == true
				})).Return(nil)
			},
			after: func(t *testing.T, deps *testDeps) {
				deps.identityProvider.AssertExpectations(t)
				deps.userRepo.AssertExpectations(t)
			},
			wantErr: false,
		},
		{
			name: "VerifyEmail_InvalidToken",
			deps: dependencies{
				identityProvider: new(mocks.MockIdentityService),
			},
			args: args{
				token: "invalid-verification-token",
			},
			before: func(deps *testDeps) {
				deps.identityProvider.On("VerifyEmail", "invalid-verification-token").
					Return("", errors.New("invalid or expired token"))
			},
			after: func(t *testing.T, deps *testDeps) {
				deps.identityProvider.AssertExpectations(t)
			},
			wantErr:   true,
			errorType: "", // The error from identity provider is passed through as-is
		},
		{
			name: "VerifyEmail_UserNotFound",
			deps: dependencies{
				userRepo:         new(mocks.MockUserRepository),
				identityProvider: new(mocks.MockIdentityService),
			},
			args: args{
				token: "valid-but-user-not-found",
			},
			before: func(deps *testDeps) {
				userID := "non-existent-user"
				deps.identityProvider.On("VerifyEmail", "valid-but-user-not-found").Return(userID, nil)
				deps.userRepo.On("GetByID", userID).Return(nil, errors.New("user not found"))
			},
			after: func(t *testing.T, deps *testDeps) {
				deps.identityProvider.AssertExpectations(t)
				deps.userRepo.AssertExpectations(t)
			},
			wantErr:   true,
			errorType: "", // The error from userRepo is passed through as-is
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test dependencies
			deps := setUpTestDeps()
			setupLoggerExpectations(deps.logger)

			// Run before function to set up mocks
			if tt.before != nil {
				tt.before(deps)
			}

			// Create service with test dependencies
			service := newTestAccountService(deps)

			// Execute
			err := service.VerifyEmail(tt.args.token)

			// Assert
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errorType != "" {
					switch v := err.(type) {
					case *cerrors.DomainError:
						assert.Equal(t, tt.errorType, v.Type)
					default:
						t.Errorf("expected DomainError with type %s, got %T", tt.errorType, err)
					}
				}
			} else {
				assert.NoError(t, err)
			}

			// Verify all expectations were met
			deps.userRepo.AssertExpectations(t)
			deps.authRepo.AssertExpectations(t)
			deps.tokenSvc.AssertExpectations(t)
			deps.identityProvider.AssertExpectations(t)
			// Check email service expectations if email was expected to be sent
			if tt.name == "RequestPasswordReset_Success" {
				deps.emailSvc.AssertExpectations(t)
			}
		})
	}
}

func TestAccountService_RequestPasswordReset(t *testing.T) {
	// Define test case structure
	type testCase struct {
		name      string
		args      struct {
			email string
		}
		setup     func(*testDeps)
		assert    func(*testing.T, *testDeps, error)
		wantErr   bool
		errorType cerrors.ErrorType
		emailSent bool
	}

	tests := []testCase{
		{
			name: "RequestPasswordReset_Success",
			args: struct{ email string }{
				email: "test@example.com",
			},
			setup: func(d *testDeps) {
				token := "reset-token-123"
				d.identityProvider.On("RequestPasswordReset", "test@example.com").Return(token, nil).Once()
				d.emailSvc.On("SendPasswordResetEmail", "test@example.com", token).Return(nil).Once()
				d.logger.On("Infof", mock.Anything, mock.Anything).Maybe()
			},
			assert: func(t *testing.T, d *testDeps, err error) {
				d.identityProvider.AssertExpectations(t)
				d.emailSvc.AssertExpectations(t)
			},
			emailSent: true,
		},
		{
			name: "RequestPasswordReset_UserNotFound",
			args: struct{ email string }{
				email: "nonexistent@example.com",
			},
			setup: func(d *testDeps) {
				d.identityProvider.On("RequestPasswordReset", "nonexistent@example.com").Return("", nil).Once()
				d.logger.On("Infof", mock.Anything, mock.Anything).Maybe()
			},
			assert: func(t *testing.T, d *testDeps, err error) {
				d.identityProvider.AssertExpectations(t)
			},
			wantErr: false, // Should not return error for non-existent user (security measure)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test dependencies
			deps := setUpTestDeps()
			setupLoggerExpectations(deps.logger)

			// Run setup function to configure mocks
			if tt.setup != nil {
				tt.setup(deps)
			}

			// Create service with test dependencies
			service := newTestAccountService(deps)

			// Execute
			err := service.RequestPasswordReset(tt.args.email)

			// Assert
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errorType != "" {
					domainErr, ok := err.(*cerrors.DomainError)
					assert.True(t, ok)
					assert.Equal(t, tt.errorType, domainErr.Type)
				}
			} else {
				assert.NoError(t, err)
			}

			// Run assertions
			if tt.assert != nil {
				tt.assert(t, deps, err)
			}

			// Verify all expectations were met
			deps.userRepo.AssertExpectations(t)
			deps.authRepo.AssertExpectations(t)
			deps.tokenSvc.AssertExpectations(t)
			deps.identityProvider.AssertExpectations(t)
			if tt.emailSent {
				deps.emailSvc.AssertExpectations(t)
			}
		})
	}
}

func TestAccountService_ResetPassword(t *testing.T) {
	// Define test dependencies
	type dependencies struct {
		userRepo         *mocks.MockUserRepository
		authRepo         *mocks.MockAuthRepository
		tokenSvc         *mocks.MockTokenService
		identityProvider *mocks.MockIdentityService
	}

	// Define test arguments
	type args struct {
		token       string
		newPassword string
	}

	tests := []struct {
		name      string
		deps      dependencies
		args      args
		before    func(deps *testDeps)
		after     func(t *testing.T, deps *testDeps)
		wantErr   bool
		errorType cerrors.ErrorType
	}{
		{
			name: "ResetPassword_Success",
			deps: dependencies{
				identityProvider: new(mocks.MockIdentityService),
			},
			args: struct {
				token       string
				newPassword string
			}{
				token:       "valid-reset-token",
				newPassword: "NewPassword123!",
			},
			before: func(d *testDeps) {
				hashedPassword := "$2a$10$hashedpassword12345678901234567890123456789012345678901234567890"
				d.identityProvider.On("ResetPassword", "valid-reset-token", "NewPassword123!").
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
			after: func(t *testing.T, deps *testDeps) {
				deps.identityProvider.AssertExpectations(t)
			},
			wantErr: false,
		},
		{
			name: "ResetPassword_InvalidToken",
			deps: dependencies{
				identityProvider: new(mocks.MockIdentityService),
			},
			args: args{
				token:       "invalid-reset-token",
				newPassword: "NewPassword123!",
			},
			before: func(deps *testDeps) {
				deps.identityProvider.On("ResetPassword", "invalid-reset-token", "NewPassword123!").
					Return("", "", cerrors.NewError(cerrors.ErrorTypeInvalidInput, "invalid or expired token", nil)).Once()
				deps.logger.On("Infof", mock.Anything, mock.Anything).Maybe()
			},
			after: func(t *testing.T, deps *testDeps) {
				deps.identityProvider.AssertExpectations(t)
			},
			wantErr:   true,
			errorType: cerrors.ErrorTypeInvalidInput,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test dependencies
			deps := setUpTestDeps()
			setupLoggerExpectations(deps.logger)

			// Run before function to set up mocks
			if tt.before != nil {
				tt.before(deps)
			}

			// Create service with test dependencies
			service := newTestAccountService(deps)

			// Execute
			err := service.ResetPassword(tt.args.token, tt.args.newPassword)

			// Assert
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errorType != "" {
					domainErr, ok := err.(*cerrors.DomainError)
					assert.True(t, ok)
					assert.Equal(t, tt.errorType, domainErr.Type)
				}
			} else {
				assert.NoError(t, err)
			}

			// Run after function for cleanup/verification
			if tt.after != nil {
				tt.after(t, deps)
			}
		})
	}
}

func TestAccountService_ChangePassword(t *testing.T) {
	// Define test dependencies
	type dependencies struct {
		userRepo *mocks.MockUserRepository
	}

	// Define test arguments
	type args struct {
		userID      string
		oldPassword string
		newPassword string
	}

	tests := []struct {
		name      string
		deps      dependencies
		args      args
		before    func(deps *testDeps)
		after     func(t *testing.T, deps *testDeps)
		wantErr   bool
		errorType cerrors.ErrorType
	}{
		{
			name: "ChangePassword_Success",
			deps: dependencies{
				userRepo: new(mocks.MockUserRepository),
			},
			args: args{
				userID:      "user-id-123",
				oldPassword: "OldPassword123!",
				newPassword: "NewPassword123!",
			},
			before: func(deps *testDeps) {
				userID := "user-id-123"
				oldPassword := "OldPassword123!"
				// Generate a proper bcrypt hash with MinCost for test speed
				hashedOldPassword, _ := bcrypt.GenerateFromPassword([]byte(oldPassword), bcrypt.MinCost)

				// Setup expectations with fresh hash
				hashedNewPassword := "hashed-new-password-123"
				user := &domain.User{
					ID:             userID,
					Email:          "test@example.com",
					HashedPassword: string(hashedOldPassword),
				}
				deps.userRepo.On("GetByID", userID).Return(user, nil)
				deps.identityProvider.On("ChangePassword", userID, oldPassword, "NewPassword123!").
					Return(hashedNewPassword, nil).Once()
				deps.userRepo.On("Update", mock.MatchedBy(func(u *domain.User) bool {
					// Check that the password was updated
					return u.ID == userID && u.HashedPassword == hashedNewPassword
				})).Return(nil).Once()
			},
			after: func(t *testing.T, deps *testDeps) {
				// Verify all expectations were met
				deps.userRepo.AssertExpectations(t)
			},
			wantErr: false,
		},
		{
			name: "ChangePassword_WrongOldPassword",
			deps: dependencies{
				userRepo: new(mocks.MockUserRepository),
			},
			args: args{
				userID:      "user-id-123",
				oldPassword: "WrongOldPassword123!",
				newPassword: "NewPassword123!",
			},
			before: func(deps *testDeps) {
				userID := "user-id-123"
				correctOldPassword := "OldPassword123!"
				hashedOldPassword, _ := bcrypt.GenerateFromPassword([]byte(correctOldPassword), bcrypt.DefaultCost)

				// Setup expectations
				user := &domain.User{
					ID:             userID,
					Email:          "test@example.com",
					HashedPassword: string(hashedOldPassword),
				}
				deps.userRepo.On("GetByID", userID).Return(user, nil)
				err := errors.New("invalid current password")
				deps.identityProvider.On("ChangePassword", userID, "WrongOldPassword123!", "NewPassword123!").
					Return("", err).Once()
			},
			after: func(t *testing.T, deps *testDeps) {
				deps.userRepo.AssertExpectations(t)
			},
			wantErr:   true,
			errorType: cerrors.ErrorTypeInvalidAuth,
		},
		{
			name: "ChangePassword_UserNotFound",
			deps: dependencies{
				userRepo: new(mocks.MockUserRepository),
			},
			args: args{
				userID:      "nonexistent-user-id",
				oldPassword: "OldPassword123!",
				newPassword: "NewPassword123!",
			},
			before: func(deps *testDeps) {
				deps.userRepo.On("GetByID", "nonexistent-user-id").Return(nil, errors.New("user not found"))
			},
			after: func(t *testing.T, deps *testDeps) {
				deps.userRepo.AssertExpectations(t)
			},
			wantErr:   true,
			errorType: cerrors.ErrorTypeNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test dependencies
			deps := setUpTestDeps()
			setupLoggerExpectations(deps.logger)

			// Run before function to set up mocks
			if tt.before != nil {
				tt.before(deps)
			}

			// Create service with test dependencies
			service := newTestAccountService(deps)

			// Execute
			err := service.ChangePassword(tt.args.userID, tt.args.oldPassword, tt.args.newPassword)

			// Assert
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errorType != "" {
					domainErr, ok := err.(*cerrors.DomainError)
					assert.True(t, ok)
					assert.Equal(t, tt.errorType, domainErr.Type)
				}
			} else {
				assert.NoError(t, err)
			}

			// Run after function for cleanup/verification
			if tt.after != nil {
				tt.after(t, deps)
			}
		})
	}
}
