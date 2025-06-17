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
		userRepo *mocks.MockUserRepository
		authRepo *mocks.MockAuthRepository
		tokenSvc *mocks.MockTokenService
	}

	type args struct {
		token string
	}

	tests := []struct {
		name     string
		deps     dependencies
		args     args
		before   func(deps *testDeps)
		after    func(t *testing.T, deps *testDeps)
		wantErr  bool
		errorType cerrors.ErrorType
	}{
		{
			name: "VerifyEmail_Success",
			deps: dependencies{
				userRepo: new(mocks.MockUserRepository),
				authRepo: new(mocks.MockAuthRepository),
				tokenSvc: new(mocks.MockTokenService),
			},
			args: args{
				token: "valid-verification-token",
			},
			before: func(deps *testDeps) {
				userID := "user-id-123"
				deps.authRepo.On("GetUserIDByVerificationToken", "valid-verification-token").Return(userID, nil)
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
				deps.userRepo.AssertExpectations(t)
				deps.authRepo.AssertExpectations(t)
				deps.tokenSvc.AssertExpectations(t)
			},
			wantErr: false,
		},
		{
			name: "VerifyEmail_InvalidToken",
			deps: dependencies{
				authRepo: new(mocks.MockAuthRepository),
			},
			args: args{
				token: "invalid-verification-token",
			},
			before: func(deps *testDeps) {
				deps.authRepo.On("GetUserIDByVerificationToken", "invalid-verification-token").
					Return("", errors.New("token not found"))
			},
			after: func(t *testing.T, deps *testDeps) {
				deps.authRepo.AssertExpectations(t)
			},
			wantErr: true,
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
			err := service.VerifyEmail(tt.args.token)

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

			// Verify all expectations were met
			deps.userRepo.AssertExpectations(t)
			deps.authRepo.AssertExpectations(t)
			deps.tokenSvc.AssertExpectations(t)
		})
	}
}

func TestAccountService_RequestPasswordReset(t *testing.T) {
	// Define test dependencies
	type dependencies struct {
		userRepo *mocks.MockUserRepository
		authRepo *mocks.MockAuthRepository
		tokenSvc *mocks.MockTokenService
	}

	// Define test arguments
	type args struct {
		email string
	}

	tests := []struct {
		name     string
		deps     dependencies
		args     args
		before   func(deps *testDeps)
		after    func(t *testing.T, deps *testDeps)
		wantErr  bool
		errorType cerrors.ErrorType
	}{
		{
			name: "RequestPasswordReset_Success",
			deps: dependencies{
				userRepo: new(mocks.MockUserRepository),
				authRepo: new(mocks.MockAuthRepository),
				tokenSvc: new(mocks.MockTokenService),
			},
			args: args{
				email: "test@example.com",
			},
			before: func(deps *testDeps) {
				userID := "user-id-123"
				user := &domain.User{
					ID:    userID,
					Email: "test@example.com",
				}
				deps.userRepo.On("GetByEmail", "test@example.com").Return(user, nil)
				deps.tokenSvc.On("GenerateResetToken").Return("reset-token-123")
				deps.authRepo.On("StoreResetToken", userID, "reset-token-123").Return(nil)
			},
			after: func(t *testing.T, deps *testDeps) {
				deps.userRepo.AssertExpectations(t)
				deps.tokenSvc.AssertExpectations(t)
				deps.authRepo.AssertExpectations(t)
			},
			wantErr: false,
		},
		{
			name: "RequestPasswordReset_UserNotFound",
			deps: dependencies{
				userRepo: new(mocks.MockUserRepository),
			},
			args: args{
				email: "nonexistent@example.com",
			},
			before: func(deps *testDeps) {
				deps.userRepo.On("GetByEmail", "nonexistent@example.com").Return(nil, errors.New("user not found"))
			},
			after: func(t *testing.T, deps *testDeps) {
				deps.userRepo.AssertExpectations(t)
			},
			wantErr: false, // This operation doesn't return an error for security reasons
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

			// Run after function for cleanup/verification
			if tt.after != nil {
				tt.after(t, deps)
			}
		})
	}
}

func TestAccountService_ResetPassword(t *testing.T) {
	// Define test dependencies
	type dependencies struct {
		userRepo *mocks.MockUserRepository
		authRepo *mocks.MockAuthRepository
		tokenSvc *mocks.MockTokenService
	}

	// Define test arguments
	type args struct {
		token      string
		newPassword string
	}

	tests := []struct {
		name     string
		deps     dependencies
		args     args
		before   func(deps *testDeps)
		after    func(t *testing.T, deps *testDeps)
		wantErr  bool
		errorType cerrors.ErrorType
	}{
		{
			name: "ResetPassword_Success",
			deps: dependencies{
				userRepo: new(mocks.MockUserRepository),
				authRepo: new(mocks.MockAuthRepository),
				tokenSvc: new(mocks.MockTokenService),
			},
			args: args{
				token:      "valid-reset-token",
				newPassword: "NewPassword123!",
			},
			before: func(deps *testDeps) {
				userID := "user-id-123"
				deps.authRepo.On("GetUserIDByResetToken", "valid-reset-token").Return(userID, nil)
				deps.userRepo.On("GetByID", userID).Return(&domain.User{
					ID:             userID,
					Email:          "test@example.com",
					HashedPassword: "old-hashed-password",
				}, nil)
				deps.userRepo.On("Update", mock.AnythingOfType("*domain.User")).Run(func(args mock.Arguments) {
					user := args.Get(0).(*domain.User)
					// Verify the password was hashed
					err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte("NewPassword123!"))
					assert.NoError(t, err, "password should be hashed")
				}).Return(nil)
			},
			after: func(t *testing.T, deps *testDeps) {
				deps.authRepo.AssertExpectations(t)
				deps.userRepo.AssertExpectations(t)
			},
			wantErr: false,
		},
		{
			name: "ResetPassword_InvalidToken",
			deps: dependencies{
				authRepo: new(mocks.MockAuthRepository),
			},
			args: args{
				token:      "invalid-reset-token",
				newPassword: "NewPassword123!",
			},
			before: func(deps *testDeps) {
				deps.authRepo.On("GetUserIDByResetToken", "invalid-reset-token").Return("", errors.New("token not found"))
			},
			after: func(t *testing.T, deps *testDeps) {
				deps.authRepo.AssertExpectations(t)
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
		name     string
		deps     dependencies
		args     args
		before   func(deps *testDeps)
		after    func(t *testing.T, deps *testDeps)
		wantErr  bool
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
				user := &domain.User{
					ID:             userID,
					Email:          "test@example.com",
					HashedPassword: string(hashedOldPassword),
				}
				deps.userRepo.On("GetByID", userID).Return(user, nil)
				deps.userRepo.On("Update", mock.MatchedBy(func(u *domain.User) bool {
					// Check that the password was updated
					return u.ID == userID && u.HashedPassword != string(hashedOldPassword)
				})).Return(nil)
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
