package services

import (
	"errors"
	"testing"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	cerrors "github.com/Businge931/sba-user-accounts/internal/core/errors"
	"github.com/Businge931/sba-user-accounts/internal/core/services/mocks"
	"github.com/Businge931/sba-user-accounts/internal/core/validation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

func TestAccountManagementService(t *testing.T) {
	// Common test setup
	mockUserRepo := new(mocks.MockUserRepository)
	mockAuthRepo := new(mocks.MockAuthRepository)
	mockTokenSvc := new(mocks.MockTokenService)
	mockLogger := new(mocks.MockLogger)

	// Setup common expectations for the logger
	mockLogger.On("Debug", mock.Anything).Return()
	mockLogger.On("Debugf", mock.Anything, mock.Anything).Return()
	mockLogger.On("Info", mock.Anything).Return()
	mockLogger.On("Infof", mock.Anything, mock.Anything).Return()
	mockLogger.On("Warn", mock.Anything).Return()
	mockLogger.On("Warnf", mock.Anything, mock.Anything).Return()
	mockLogger.On("Error", mock.Anything).Return()
	mockLogger.On("Errorf", mock.Anything, mock.Anything).Return()

	validator := validation.NewValidator()

	accountService := NewAccountManagementService(
		mockUserRepo,
		mockAuthRepo,
		mockTokenSvc,
		nil, // No email service for tests
		validator,
		mockLogger,
	)

	verifyEmailTests := []struct {
		name     string
		deps     struct {
			userRepo   *mocks.MockUserRepository
			authRepo   *mocks.MockAuthRepository
			tokenSvc   *mocks.MockTokenService
		}
		args     struct {
			token string
		}
		before   func()
		expected struct {
			error   bool
			errType cerrors.ErrorType
		}
	}{
		{
			name: "VerifyEmail_Success",
			deps: struct {
				userRepo   *mocks.MockUserRepository
				authRepo   *mocks.MockAuthRepository
				tokenSvc   *mocks.MockTokenService
			}{
				userRepo:   mockUserRepo,
				authRepo:   mockAuthRepo,
				tokenSvc:   mockTokenSvc,
			},
			args: struct {
				token string
			}{
				token: "valid-verification-token",
			},
			before: func() {
				// Reset mocks
				mockUserRepo.ExpectedCalls = nil
				mockAuthRepo.ExpectedCalls = nil
				mockTokenSvc.ExpectedCalls = nil

				userID := "user-id-123"
				// Setup expectations
				mockAuthRepo.On("GetUserIDByVerificationToken", "valid-verification-token").Return(userID, nil)

				user := &domain.User{
					ID:              userID,
					Email:           "test@example.com",
					IsEmailVerified: false,
				}
				mockUserRepo.On("GetByID", userID).Return(user, nil)
				mockUserRepo.On("Update", mock.MatchedBy(func(u *domain.User) bool {
					return u.ID == userID && u.IsEmailVerified == true
				})).Return(nil)
			},
			expected: struct {
				error   bool
				errType cerrors.ErrorType
			}{
				error:   false,
				errType: "",
			},
		},
		{
			name: "VerifyEmail_InvalidToken",
			deps: struct {
				userRepo   *mocks.MockUserRepository
				authRepo   *mocks.MockAuthRepository
				tokenSvc   *mocks.MockTokenService
			}{
				userRepo:   mockUserRepo,
				authRepo:   mockAuthRepo,
				tokenSvc:   mockTokenSvc,
			},
			args: struct {
				token string
			}{
				token: "invalid-verification-token",
			},
			before: func() {
				// Reset mocks
				mockUserRepo.ExpectedCalls = nil
				mockAuthRepo.ExpectedCalls = nil
				mockTokenSvc.ExpectedCalls = nil

				// Setup expectations
				mockAuthRepo.On("GetUserIDByVerificationToken", "invalid-verification-token").Return("", errors.New("token not found"))
			},
			expected: struct {
				error   bool
				errType cerrors.ErrorType
			}{
				error:   true,
				errType: cerrors.ErrorTypeInvalidInput,
			},
		},
	}

	// Run all VerifyEmail tests
	for _, tc := range verifyEmailTests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mocks for this test case
			tc.before()

			// Execute the test
			err := accountService.VerifyEmail(tc.args.token)

			// Check error expectation
			if tc.expected.error {
				assert.Error(t, err)
				if tc.expected.errType != "" {
					domainErr, ok := err.(*cerrors.DomainError)
					assert.True(t, ok)
					assert.Equal(t, tc.expected.errType, domainErr.Type)
				}
			} else {
				assert.NoError(t, err)
			}

			// Verify the mocks were called appropriately
			tc.deps.authRepo.AssertExpectations(t)
			tc.deps.userRepo.AssertExpectations(t)
		})
	}

	// Define table-driven tests for RequestPasswordReset function
	requestPasswordResetTests := []struct {
		name     string
		deps     struct {
			userRepo   *mocks.MockUserRepository
			authRepo   *mocks.MockAuthRepository
			tokenSvc   *mocks.MockTokenService
		}
		args     struct {
			email string
		}
		before   func()
		expected struct {
			error   bool
			errType cerrors.ErrorType
		}
	}{
		{
			name: "RequestPasswordReset_Success",
			deps: struct {
				userRepo   *mocks.MockUserRepository
				authRepo   *mocks.MockAuthRepository
				tokenSvc   *mocks.MockTokenService
			}{
				userRepo:   mockUserRepo,
				authRepo:   mockAuthRepo,
				tokenSvc:   mockTokenSvc,
			},
			args: struct {
				email string
			}{
				email: "test@example.com",
			},
			before: func() {
				// Reset mocks
				mockUserRepo.ExpectedCalls = nil
				mockAuthRepo.ExpectedCalls = nil
				mockTokenSvc.ExpectedCalls = nil

				userID := "user-id-123"
				// Setup expectations
				user := &domain.User{
					ID:    userID,
					Email: "test@example.com",
				}
				mockUserRepo.On("GetByEmail", "test@example.com").Return(user, nil)
				mockTokenSvc.On("GenerateResetToken").Return("reset-token-123")
				mockAuthRepo.On("StoreResetToken", userID, "reset-token-123").Return(nil)
			},
			expected: struct {
				error   bool
				errType cerrors.ErrorType
			}{
				error:   false,
				errType: "",
			},
		},
		{
			name: "RequestPasswordReset_UserNotFound",
			deps: struct {
				userRepo   *mocks.MockUserRepository
				authRepo   *mocks.MockAuthRepository
				tokenSvc   *mocks.MockTokenService
			}{
				userRepo:   mockUserRepo,
				authRepo:   mockAuthRepo,
				tokenSvc:   mockTokenSvc,
			},
			args: struct {
				email string
			}{
				email: "nonexistent@example.com",
			},
			before: func() {
				// Reset mocks
				mockUserRepo.ExpectedCalls = nil
				mockAuthRepo.ExpectedCalls = nil
				mockTokenSvc.ExpectedCalls = nil

				// Setup expectations
				mockUserRepo.On("GetByEmail", "nonexistent@example.com").Return(nil, errors.New("user not found"))
			},
			expected: struct {
				error   bool
				errType cerrors.ErrorType
			}{
				error:   false, // This operation doesn't return an error for security reasons
				errType: "",
			},
		},
	}

	// Run all RequestPasswordReset tests
	for _, tc := range requestPasswordResetTests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mocks for this test case
			tc.before()

			// Execute the test
			err := accountService.RequestPasswordReset(tc.args.email)

			// Check error expectation
			if tc.expected.error {
				assert.Error(t, err)
				if tc.expected.errType != "" {
					domainErr, ok := err.(*cerrors.DomainError)
					assert.True(t, ok)
					assert.Equal(t, tc.expected.errType, domainErr.Type)
				}
			} else {
				assert.NoError(t, err)
			}

			// Verify the mocks were called appropriately
			tc.deps.userRepo.AssertExpectations(t)
			
			// Check other mocks based on test case
			if tc.name == "RequestPasswordReset_Success" {
				tc.deps.tokenSvc.AssertExpectations(t)
				tc.deps.authRepo.AssertExpectations(t)
			}
		})
	}

	// Define table-driven tests for ResetPassword function
	resetPasswordTests := []struct {
		name     string
		deps     struct {
			userRepo   *mocks.MockUserRepository
			authRepo   *mocks.MockAuthRepository
		}
		args     struct {
			token       string
			newPassword string
		}
		before   func()
		expected struct {
			error   bool
			errType cerrors.ErrorType
		}
	}{
		{
			name: "ResetPassword_Success",
			deps: struct {
				userRepo   *mocks.MockUserRepository
				authRepo   *mocks.MockAuthRepository
			}{
				userRepo: mockUserRepo,
				authRepo: mockAuthRepo,
			},
			args: struct {
				token       string
				newPassword string
			}{
				token:       "valid-reset-token",
				newPassword: "NewPassword123!",
			},
			before: func() {
				// Reset mocks
				mockUserRepo.ExpectedCalls = nil
				mockAuthRepo.ExpectedCalls = nil
				mockTokenSvc.ExpectedCalls = nil

				userID := "user-id-123"
				// Setup expectations
				mockAuthRepo.On("GetUserIDByResetToken", "valid-reset-token").Return(userID, nil)
				
				user := &domain.User{
					ID:    userID,
					Email: "test@example.com",
				}
				mockUserRepo.On("GetByID", userID).Return(user, nil)
				mockUserRepo.On("Update", mock.MatchedBy(func(u *domain.User) bool {
					// Check that the password was updated
					return u.ID == userID && u.HashedPassword != ""
				})).Return(nil)
				mockAuthRepo.On("DeleteResetToken", userID).Return(nil)
			},
			expected: struct {
				error   bool
				errType cerrors.ErrorType
			}{
				error:   false,
				errType: "",
			},
		},
		{
			name: "ResetPassword_InvalidToken",
			deps: struct {
				userRepo   *mocks.MockUserRepository
				authRepo   *mocks.MockAuthRepository
			}{
				userRepo: mockUserRepo,
				authRepo: mockAuthRepo,
			},
			args: struct {
				token       string
				newPassword string
			}{
				token:       "invalid-reset-token",
				newPassword: "NewPassword123!",
			},
			before: func() {
				// Reset mocks
				mockUserRepo.ExpectedCalls = nil
				mockAuthRepo.ExpectedCalls = nil
				mockTokenSvc.ExpectedCalls = nil

				// Setup expectations
				mockAuthRepo.On("GetUserIDByResetToken", "invalid-reset-token").Return("", errors.New("token not found"))
			},
			expected: struct {
				error   bool
				errType cerrors.ErrorType
			}{
				error:   true,
				errType: cerrors.ErrorTypeInvalidInput,
			},
		},
	}

	// Run all ResetPassword tests
	for _, tc := range resetPasswordTests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mocks for this test case
			tc.before()

			// Execute the test
			err := accountService.ResetPassword(tc.args.token, tc.args.newPassword)

			// Check error expectation
			if tc.expected.error {
				assert.Error(t, err)
				if tc.expected.errType != "" {
					domainErr, ok := err.(*cerrors.DomainError)
					assert.True(t, ok)
					assert.Equal(t, tc.expected.errType, domainErr.Type)
				}
			} else {
				assert.NoError(t, err)
			}

			// Verify the mocks were called appropriately
			tc.deps.authRepo.AssertExpectations(t)
			if !tc.expected.error {
				tc.deps.userRepo.AssertExpectations(t)
			}
		})
	}

	// Define table-driven tests for ChangePassword function
	changePasswordTests := []struct {
		name     string
		deps     struct {
			userRepo   *mocks.MockUserRepository
		}
		args     struct {
			userID      string
			oldPassword string
			newPassword string
		}
		before   func()
		expected struct {
			error   bool
			errType cerrors.ErrorType
		}
	}{
		{
			name: "ChangePassword_Success",
			deps: struct {
				userRepo   *mocks.MockUserRepository
			}{
				userRepo: mockUserRepo,
			},
			args: struct {
				userID      string
				oldPassword string
				newPassword string
			}{
				userID:      "user-id-123",
				oldPassword: "OldPassword123!",
				newPassword: "NewPassword123!",
			},
			before: func() {
				// Reset mocks
				mockUserRepo.ExpectedCalls = nil
				mockAuthRepo.ExpectedCalls = nil
				mockTokenSvc.ExpectedCalls = nil

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
				mockUserRepo.On("GetByID", userID).Return(user, nil)
				mockUserRepo.On("Update", mock.MatchedBy(func(u *domain.User) bool {
					// Check that the password was updated
					return u.ID == userID && u.HashedPassword != string(hashedOldPassword)
				})).Return(nil)
			},
			expected: struct {
				error   bool
				errType cerrors.ErrorType
			}{
				error:   false,
				errType: "",
			},
		},
		{
			name: "ChangePassword_WrongOldPassword",
			deps: struct {
				userRepo   *mocks.MockUserRepository
			}{
				userRepo: mockUserRepo,
			},
			args: struct {
				userID      string
				oldPassword string
				newPassword string
			}{
				userID:      "user-id-123",
				oldPassword: "WrongOldPassword123!",
				newPassword: "NewPassword123!",
			},
			before: func() {
				// Reset mocks
				mockUserRepo.ExpectedCalls = nil
				mockAuthRepo.ExpectedCalls = nil
				mockTokenSvc.ExpectedCalls = nil

				userID := "user-id-123"
				correctOldPassword := "OldPassword123!"
				hashedOldPassword, _ := bcrypt.GenerateFromPassword([]byte(correctOldPassword), bcrypt.DefaultCost)

				// Setup expectations
				user := &domain.User{
					ID:             userID,
					Email:          "test@example.com",
					HashedPassword: string(hashedOldPassword),
				}
				mockUserRepo.On("GetByID", userID).Return(user, nil)
			},
			expected: struct {
				error   bool
				errType cerrors.ErrorType
			}{
				error:   true,
				errType: cerrors.ErrorTypeInvalidAuth,
			},
		},
		{
			name: "ChangePassword_UserNotFound",
			deps: struct {
				userRepo   *mocks.MockUserRepository
			}{
				userRepo: mockUserRepo,
			},
			args: struct {
				userID      string
				oldPassword string
				newPassword string
			}{
				userID:      "nonexistent-user-id",
				oldPassword: "OldPassword123!",
				newPassword: "NewPassword123!",
			},
			before: func() {
				// Reset mocks
				mockUserRepo.ExpectedCalls = nil
				mockAuthRepo.ExpectedCalls = nil
				mockTokenSvc.ExpectedCalls = nil

				// Setup expectations
				mockUserRepo.On("GetByID", "nonexistent-user-id").Return(nil, errors.New("user not found"))
			},
			expected: struct {
				error   bool
				errType cerrors.ErrorType
			}{
				error:   true,
				errType: cerrors.ErrorTypeNotFound,
			},
		},
	}

	// Run all ChangePassword tests
	for _, tc := range changePasswordTests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mocks for this test case
			tc.before()

			// Execute the test
			err := accountService.ChangePassword(tc.args.userID, tc.args.oldPassword, tc.args.newPassword)

			// Check error expectation
			if tc.expected.error {
				assert.Error(t, err)
				if tc.expected.errType != "" {
					domainErr, ok := err.(*cerrors.DomainError)
					assert.True(t, ok)
					assert.Equal(t, tc.expected.errType, domainErr.Type)
				}
			} else {
				assert.NoError(t, err)
			}

			// Verify the mocks were called appropriately
			tc.deps.userRepo.AssertExpectations(t)
		})
	}
}
