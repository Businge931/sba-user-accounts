package unit

import (
	"errors"
	"testing"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	cerrors "github.com/Businge931/sba-user-accounts/internal/core/errors"
	"github.com/Businge931/sba-user-accounts/internal/core/services"
	"github.com/Businge931/sba-user-accounts/internal/core/validation"
	"github.com/Businge931/sba-user-accounts/tests/unit/mocks"
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

	accountService := services.NewAccountManagementService(
		mockUserRepo,
		mockAuthRepo,
		mockTokenSvc,
		nil, // No email service for tests
		validator,
		mockLogger,
	)

	t.Run("VerifyEmail_Success", func(t *testing.T) {
		// Test data
		token := "valid-verification-token"
		userID := "user-id-123"

		// Setup expectations
		mockAuthRepo.On("GetUserIDByVerificationToken", token).Return(userID, nil)

		user := &domain.User{
			ID:              userID,
			Email:           "test@example.com",
			IsEmailVerified: false,
		}
		mockUserRepo.On("GetByID", userID).Return(user, nil)
		mockUserRepo.On("Update", mock.MatchedBy(func(u *domain.User) bool {
			return u.ID == userID && u.IsEmailVerified == true
		})).Return(nil)

		// Execute
		err := accountService.VerifyEmail(token)

		// Assert
		assert.NoError(t, err)
		mockAuthRepo.AssertExpectations(t)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("VerifyEmail_InvalidToken", func(t *testing.T) {
		// Test data
		token := "invalid-verification-token"

		// Setup expectations
		mockAuthRepo.On("GetUserIDByVerificationToken", token).Return("", errors.New("token not found"))

		// Execute
		err := accountService.VerifyEmail(token)

		// Assert
		assert.Error(t, err)
		domainErr, ok := err.(*cerrors.DomainError)
		assert.True(t, ok)
		assert.Equal(t, cerrors.ErrorTypeInvalidInput, domainErr.Type)

		mockAuthRepo.AssertExpectations(t)
		mockUserRepo.AssertNotCalled(t, "GetByID")
		mockUserRepo.AssertNotCalled(t, "Update")
	})

	t.Run("RequestPasswordReset_Success", func(t *testing.T) {
		// Test data
		email := "test@example.com"
		userID := "user-id-123"
		resetToken := "reset-token-123"

		// Setup expectations
		user := &domain.User{
			ID:    userID,
			Email: email,
		}
		mockUserRepo.On("GetByEmail", email).Return(user, nil)
		mockTokenSvc.On("GenerateResetToken").Return(resetToken)
		mockAuthRepo.On("StoreResetToken", userID, resetToken).Return(nil)
		// Note: Email service is set to nil for tests

		// Execute
		err := accountService.RequestPasswordReset(email)

		// Assert
		assert.NoError(t, err)
		mockUserRepo.AssertExpectations(t)
		mockTokenSvc.AssertExpectations(t)
		mockAuthRepo.AssertExpectations(t)
	})

	// t.Run("RequestPasswordReset_UserNotFound", func(t *testing.T) {
	// 	// Test data
	// 	email := "nonexistent@example.com"

	// 	// Reset token service expectations
	// 	mockTokenSvc.ExpectedCalls = nil
	// 	// Add explicit mock to prevent token generation
	// 	mockTokenSvc.On("GenerateResetToken").Return("", errors.New("should not be called")).Maybe()

	// 	// Setup user repository expectations
	// 	mockUserRepo.On("GetByEmail", email).Return(nil, errors.New("user not found"))

	// 	// Execute
	// 	err := accountService.RequestPasswordReset(email)

	// 	// Assert - should not return error for security reasons
	// 	assert.NoError(t, err)
	// 	mockUserRepo.AssertExpectations(t)
	// 	mockTokenSvc.AssertNotCalled(t, "GenerateResetToken")
	// 	mockAuthRepo.AssertNotCalled(t, "StoreResetToken")
	// })

	t.Run("ResetPassword_Success", func(t *testing.T) {
		// Test data
		token := "valid-reset-token"
		userID := "user-id-123"
		newPassword := "NewPassword123!"

		// Setup expectations
		mockAuthRepo.On("GetUserIDByResetToken", token).Return(userID, nil)

		user := &domain.User{
			ID:             userID,
			Email:          "test@example.com",
			HashedPassword: "old-hashed-password",
		}
		mockUserRepo.On("GetByID", userID).Return(user, nil)
		mockUserRepo.On("Update", mock.MatchedBy(func(u *domain.User) bool {
			// Check that the password was updated
			return u.ID == userID && u.HashedPassword != "old-hashed-password"
		})).Return(nil)

		// Execute
		err := accountService.ResetPassword(token, newPassword)

		// Assert
		assert.NoError(t, err)
		mockAuthRepo.AssertExpectations(t)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("ResetPassword_InvalidToken", func(t *testing.T) {
		// Test data
		token := "invalid-reset-token"
		newPassword := "NewPassword123!"

		// Setup expectations
		mockAuthRepo.On("GetUserIDByResetToken", token).Return("", errors.New("token not found"))

		// Execute
		err := accountService.ResetPassword(token, newPassword)

		// Assert
		assert.Error(t, err)
		domainErr, ok := err.(*cerrors.DomainError)
		assert.True(t, ok)
		assert.Equal(t, cerrors.ErrorTypeInvalidInput, domainErr.Type)

		mockAuthRepo.AssertExpectations(t)
		mockUserRepo.AssertNotCalled(t, "GetByID")
		mockUserRepo.AssertNotCalled(t, "Update")
	})

	// t.Run("ChangePassword_Success", func(t *testing.T) {
	// 	// Test data
	// 	userID := "user-id-123"
	// 	oldPassword := "OldPassword123!"
	// 	newPassword := "NewPassword123!"

	// 	// Generate a proper bcrypt hash with MinCost for test speed
	// 	hashedOldPassword, errHash := bcrypt.GenerateFromPassword([]byte(oldPassword), bcrypt.MinCost)
	// 	assert.NoError(t, errHash, "Failed to generate password hash")

	// 	// Setup expectations with fresh hash
	// 	user := &domain.User{
	// 		ID:             userID,
	// 		Email:          "test@example.com",
	// 		HashedPassword: string(hashedOldPassword),
	// 	}
	// 	mockUserRepo.On("GetByID", userID).Return(user, nil)
	// 	mockUserRepo.On("Update", mock.MatchedBy(func(u *domain.User) bool {
	// 		// Check that the password was updated
	// 		return u.ID == userID && u.HashedPassword != string(hashedOldPassword)
	// 	})).Return(nil)

	// 	// Execute
	// 	err := accountService.ChangePassword(userID, oldPassword, newPassword)

	// 	// Assert
	// 	assert.NoError(t, err)
	// 	mockUserRepo.AssertExpectations(t)
	// })

	t.Run("ChangePassword_WrongOldPassword", func(t *testing.T) {
		// Test data
		userID := "user-id-123"
		correctOldPassword := "OldPassword123!"
		wrongOldPassword := "WrongOldPassword123!"
		newPassword := "NewPassword123!"
		hashedOldPassword, _ := bcrypt.GenerateFromPassword([]byte(correctOldPassword), bcrypt.DefaultCost)

		// Setup expectations
		user := &domain.User{
			ID:             userID,
			Email:          "test@example.com",
			HashedPassword: string(hashedOldPassword),
		}
		mockUserRepo.On("GetByID", userID).Return(user, nil)

		// Execute with wrong old password
		err := accountService.ChangePassword(userID, wrongOldPassword, newPassword)

		// Assert
		assert.Error(t, err)
		domainErr, ok := err.(*cerrors.DomainError)
		assert.True(t, ok)
		assert.Equal(t, cerrors.ErrorTypeInvalidAuth, domainErr.Type)

		mockUserRepo.AssertExpectations(t)
		mockUserRepo.AssertNotCalled(t, "Update")
	})

	t.Run("ChangePassword_UserNotFound", func(t *testing.T) {
		// Test data
		userID := "nonexistent-user-id"
		oldPassword := "OldPassword123!"
		newPassword := "NewPassword123!"

		// Setup expectations
		mockUserRepo.On("GetByID", userID).Return(nil, errors.New("user not found"))

		// Execute
		err := accountService.ChangePassword(userID, oldPassword, newPassword)

		// Assert
		assert.Error(t, err)
		domainErr, ok := err.(*cerrors.DomainError)
		assert.True(t, ok)
		assert.Equal(t, cerrors.ErrorTypeNotFound, domainErr.Type)

		mockUserRepo.AssertExpectations(t)
		mockUserRepo.AssertNotCalled(t, "Update")
	})

	// Reset mocks for the next test
	mockUserRepo.ExpectedCalls = nil
	mockAuthRepo.ExpectedCalls = nil
	mockTokenSvc.ExpectedCalls = nil
}
