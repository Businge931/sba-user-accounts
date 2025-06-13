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

func TestAuthService_Register(t *testing.T) {
	// Setup test dependencies
	deps := SetupTestDependencies()
	AuthServiceSetupMockLogger(deps.logger)
	authService := newTestAuthService(deps)

	tests := []struct {
		name       string
		args       domain.RegisterRequest
		beforeFunc func(*TestDependencies)
		afterFunc  func(*testing.T, *domain.User, error)
	}{
		{
			name: "successful registration",
			args: domain.RegisterRequest{
				Email:     "test@example.com",
				Password:  "Password123!",
				FirstName: "John",
				LastName:  "Doe",
			},
			beforeFunc: func(d *TestDependencies) {
				d.userRepo.On("GetByEmail", "test@example.com").Return(nil, errors.New("not found"))
				d.userRepo.On("Create", mock.AnythingOfType("*domain.User")).Return(nil)
				d.tokenSvc.On("GenerateVerificationToken").Return("verification-token")
				d.authRepo.On("StoreVerificationToken", mock.Anything, "verification-token").Return(nil)
			},
			afterFunc: func(t *testing.T, user *domain.User, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, user)
				assert.Equal(t, "test@example.com", user.Email)
				assert.Equal(t, "John", user.FirstName)
				assert.Equal(t, "Doe", user.LastName)
				assert.False(t, user.IsEmailVerified)
			},
		},
		{
			name: "user already exists",
			args: domain.RegisterRequest{
				Email:     "existing@example.com",
				Password:  "Password123!",
				FirstName: "Existing",
				LastName:  "User",
			},
			beforeFunc: func(d *TestDependencies) {
				existingUser := &domain.User{
					ID:             "existing-user-id",
					Email:          "existing@example.com",
					HashedPassword: "hashed-password",
					FirstName:      "Existing",
					LastName:       "User",
				}
				d.userRepo.On("GetByEmail", "existing@example.com").Return(existingUser, nil)
			},
			afterFunc: func(t *testing.T, user *domain.User, err error) {
				assert.Error(t, err)
				// The error is not wrapped in a DomainError, so we just check the error message
				assert.Contains(t, err.Error(), "user with this email already exists")
				// User should be nil when there's an error
				assert.Nil(t, user)
			},
		},
		{
			name: "invalid email",
			args: domain.RegisterRequest{
				Email:     "invalid-email",
				Password:  "Password123!",
				FirstName: "Test",
				LastName:  "User",
			},
			beforeFunc: func(d *TestDependencies) {
			},
			afterFunc: func(t *testing.T, user *domain.User, err error) {
				assert.Error(t, err)
				domainErr, ok := err.(*cerrors.DomainError)
				assert.True(t, ok)
				assert.Equal(t, cerrors.ErrorTypeInvalidInput, domainErr.Type)
			},
		},
		{
			name: "invalid password",
			args: domain.RegisterRequest{
				Email:     "valid@example.com",
				Password:  "weak",
				FirstName: "Test",
				LastName:  "User",
			},
			beforeFunc: func(d *TestDependencies) {
			},
			afterFunc: func(t *testing.T, user *domain.User, err error) {
				assert.Error(t, err)
				domainErr, ok := err.(*cerrors.DomainError)
				assert.True(t, ok)
				assert.Equal(t, cerrors.ErrorTypeInvalidInput, domainErr.Type)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mocks for this test case
			tc.beforeFunc(deps)

			// Execute the test
			user, err := authService.Register(tc.args)

			// Check error expectation and basic assertions
			tc.afterFunc(t, user, err)

			// Only perform these assertions if there was no error
			if err == nil {
				assert.NotNil(t, user)
				assert.Equal(t, tc.args.Email, user.Email)
				assert.Equal(t, tc.args.FirstName, user.FirstName)
				assert.Equal(t, tc.args.LastName, user.LastName)
				assert.False(t, user.IsEmailVerified)

				// Verify that password was hashed
				assert.NotEqual(t, tc.args.Password, user.HashedPassword)
				bcryptErr := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(tc.args.Password))
				assert.NoError(t, bcryptErr)
			}
		})
	}

	// Verify mocks were called with expected values
	deps.userRepo.AssertExpectations(t)
	deps.authRepo.AssertExpectations(t)
	deps.tokenSvc.AssertExpectations(t)
}

func TestAuthService_Login(t *testing.T) {
	// Setup test dependencies
	deps := SetupTestDependencies()
	AuthServiceSetupMockLogger(deps.logger)
	authService := newTestAuthService(deps)

	// Test cases
	tests := []struct {
		name       string
		args       domain.LoginRequest
		beforeFunc func(*TestDependencies)
		afterFunc  func(*testing.T, string, error)
	}{
		{
			name: "successful login",
			args: domain.LoginRequest{
				Email:    "test@example.com",
				Password: "Password123!",
			},
			beforeFunc: func(d *TestDependencies) {
				hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("Password123!"), bcrypt.DefaultCost)
				user := &domain.User{
					ID:              "user-123",
					Email:           "test@example.com",
					HashedPassword:  string(hashedPassword),
					IsEmailVerified: true,
				}
				d.userRepo.On("GetByEmail", "test@example.com").Return(user, nil)
				d.tokenSvc.On("GenerateToken", "user-123").Return("jwt-token-123", nil)
			},
			afterFunc: func(t *testing.T, token string, err error) {
				assert.NoError(t, err)
				assert.Equal(t, "jwt-token-123", token)
			},
		},
		{
			name: "user not found",
			args: domain.LoginRequest{
				Email:    "nonexistent@example.com",
				Password: "Password123!",
			},
			beforeFunc: func(d *TestDependencies) {
				d.userRepo.On("GetByEmail", "nonexistent@example.com").Return(nil, errors.New("user not found"))
			},
			afterFunc: func(t *testing.T, token string, err error) {
				assert.Error(t, err)
				assert.Empty(t, token)
				domainErr, ok := err.(*cerrors.DomainError)
				assert.True(t, ok)
				assert.Equal(t, cerrors.ErrorTypeNotFound, domainErr.Type)
			},
		},
		{
			name: "invalid password",
			args: domain.LoginRequest{
				Email:    "test@example.com",
				Password: "WrongPassword123!",
			},
			beforeFunc: func(d *TestDependencies) {
				hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("Password123!"), bcrypt.DefaultCost)
				user := &domain.User{
					ID:              "user-123",
					Email:           "test@example.com",
					HashedPassword:  string(hashedPassword),
					IsEmailVerified: true,
				}
				d.userRepo.On("GetByEmail", "test@example.com").Return(user, nil)
			},
			afterFunc: func(t *testing.T, token string, err error) {
				assert.Error(t, err)
				assert.Empty(t, token)
				domainErr, ok := err.(*cerrors.DomainError)
				assert.True(t, ok)
				assert.Equal(t, cerrors.ErrorTypeInvalidAuth, domainErr.Type)
			},
		},
		// {
		// 	name: "email not verified",
		// 	req: domain.LoginRequest{
		// 		Email:    "unverified@example.com",
		// 		Password: "Password123!",
		// 	},
		// 	setupMocks: func(d *testDependencies) {
		// 		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("Password123!"), bcrypt.DefaultCost)
		// 		user := &domain.User{
		// 			ID:              "user-123",
		// 			Email:           "unverified@example.com",
		// 			HashedPassword:  string(hashedPassword),
		// 			IsEmailVerified: false,
		// 		}
		// 		d.userRepo.On("GetByEmail", "unverified@example.com").Return(user, nil)
		// 	},
		// 	expect: func(t *testing.T, token string, err error) {
		// 		assert.Error(t, err)
		// 		assert.Empty(t, token)
		// 		domainErr, ok := err.(*cerrors.DomainError)
		// 		assert.True(t, ok)
		// 		assert.Equal(t, cerrors.ErrorTypeUnauthorized, domainErr.Type)
		// 	},
		// },
		// {
		// 	name: "invalid email format",
		// 	req: domain.LoginRequest{
		// 		Email:    "invalid-email",
		// 		Password: "Password123!",
		// 	},
		// 	setupMocks: func(d *testDependencies) {
		// 	},
		// 	expect: func(t *testing.T, token string, err error) {
		// 		assert.Error(t, err)
		// 		assert.Empty(t, token)
		// 		domainErr, ok := err.(*cerrors.DomainError)
		// 		assert.True(t, ok)
		// 		assert.Equal(t, cerrors.ErrorTypeInvalidInput, domainErr.Type)
		// 	},
		// },
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mocks for this test case
			tc.beforeFunc(deps)

			// Execute the test
			token, err := authService.Login(tc.args)

			// Run assertions
			tc.afterFunc(t, token, err)

			// Verify mocks were called with expected values
			deps.userRepo.AssertExpectations(t)
			deps.tokenSvc.AssertExpectations(t)
		})
	}
}
