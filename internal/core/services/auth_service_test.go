package services

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	cerrors "github.com/Businge931/sba-user-accounts/internal/core/errors"

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
				// Check if user exists
				d.userRepo.On("GetByEmail", "test@example.com").Return(nil, errors.New("not found"))

				// Mock the identity provider Register method
				expectedUser := &domain.User{
					Email:           "test@example.com",
					FirstName:       "John",
					LastName:        "Doe",
					IsEmailVerified: false,
					HashedPassword:  "hashed-password", // Identity provider handles hashing
				}
				d.identitySvc.On("Register", mock.MatchedBy(func(req domain.RegisterRequest) bool {
					return req.Email == "test@example.com" &&
						req.Password == "Password123!" &&
						req.FirstName == "John" &&
						req.LastName == "Doe"
				})).Return(expectedUser, nil)

				// Mock the user repository Create method
				d.userRepo.On("Create", mock.AnythingOfType("*domain.User")).Return(nil)
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
				// No need to mock identity provider as the function should return early
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
				// No mocks needed as validation should fail
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
				// No mocks needed as validation should fail
			},
			afterFunc: func(t *testing.T, user *domain.User, err error) {
				assert.Error(t, err)
				domainErr, ok := err.(*cerrors.DomainError)
				assert.True(t, ok)
				assert.Equal(t, cerrors.ErrorTypeInvalidInput, domainErr.Type)
			},
		},
		{
			name: "identity provider registration failure",
			args: domain.RegisterRequest{
				Email:     "fail@example.com",
				Password:  "Password123!",
				FirstName: "Fail",
				LastName:  "User",
			},
			beforeFunc: func(d *TestDependencies) {
				// User doesn't exist
				d.userRepo.On("GetByEmail", "fail@example.com").Return(nil, errors.New("not found"))

				// Identity provider fails
				d.identitySvc.On("Register", mock.MatchedBy(func(req domain.RegisterRequest) bool {
					return req.Email == "fail@example.com"
				})).Return(nil, errors.New("identity provider error"))
			},
			afterFunc: func(t *testing.T, user *domain.User, err error) {
				assert.Error(t, err)
				assert.Nil(t, user)
				assert.Contains(t, err.Error(), "failed to register user")
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

		})
	}

	// Verify mocks were called with expected values
	deps.userRepo.AssertExpectations(t)
	deps.identitySvc.AssertExpectations(t)
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
				// Set up logger mock for this specific test case
				AuthServiceSetupMockLogger(d.logger)

				// Mock user repository
				user := &domain.User{
					ID:              "user-123",
					Email:           "test@example.com",
					HashedPassword:  "hashed-password", // Not used directly anymore
					IsEmailVerified: true,
				}
				d.userRepo.On("GetByEmail", "test@example.com").Return(user, nil)

				// Mock identity provider login
				d.identitySvc.On("Login",
					mock.MatchedBy(func(req domain.LoginRequest) bool {
						return req.Email == "test@example.com" && req.Password == "Password123!"
					}),
					mock.MatchedBy(func(u *domain.User) bool {
						return u.ID == "user-123"
					}),
				).Return("jwt-token-123", nil)
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
				// Set up logger mock for this specific test case
				AuthServiceSetupMockLogger(d.logger)

				d.userRepo.On("GetByEmail", "nonexistent@example.com").Return(nil, errors.New("user not found"))
				// No need to mock identity provider as the function should return early
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
			name: "identity provider authentication failure",
			args: domain.LoginRequest{
				Email:    "test@example.com",
				Password: "WrongPassword123!",
			},
			beforeFunc: func(d *TestDependencies) {
				// Set up logger mock for this specific test case
				AuthServiceSetupMockLogger(d.logger)

				// User exists
				user := &domain.User{
					ID:              "user-123",
					Email:           "test@example.com",
					HashedPassword:  "hashed-password", // Not used directly anymore
					IsEmailVerified: true,
				}
				d.userRepo.On("GetByEmail", "test@example.com").Return(user, nil)

				// Identity provider returns authentication error
				d.identitySvc.On("Login",
					mock.MatchedBy(func(req domain.LoginRequest) bool {
						return req.Email == "test@example.com" && req.Password == "WrongPassword123!"
					}),
					mock.MatchedBy(func(u *domain.User) bool {
						return u.ID == "user-123"
					}),
				).Return("", cerrors.NewInvalidAuthError("invalid credentials", nil))
			},
			afterFunc: func(t *testing.T, token string, err error) {
				assert.Error(t, err)
				assert.Empty(t, token)
				domainErr, ok := err.(*cerrors.DomainError)
				assert.True(t, ok)
				assert.Equal(t, cerrors.ErrorTypeInvalidAuth, domainErr.Type)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mocks for this test case
			tc.beforeFunc(deps)

			// Execute the test
			token, err := authService.Login(tc.args)

			// Run assertions
			tc.afterFunc(t, token, err)

		})
	}

	// Verify mocks were called with expected values
	deps.userRepo.AssertExpectations(t)
	deps.identitySvc.AssertExpectations(t)
}
