package services

import (
	"errors"
	"testing"

	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/validation"
	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	cerrors "github.com/Businge931/sba-user-accounts/internal/core/errors"
	"github.com/Businge931/sba-user-accounts/internal/core/services/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

// testDependencies contains all the mock dependencies needed for auth service tests
type testDependencies struct {
	userRepo  *mocks.MockUserRepository
	authRepo  *mocks.MockAuthRepository
	tokenSvc  *mocks.MockTokenService
	logger    *mocks.MockLogger
	validator *validation.Validator
}

// setupTestDependencies creates and returns all the mock dependencies needed for testing
func setupTestDependencies() *testDependencies {
	return &testDependencies{
		userRepo:  new(mocks.MockUserRepository),
		authRepo:  new(mocks.MockAuthRepository),
		tokenSvc:  new(mocks.MockTokenService),
		logger:    new(mocks.MockLogger),
		validator: validation.NewValidator(),
	}
}

// setupMockLogger sets up common expectations for the logger
func setupMockLogger(logger *mocks.MockLogger) {
	logger.On("Debug", mock.Anything).Return()
	logger.On("Debugf", mock.Anything, mock.Anything).Return()
	logger.On("Info", mock.Anything).Return()
	logger.On("Infof", mock.Anything, mock.Anything).Return()
	logger.On("Warn", mock.Anything).Return()
	logger.On("Warnf", mock.Anything, mock.Anything).Return()
	logger.On("Error", mock.Anything).Return()
	logger.On("Errorf", mock.Anything, mock.Anything).Return()
}

// newTestAuthService creates a new AuthService instance with the provided dependencies
func newTestAuthService(deps *testDependencies) *authService {
	return &authService{
		userRepo:  deps.userRepo,
		authRepo:  deps.authRepo,
		tokenSvc:  deps.tokenSvc,
		validator: deps.validator,
		logger:    deps.logger,
	}
}

func TestAuthService_Register(t *testing.T) {
	// Setup test dependencies
	deps := setupTestDependencies()
	setupMockLogger(deps.logger)
	authService := newTestAuthService(deps)

	tests := []struct {
		name       string
		req        domain.RegisterRequest
		setupMocks func(*testDependencies)
		expect     func(*testing.T, *domain.User, error)
		extraCheck func(*testing.T, *domain.User, error)
	}{
		{
			name: "successful registration",
			req: domain.RegisterRequest{
				Email:     "test@example.com",
				Password:  "Password123!",
				FirstName: "John",
				LastName:  "Doe",
			},
			setupMocks: func(d *testDependencies) {
				d.userRepo.On("GetByEmail", "test@example.com").Return(nil, errors.New("not found"))
				d.userRepo.On("Create", mock.AnythingOfType("*domain.User")).Return(nil)
				d.tokenSvc.On("GenerateVerificationToken").Return("verification-token")
				d.authRepo.On("StoreVerificationToken", mock.Anything, "verification-token").Return(nil)
			},
			expect: func(t *testing.T, user *domain.User, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, user)
				assert.Equal(t, "test@example.com", user.Email)
				assert.Equal(t, "John", user.FirstName)
				assert.Equal(t, "Doe", user.LastName)
				assert.False(t, user.IsEmailVerified)
			},
			extraCheck: func(t *testing.T, user *domain.User, err error) {
				// Additional checks if needed
			},
		},
		{
			name: "user already exists",
			req: domain.RegisterRequest{
				Email:     "existing@example.com",
				Password:  "Password123!",
				FirstName: "Existing",
				LastName:  "User",
			},
			setupMocks: func(d *testDependencies) {
				existingUser := &domain.User{
					ID:             "existing-user-id",
					Email:          "existing@example.com",
					HashedPassword: "hashed-password",
					FirstName:      "Existing",
					LastName:       "User",
				}
				d.userRepo.On("GetByEmail", "existing@example.com").Return(existingUser, nil)
			},
			expect: func(t *testing.T, user *domain.User, err error) {
				assert.Error(t, err)
				// The error is not wrapped in a DomainError, so we just check the error message
				assert.Contains(t, err.Error(), "user with this email already exists")
				// User should be nil when there's an error
				assert.Nil(t, user)
			},
			extraCheck: func(t *testing.T, user *domain.User, err error) {
				// Additional checks if needed
			},
		},
		{
			name: "invalid email",
			req: domain.RegisterRequest{
				Email:     "invalid-email",
				Password:  "Password123!",
				FirstName: "Test",
				LastName:  "User",
			},
			setupMocks: func(d *testDependencies) {
			},
			expect: func(t *testing.T, user *domain.User, err error) {
				assert.Error(t, err)
				domainErr, ok := err.(*cerrors.DomainError)
				assert.True(t, ok)
				assert.Equal(t, cerrors.ErrorTypeInvalidInput, domainErr.Type)
			},
			extraCheck: func(t *testing.T, user *domain.User, err error) {
				// Additional checks if needed
			},
		},
		{
			name: "invalid password",
			req: domain.RegisterRequest{
				Email:     "valid@example.com",
				Password:  "weak",
				FirstName: "Test",
				LastName:  "User",
			},
			setupMocks: func(d *testDependencies) {
			},
			expect: func(t *testing.T, user *domain.User, err error) {
				assert.Error(t, err)
				domainErr, ok := err.(*cerrors.DomainError)
				assert.True(t, ok)
				assert.Equal(t, cerrors.ErrorTypeInvalidInput, domainErr.Type)
			},
			extraCheck: func(t *testing.T, user *domain.User, err error) {
				// Additional checks if needed
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mocks for this test case
			tc.setupMocks(deps)

			// Execute the test
			user, err := authService.Register(tc.req)

			// Check error expectation and basic assertions
			tc.expect(t, user, err)

			// Additional checks if needed
			tc.extraCheck(t, user, err)

			// Only perform these assertions if there was no error
			if err == nil {
				assert.NotNil(t, user)
				assert.Equal(t, tc.req.Email, user.Email)
				assert.Equal(t, tc.req.FirstName, user.FirstName)
				assert.Equal(t, tc.req.LastName, user.LastName)
				assert.False(t, user.IsEmailVerified)

				// Verify that password was hashed
				assert.NotEqual(t, tc.req.Password, user.HashedPassword)
				bcryptErr := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(tc.req.Password))
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
	deps := setupTestDependencies()
	setupMockLogger(deps.logger)
	authService := newTestAuthService(deps)

	// Test cases
	tests := []struct {
		name       string
		req        domain.LoginRequest
		setupMocks func(*testDependencies)
		expect     func(*testing.T, string, error)
	}{
		{
			name: "successful login",
			req: domain.LoginRequest{
				Email:    "test@example.com",
				Password: "Password123!",
			},
			setupMocks: func(d *testDependencies) {
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
			expect: func(t *testing.T, token string, err error) {
				assert.NoError(t, err)
				assert.Equal(t, "jwt-token-123", token)
			},
		},
		{
			name: "user not found",
			req: domain.LoginRequest{
				Email:    "nonexistent@example.com",
				Password: "Password123!",
			},
			setupMocks: func(d *testDependencies) {
				d.userRepo.On("GetByEmail", "nonexistent@example.com").Return(nil, errors.New("user not found"))
			},
			expect: func(t *testing.T, token string, err error) {
				assert.Error(t, err)
				assert.Empty(t, token)
				domainErr, ok := err.(*cerrors.DomainError)
				assert.True(t, ok)
				assert.Equal(t, cerrors.ErrorTypeNotFound, domainErr.Type)
			},
		},
		{
			name: "invalid password",
			req: domain.LoginRequest{
				Email:    "test@example.com",
				Password: "WrongPassword123!",
			},
			setupMocks: func(d *testDependencies) {
				hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("Password123!"), bcrypt.DefaultCost)
				user := &domain.User{
					ID:              "user-123",
					Email:           "test@example.com",
					HashedPassword:  string(hashedPassword),
					IsEmailVerified: true,
				}
				d.userRepo.On("GetByEmail", "test@example.com").Return(user, nil)
			},
			expect: func(t *testing.T, token string, err error) {
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
			tc.setupMocks(deps)

			// Execute the test
			token, err := authService.Login(tc.req)

			// Run assertions
			tc.expect(t, token, err)

			// Verify mocks were called with expected values
			deps.userRepo.AssertExpectations(t)
			deps.tokenSvc.AssertExpectations(t)
		})
	}
}
