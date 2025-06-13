package services

import (
	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/validation"
	"github.com/Businge931/sba-user-accounts/internal/core/services/mocks"
	"github.com/stretchr/testify/mock"
)

// TestDependencies contains all the mock dependencies needed for auth service tests
type TestDependencies struct {
	userRepo  *mocks.MockUserRepository
	authRepo  *mocks.MockAuthRepository
	tokenSvc  *mocks.MockTokenService
	logger    *mocks.MockLogger
	validator *validation.Validator
}

// SetupTestDependencies creates and returns all the mock dependencies needed for testing
func SetupTestDependencies() *TestDependencies {
	return &TestDependencies{
		userRepo:  new(mocks.MockUserRepository),
		authRepo:  new(mocks.MockAuthRepository),
		tokenSvc:  new(mocks.MockTokenService),
		logger:    new(mocks.MockLogger),
		validator: validation.NewValidator(),
	}
}

// SetupMockLogger sets up common expectations for the logger
func AuthServiceSetupMockLogger(logger *mocks.MockLogger) {
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
func newTestAuthService(deps *TestDependencies) *authService {
	return &authService{
		userRepo: deps.userRepo,
		// authRepo:  deps.authRepo,
		// tokenSvc:  deps.tokenSvc,
		validator: deps.validator,
		logger:    deps.logger,
	}
}
