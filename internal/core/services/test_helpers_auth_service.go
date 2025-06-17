package services

import (
	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/validation"
	"github.com/Businge931/sba-user-accounts/internal/core/services/mocks"
	"github.com/stretchr/testify/mock"
)

type TestDependencies struct {
	userRepo    *mocks.MockUserRepository
	authRepo    *mocks.MockAuthRepository
	tokenSvc    *mocks.MockTokenService
	identitySvc *mocks.MockIdentityService
	logger      *mocks.MockLogger
	validator   *validation.Validator
}

// SetupTestDependencies creates and returns all the mock dependencies needed for testing
func SetupTestDependencies() *TestDependencies {
	return &TestDependencies{
		userRepo:    new(mocks.MockUserRepository),
		authRepo:    new(mocks.MockAuthRepository),
		tokenSvc:    new(mocks.MockTokenService),
		identitySvc: new(mocks.MockIdentityService),
		logger:      new(mocks.MockLogger),
		validator:   validation.NewValidator(),
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

func newTestAuthService(deps *TestDependencies) *authService {
	return &authService{
		userRepo:         deps.userRepo,
		validator:        deps.validator,
		logger:           deps.logger,
		
	}
}
