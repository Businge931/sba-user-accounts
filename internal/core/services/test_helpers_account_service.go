package services

import (
	"github.com/Businge931/sba-user-accounts/internal/core/errors"
	"github.com/stretchr/testify/mock"
	"github.com/Businge931/sba-user-accounts/internal/core/services/mocks"
	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/validation"

)

// Define error types to match the ones in the core errors package
type NotFoundError struct {
	*errors.DomainError
}

type AlreadyExistsError struct {
	*errors.DomainError
}

type InvalidAuthError struct {
	*errors.DomainError
}

type ValidationError struct {
	*errors.DomainError
}

type InvalidInputError struct {
	*errors.DomainError
}


type testDeps struct {
	userRepo  *mocks.MockUserRepository
	authRepo  *mocks.MockAuthRepository
	tokenSvc  *mocks.MockTokenService
	logger    *mocks.MockLogger
	validator *validation.Validator
}

func setUpTestDeps() *testDeps {
	return &testDeps{
		userRepo:  new(mocks.MockUserRepository),
		authRepo:  new(mocks.MockAuthRepository),
		tokenSvc:  new(mocks.MockTokenService),
		logger:    new(mocks.MockLogger),
		validator: validation.NewValidator(),
	}
}

func setupLoggerExpectations(logger *mocks.MockLogger) {
	logger.On("Debug", mock.Anything).Return()
	logger.On("Debugf", mock.Anything, mock.Anything).Return()
	logger.On("Info", mock.Anything).Return()
	logger.On("Infof", mock.Anything, mock.Anything).Return()
	logger.On("Warn", mock.Anything).Return()
	logger.On("Warnf", mock.Anything, mock.Anything).Return()
	logger.On("Error", mock.Anything).Return()
	logger.On("Errorf", mock.Anything, mock.Anything).Return()
}

func newTestAccountService(deps *testDeps) *accountManagementService {
	return &accountManagementService{
		userRepo:  deps.userRepo,
		authRepo:  deps.authRepo,
		tokenSvc:  deps.tokenSvc,
		emailSvc:  nil, // No email service for tests
		validator: deps.validator,
		logger:    deps.logger,
	}
}


// SetupMockLogger configures common expectations for the logger
func SetupMockLogger(logger *mock.Mock) {
	logger.On("Debug", mock.Anything).Maybe().Return()
	logger.On("Debugf", mock.Anything, mock.Anything).Maybe().Return()
	logger.On("Info", mock.Anything).Maybe().Return()
	logger.On("Infof", mock.Anything, mock.Anything).Maybe().Return()
	logger.On("Warn", mock.Anything).Maybe().Return()
	logger.On("Warnf", mock.Anything, mock.Anything).Maybe().Return()
	logger.On("Error", mock.Anything).Maybe().Return()
	logger.On("Errorf", mock.Anything, mock.Anything).Maybe().Return()
	logger.On("Fatal", mock.Anything).Maybe().Return()
	logger.On("Fatalf", mock.Anything, mock.Anything).Maybe().Return()
}
