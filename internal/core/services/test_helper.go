package services

import (
	"github.com/Businge931/sba-user-accounts/internal/core/errors"
	"github.com/stretchr/testify/mock"
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
