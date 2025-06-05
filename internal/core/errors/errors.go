package errors

import (
	"errors"
	"fmt"
)

// Standard error types that can be used throughout the application
var (
	ErrNotFound         = errors.New("resource not found")
	ErrAlreadyExists    = errors.New("resource already exists")
	ErrEmailAlreadyExists = errors.New("email already exists")
	ErrInvalidAuth      = errors.New("invalid authentication")
	ErrUnauthorized     = errors.New("unauthorized")
	ErrInvalidInput     = errors.New("invalid input")
	ErrInternal         = errors.New("internal error")
	ErrTokenExpired     = errors.New("token expired")
	ErrUserNotFound     = errors.New("user not found")
)

// Domain error types
type ErrorType string

const (
	ErrorTypeNotFound      ErrorType = "NOT_FOUND"
	ErrorTypeAlreadyExists ErrorType = "ALREADY_EXISTS"
	ErrorTypeInvalidAuth   ErrorType = "INVALID_AUTH"
	ErrorTypeUnauthorized  ErrorType = "UNAUTHORIZED"
	ErrorTypeInvalidInput  ErrorType = "INVALID_INPUT"
	ErrorTypeInternal      ErrorType = "INTERNAL"
	ErrorTypeTokenExpired  ErrorType = "TOKEN_EXPIRED"
)

// DomainError represents a domain-specific error
type DomainError struct {
	Type    ErrorType
	Message string
	Err     error
}

// Error returns the error message
func (e *DomainError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Type, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// Unwrap returns the wrapped error
func (e *DomainError) Unwrap() error {
	return e.Err
}

// Is checks if the target error is of the same type
func (e *DomainError) Is(target error) bool {
	t, ok := target.(*DomainError)
	if !ok {
		return false
	}
	return e.Type == t.Type
}

// Creates a new domain error
func NewError(errorType ErrorType, message string, err error) error {
	return &DomainError{
		Type:    errorType,
		Message: message,
		Err:     err,
	}
}

// Helper functions for common error types
func NewNotFoundError(message string, err error) error {
	return NewError(ErrorTypeNotFound, message, err)
}

func NewAlreadyExistsError(message string, err error) error {
	return NewError(ErrorTypeAlreadyExists, message, err)
}

func NewInvalidAuthError(message string, err error) error {
	return NewError(ErrorTypeInvalidAuth, message, err)
}

func NewUnauthorizedError(message string, err error) error {
	return NewError(ErrorTypeUnauthorized, message, err)
}

func NewInvalidInputError(message string, err error) error {
	return NewError(ErrorTypeInvalidInput, message, err)
}

func NewInternalError(message string, err error) error {
	return NewError(ErrorTypeInternal, message, err)
}

func NewTokenExpiredError(message string, err error) error {
	return NewError(ErrorTypeTokenExpired, message, err)
}
