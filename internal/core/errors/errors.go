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
	// New error types for auth flow
	ErrTooManyAttempts  = errors.New("too many login attempts, please try again later")
	ErrAccountDisabled  = errors.New("account has been disabled")
	
	// Specific authentication error types
	ErrInvalidEmail     = errors.New("invalid email address")
	ErrInvalidPassword  = errors.New("invalid password")
	ErrWrongPassword    = errors.New("incorrect password")
	ErrEmailNotRegistered = errors.New("email address is not registered")
	ErrEmailNotVerified = errors.New("email address is not verified")
	ErrWeakPassword     = errors.New("password does not meet security requirements")
	ErrPasswordTooShort = errors.New("password is too short")
	ErrPasswordTooLong  = errors.New("password is too long")
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
	ErrorTypeTooManyAttempts ErrorType = "TOO_MANY_ATTEMPTS"
	ErrorTypeAccountDisabled ErrorType = "ACCOUNT_DISABLED"
	// Specific authentication error types
	ErrorTypeInvalidEmail     ErrorType = "INVALID_EMAIL"
	ErrorTypeInvalidPassword  ErrorType = "INVALID_PASSWORD"
	ErrorTypeWrongPassword    ErrorType = "WRONG_PASSWORD"
	ErrorTypeEmailNotRegistered ErrorType = "EMAIL_NOT_REGISTERED"
	ErrorTypeEmailNotVerified ErrorType = "EMAIL_NOT_VERIFIED"
	ErrorTypeWeakPassword     ErrorType = "WEAK_PASSWORD"
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

// Helper functions for authentication-specific errors
func NewInvalidEmailError(message string, err error) error {
	return NewError(ErrorTypeInvalidEmail, message, err)
}

func NewInvalidPasswordError(message string, err error) error {
	return NewError(ErrorTypeInvalidPassword, message, err)
}

func NewWrongPasswordError(message string, err error) error {
	return NewError(ErrorTypeWrongPassword, message, err)
}

func NewEmailNotRegisteredError(message string, err error) error {
	return NewError(ErrorTypeEmailNotRegistered, message, err)
}

func NewEmailNotVerifiedError(message string, err error) error {
	return NewError(ErrorTypeEmailNotVerified, message, err)
}

func NewWeakPasswordError(message string, err error) error {
	return NewError(ErrorTypeWeakPassword, message, err)
}
