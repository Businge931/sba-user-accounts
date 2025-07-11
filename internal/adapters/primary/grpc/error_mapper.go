package grpc

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	dcerrors "github.com/Businge931/sba-user-accounts/internal/core/errors"
)

// MapError maps domain errors to appropriate gRPC status errors
// It uses the error message from the original error
func MapError(err error) error {
	if err == nil {
		return nil
	}

	// For domain errors, use their message directly
	var domainErr *dcerrors.DomainError
	if errors.As(err, &domainErr) {
		switch domainErr.Type {
		case dcerrors.ErrorTypeNotFound:
			return status.Error(codes.NotFound, domainErr.Error())
		case dcerrors.ErrorTypeAlreadyExists:
			return status.Error(codes.AlreadyExists, domainErr.Error())
		case dcerrors.ErrorTypeInvalidAuth:
			return status.Error(codes.Unauthenticated, domainErr.Error())
		case dcerrors.ErrorTypeUnauthorized:
			return status.Error(codes.PermissionDenied, domainErr.Error())
		case dcerrors.ErrorTypeInvalidInput:
			return status.Error(codes.InvalidArgument, domainErr.Error())
		case dcerrors.ErrorTypeTokenExpired:
			return status.Error(codes.Unauthenticated, domainErr.Error())
		}
	}

	// For standard errors, use their message directly
	switch {
	case errors.Is(err, dcerrors.ErrUserNotFound):
		return status.Error(codes.NotFound, dcerrors.ErrUserNotFound.Error())
	case errors.Is(err, dcerrors.ErrEmailAlreadyExists):
		return status.Error(codes.AlreadyExists, dcerrors.ErrEmailAlreadyExists.Error())
	case errors.Is(err, dcerrors.ErrInvalidAuth):
		return status.Error(codes.Unauthenticated, dcerrors.ErrInvalidAuth.Error())
	case errors.Is(err, dcerrors.ErrUnauthorized):
		return status.Error(codes.PermissionDenied, dcerrors.ErrUnauthorized.Error())
	case errors.Is(err, dcerrors.ErrInvalidInput):
		return status.Error(codes.InvalidArgument, dcerrors.ErrInvalidInput.Error())
	case errors.Is(err, dcerrors.ErrTokenExpired):
		return status.Error(codes.Unauthenticated, dcerrors.ErrTokenExpired.Error())
	}

	// Default to internal server error with a generic message
	return status.Error(codes.Internal, dcerrors.ErrInternal.Error())
}

// MapLoginError provides specific error mapping for login-related errors
// It returns a generic "invalid credentials" message for security
func MapLoginError(err error) error {
	switch {
	case errors.Is(err, dcerrors.ErrUserNotFound),
		errors.Is(err, dcerrors.ErrInvalidAuth):
		return status.Error(codes.Unauthenticated, "Invalid email or password")
	case errors.Is(err, dcerrors.ErrTokenExpired):
		return status.Error(codes.Unauthenticated, dcerrors.ErrTokenExpired.Error())
	}

	// Fall back to the general error mapper
	return MapError(err)
}
