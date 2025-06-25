package grpc

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	dcerrors "github.com/Businge931/sba-user-accounts/internal/core/errors"
)

// mapLoginError maps domain errors to appropriate gRPC status errors for login operations
func mapLoginError(err error) error {
	switch {
	case errors.Is(err, dcerrors.ErrNotFound):
		return status.Error(codes.NotFound, "Account not found. Please check your username or register.")
	case errors.Is(err, dcerrors.ErrInvalidAuth):
		return status.Error(codes.Unauthenticated, "Incorrect username or password. Please try again.")
	case errors.Is(err, dcerrors.ErrUnauthorized):
		return status.Error(codes.PermissionDenied, "Please verify your email before logging in.")
	default:
		// For any other unexpected errors
		return status.Error(codes.Internal, "An unexpected error occurred. Please try again later.")
	}
}