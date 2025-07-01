package http

import (
	stderrors "errors"
	"net/http"

	coreerrors "github.com/Businge931/sba-user-accounts/internal/core/errors"
)

// handleError handles errors by mapping them to appropriate HTTP status codes
func handleError(w http.ResponseWriter, err error) {
	// Check for domain errors first
	var domainErr *coreerrors.DomainError
	if stderrors.As(err, &domainErr) {
		switch domainErr.Type {
		case coreerrors.ErrorTypeNotFound:
			http.Error(w, domainErr.Error(), http.StatusNotFound)
		case coreerrors.ErrorTypeAlreadyExists:
			http.Error(w, domainErr.Error(), http.StatusConflict)
		case coreerrors.ErrorTypeInvalidAuth, coreerrors.ErrorTypeUnauthorized:
			http.Error(w, domainErr.Error(), http.StatusUnauthorized)
		case coreerrors.ErrorTypeInvalidInput:
			http.Error(w, domainErr.Error(), http.StatusBadRequest)
		case coreerrors.ErrorTypeTokenExpired:
			http.Error(w, domainErr.Error(), http.StatusUnauthorized)
		default:
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// Check for standard errors
	switch {
	case stderrors.Is(err, coreerrors.ErrNotFound), stderrors.Is(err, coreerrors.ErrUserNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case stderrors.Is(err, coreerrors.ErrAlreadyExists), stderrors.Is(err, coreerrors.ErrEmailAlreadyExists):
		http.Error(w, err.Error(), http.StatusConflict)
	case stderrors.Is(err, coreerrors.ErrInvalidAuth), stderrors.Is(err, coreerrors.ErrUnauthorized), 
		stderrors.Is(err, coreerrors.ErrTokenExpired):
		http.Error(w, err.Error(), http.StatusUnauthorized)
	case stderrors.Is(err, coreerrors.ErrInvalidInput):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case stderrors.Is(err, coreerrors.ErrInternal):
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	default:
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
