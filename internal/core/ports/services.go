package ports

import "github.com/Businge931/sba-user-accounts/internal/core/domain"

// AuthService defines the interface for core authentication operations
type AuthService interface {
	Register(email, password, firstName, lastName string) (*domain.User, error)
	Login(email, password string) (string, error) // returns JWT token
}

// AccountManagementService defines the interface for account operations
type AccountManagementService interface {
	VerifyEmail(token string) error
	RequestPasswordReset(email string) error
	ResetPassword(token, newPassword string) error
	ChangePassword(userID, oldPassword, newPassword string) error
}

// EmailService defines the interface for email operations
type EmailService interface {
	SendVerificationEmail(to, token string) error
	SendPasswordResetEmail(to, token string) error
}
