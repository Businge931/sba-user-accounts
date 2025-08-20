package identityprovider

import (
	"context"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
)

// FirebaseClient defines the interface for Firebase operations
type FirebaseClient interface {
	CreateUser(ctx context.Context, email, password, firstName, lastName string) (*domain.User, error)
	GetUserByEmail(ctx context.Context, email string) (*domain.User, error)
	UpdateUser(ctx context.Context, userID string, updates map[string]any) error
	VerifyIDToken(ctx context.Context, token string) (string, error)
	CreateCustomToken(ctx context.Context, userID string) (string, error)
	VerifyPassword(ctx context.Context, email, password string) (string, error)
	UpdatePassword(ctx context.Context, userID, newPassword string) error
	SendVerificationEmail(ctx context.Context, email string) (string, error)
	SendPasswordResetEmail(ctx context.Context, email string) (string, error)
	VerifyEmail(ctx context.Context, token string) error
}

// FirebaseAuthProvider defines the interface for Firebase auth provider operations
type FirebaseAuthProvider interface {
	RegisterSvc(ctx context.Context, req domain.RegisterRequest) (*domain.User, string, error)
	LoginSvc(ctx context.Context, req domain.LoginRequest, user *domain.User) (string, error)
	VerifyEmailSvc(ctx context.Context, token string) (string, error)
	RequestPasswordResetSvc(ctx context.Context, email string) (string, error)
	ResetPasswordSvc(ctx context.Context, token, newPassword string) (string, string, error)
	ChangePasswordSvc(ctx context.Context, userID, oldPassword, newPassword string) (string, error)
}
