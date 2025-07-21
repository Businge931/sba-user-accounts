package identityprovider

import (
	"context"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
)

// firebaseAuthAdapter adapts firebaseAuthProvider to implement ports.IdentityService
// without context parameters by creating contexts internally
type firebaseAuthAdapter struct {
	provider *firebaseAuthProvider
}

func (a *firebaseAuthAdapter) RegisterSvc(req domain.RegisterRequest) (*domain.User, string, error) {
	ctx := context.Background()
	return a.provider.RegisterSvc(ctx, req)
}

func (a *firebaseAuthAdapter) LoginSvc(req domain.LoginRequest, user *domain.User) (string, error) {
	ctx := context.Background()
	return a.provider.LoginSvc(ctx, req, user)
}

func (a *firebaseAuthAdapter) VerifyEmailSvc(token string) (string, error) {
	ctx := context.Background()
	return a.provider.VerifyEmailSvc(ctx, token)
}

func (a *firebaseAuthAdapter) RequestPasswordResetSvc(email string) (string, error) {
	ctx := context.Background()
	return a.provider.RequestPasswordResetSvc(ctx, email)
}

func (a *firebaseAuthAdapter) ResetPasswordSvc(token, newPassword string) (string, string, error) {
	ctx := context.Background()
	return a.provider.ResetPasswordSvc(ctx, token, newPassword)
}

func (a *firebaseAuthAdapter) ChangePasswordSvc(userID, oldPassword, newPassword string) (string, error) {
	ctx := context.Background()
	return a.provider.ChangePasswordSvc(ctx, userID, oldPassword, newPassword)
}
