package identityprovider

import (
	"context"
	"fmt"

	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/identity_provider/firebase"
	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	dcerrors "github.com/Businge931/sba-user-accounts/internal/core/errors"
	"github.com/Businge931/sba-user-accounts/internal/core/ports"
	"github.com/sirupsen/logrus"
)

type firebaseAuthProvider struct {
	client *firebase.FirebaseClient
	logger *logrus.Logger
}

func NewFirebaseAuthProvider(client *firebase.FirebaseClient, logger *logrus.Logger) ports.IdentityService {
	return &firebaseAuthAdapter{
		provider: &firebaseAuthProvider{
			client: client,
			logger: logger,
		},
	}
}

// firebaseAuthAdapter adapts firebaseAuthProvider to implement ports.IdentityService
// without context parameters by creating contexts internally
type firebaseAuthAdapter struct {
	provider *firebaseAuthProvider
}

// Implement ports.IdentityService interface (without context parameters)
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

func (p *firebaseAuthProvider) RegisterSvc(ctx context.Context, req domain.RegisterRequest) (*domain.User, string, error) {
	// Create the user in Firebase
	user, err := p.client.CreateUser(ctx, req.Email, req.Password, req.FirstName, req.LastName)
	if err != nil {
		p.logger.Errorf("Failed to create Firebase user: %v", err)
		return nil, "", fmt.Errorf("failed to create user: %w", err)
	}

	// Generate email verification link
	verificationLink, err := p.client.SendVerificationEmail(ctx, req.Email)
	if err != nil {
		p.logger.Errorf("Failed to send verification email: %v", err)
		// Continue without failing since we can still create the user
	}

	// Map to domain user
	domainUser := &domain.User{
		ID:              user.ID,
		Email:           user.Email,
		FirstName:       user.FirstName,
		LastName:        user.LastName,
		IsEmailVerified: user.IsEmailVerified,
	}

	return domainUser, verificationLink, nil
}

func (p *firebaseAuthProvider) verifyPassword(ctx context.Context, email, password string) (string, error) {
	// Verify the password using the Firebase client
	userID, err := p.client.VerifyPassword(ctx, email, password)
	if err != nil {
		p.logger.Debugf("Authentication failed for user %s: %v", email, err)
		return "", dcerrors.ErrInvalidAuth
	}

	p.logger.Debugf("Successfully verified password for user: %s", email)
	return userID, nil
}

func (p *firebaseAuthProvider) LoginSvc(ctx context.Context, req domain.LoginRequest, user *domain.User) (string, error) {
	if user == nil {
		p.logger.Error("Login attempt with nil user")
		return "", dcerrors.ErrInvalidAuth
	}

	// Verify the password with Firebase
	userID, err := p.verifyPassword(ctx, req.Email, req.Password)
	if err != nil {
		// verifyPassword returns standard domain errors
		p.logger.Debugf("Login failed for user with email %s: %v", req.Email, err)
		return "", err
	}

	// Double-check that the user ID matches
	if userID != user.ID {
		err := fmt.Errorf("user ID mismatch: expected %s, got %s", user.ID, userID)
		p.logger.Errorf("Authentication failed: %v", err)
		return "", dcerrors.ErrInternal
	}

	// Generate a custom token for the user
	token, err := p.client.CreateCustomToken(ctx, userID)
	if err != nil {
		p.logger.Errorf("Failed to generate custom token for user %s: %v", user.ID, err)
		return "", dcerrors.ErrInternal
	}

	// Log successful login (without logging sensitive data)
	p.logger.Infof("User %s logged in successfully", user.ID)

	return token, nil
}

func (p *firebaseAuthProvider) VerifyEmailSvc(ctx context.Context, token string) (string, error) {
	// Verify the email verification token
	err := p.client.VerifyEmail(ctx, token)
	if err != nil {
		p.logger.Errorf("Failed to verify email token: %v", err)
		return "", fmt.Errorf("invalid or expired verification token")
	}

	// Get the user's ID from the token
	userID, err := p.client.VerifyIDToken(ctx, token)
	if err != nil {
		p.logger.Errorf("Failed to get user ID from token: %v", err)
		return "", fmt.Errorf("invalid token")
	}

	return userID, nil
}

func (p *firebaseAuthProvider) RequestPasswordResetSvc(ctx context.Context, email string) (string, error) {
	// Send password reset email
	resetLink, err := p.client.SendPasswordResetEmail(ctx, email)
	if err != nil {
		p.logger.Errorf("Failed to send password reset email: %v", err)
		return "", fmt.Errorf("failed to send password reset email")
	}

	return resetLink, nil
}

func (p *firebaseAuthProvider) ResetPasswordSvc(ctx context.Context, token, newPassword string) (string, string, error) {
	// Note: Firebase handles the password reset flow via email link
	// This method is called after the user has clicked the reset link and submitted a new password
	// The token should be verified by the frontend before calling this method

	// Get the user ID from the token
	userID, err := p.client.VerifyIDToken(ctx, token)
	if err != nil {
		p.logger.Errorf("Failed to verify token: %v", err)
		return "", "", fmt.Errorf("invalid or expired token")
	}

	// Update the user's password
	err = p.client.UpdatePassword(ctx, userID, newPassword)
	if err != nil {
		p.logger.Errorf("Failed to update user password: %v", err)
		return "", "", fmt.Errorf("failed to reset password")
	}

	// Generate a new token for the user
	newToken, err := p.client.CreateCustomToken(ctx, userID)
	if err != nil {
		p.logger.Errorf("Failed to generate new token: %v", err)
		return "", "", fmt.Errorf("failed to generate new token")
	}

	return userID, newToken, nil
}

func (p *firebaseAuthProvider) ChangePasswordSvc(ctx context.Context, userID, oldPassword, newPassword string) (string, error) {
	// Get the user by ID
	user, err := p.client.GetUserByEmail(ctx, userID) // Using email as ID for now
	if err != nil {
		p.logger.Errorf("Failed to get user: %v", err)
		return "", fmt.Errorf("user not found")
	}

	// Verify the old password
	_, err = p.verifyPassword(ctx, user.Email, oldPassword)
	if err != nil {
		p.logger.Debugf("Failed to verify old password for user %s: %v", userID, err)
		return "", fmt.Errorf("invalid old password")
	}

	// Update to the new password
	err = p.client.UpdatePassword(ctx, user.ID, newPassword)
	if err != nil {
		p.logger.Errorf("Failed to update password: %v", err)
		return "", fmt.Errorf("failed to update password")
	}

	// Generate a new token for the user
	newToken, err := p.client.CreateCustomToken(ctx, user.ID)
	if err != nil {
		p.logger.Errorf("Failed to generate new token: %v", err)
		return "", fmt.Errorf("failed to generate new token")
	}

	return newToken, nil
}
