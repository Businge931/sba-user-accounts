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

// NewFirebaseAuthProvider creates a new instance of the Firebase Auth provider
func NewFirebaseAuthProvider(client *firebase.FirebaseClient, logger *logrus.Logger) ports.IdentityService {
	return &firebaseAuthProvider{
		client: client,
		logger: logger,
	}
}

func (p *firebaseAuthProvider) RegisterSvc(req domain.RegisterRequest) (*domain.User, string, error) {
	// Create the user in Firebase
	user, err := p.client.CreateUser(context.Background(), req.Email, req.Password, req.FirstName, req.LastName)
	if err != nil {
		p.logger.Errorf("Failed to create Firebase user: %v", err)
		return nil, "", fmt.Errorf("failed to create user: %w", err)
	}

	// Generate email verification link
	verificationLink, err := p.client.SendVerificationEmail(context.Background(), req.Email)
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

func (p *firebaseAuthProvider) verifyPassword(email, password string) (string, error) {
	// Verify the password using the Firebase client
	userID, err := p.client.VerifyPassword(context.Background(), email, password)
	if err != nil {
		p.logger.Debugf("Authentication failed for user %s: %v", email, err)
		return "", dcerrors.ErrInvalidAuth
	}

	p.logger.Debugf("Successfully verified password for user: %s", email)
	return userID, nil
}

func (p *firebaseAuthProvider) LoginSvc(req domain.LoginRequest, user *domain.User) (string, error) {
	if user == nil {
		p.logger.Error("Login attempt with nil user")
		return "", dcerrors.ErrInvalidAuth
	}

	// Verify the password with Firebase
	userID, err := p.verifyPassword(req.Email, req.Password)
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
	token, err := p.client.CreateCustomToken(context.Background(), userID)
	if err != nil {
		p.logger.Errorf("Failed to generate custom token for user %s: %v", user.ID, err)
		return "", dcerrors.ErrInternal
	}

	// Log successful login (without logging sensitive data)
	p.logger.Infof("User %s logged in successfully", user.ID)

	return token, nil
}

// VerifyEmailSvc verifies a user's email using the verification token
func (p *firebaseAuthProvider) VerifyEmailSvc(token string) (string, error) {
	// Verify the email verification token
	err := p.client.VerifyEmail(context.Background(), token)
	if err != nil {
		p.logger.Errorf("Failed to verify email token: %v", err)
		return "", fmt.Errorf("invalid or expired verification token")
	}

	// Get the user's ID from the token
	userID, err := p.client.VerifyIDToken(context.Background(), token)
	if err != nil {
		p.logger.Errorf("Failed to get user ID from token: %v", err)
		return "", fmt.Errorf("invalid token")
	}

	return userID, nil
}

// RequestPasswordResetSvc sends a password reset email to the user
func (p *firebaseAuthProvider) RequestPasswordResetSvc(email string) (string, error) {
	// Send password reset email
	resetLink, err := p.client.SendPasswordResetEmail(context.Background(), email)
	if err != nil {
		p.logger.Errorf("Failed to send password reset email: %v", err)
		return "", fmt.Errorf("failed to send password reset email")
	}

	return resetLink, nil
}

// ResetPasswordSvc resets a user's password using a reset token
func (p *firebaseAuthProvider) ResetPasswordSvc(token, newPassword string) (string, string, error) {
	// Note: Firebase handles the password reset flow via email link
	// This method is called after the user has clicked the reset link and submitted a new password
	// The token should be verified by the frontend before calling this method

	// Get the user ID from the token
	userID, err := p.client.VerifyIDToken(context.Background(), token)
	if err != nil {
		p.logger.Errorf("Failed to verify token: %v", err)
		return "", "", fmt.Errorf("invalid or expired token")
	}

	// Update the user's password
	err = p.client.UpdatePassword(context.Background(), userID, newPassword)
	if err != nil {
		p.logger.Errorf("Failed to update user password: %v", err)
		return "", "", fmt.Errorf("failed to reset password")
	}

	// Generate a new token for the user
	newToken, err := p.client.CreateCustomToken(context.Background(), userID)
	if err != nil {
		p.logger.Errorf("Failed to generate new token: %v", err)
		return "", "", fmt.Errorf("failed to generate new token")
	}

	return userID, newToken, nil
}

// ChangePasswordSvc changes a user's password
func (p *firebaseAuthProvider) ChangePasswordSvc(userID, oldPassword, newPassword string) (string, error) {
	// Get the user by ID
	user, err := p.client.GetUserByEmail(context.Background(), userID) // Using email as ID for now
	if err != nil {
		p.logger.Errorf("Failed to get user: %v", err)
		return "", fmt.Errorf("user not found")
	}

	// Verify the old password
	_, err = p.verifyPassword(user.Email, oldPassword)
	if err != nil {
		p.logger.Debugf("Failed to verify old password for user %s: %v", userID, err)
		return "", fmt.Errorf("invalid old password")
	}

	// Update to the new password
	err = p.client.UpdatePassword(context.Background(), user.ID, newPassword)
	if err != nil {
		p.logger.Errorf("Failed to update password: %v", err)
		return "", fmt.Errorf("failed to update password")
	}

	// Generate a new token for the user
	newToken, err := p.client.CreateCustomToken(context.Background(), user.ID)
	if err != nil {
		p.logger.Errorf("Failed to generate new token: %v", err)
		return "", fmt.Errorf("failed to generate new token")
	}

	return newToken, nil
}
