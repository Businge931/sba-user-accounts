package identityprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"firebase.google.com/go/v4/auth"
	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	dcerrors "github.com/Businge931/sba-user-accounts/internal/core/errors"
	"github.com/Businge931/sba-user-accounts/internal/core/ports"
	"github.com/sirupsen/logrus"
)

type firebaseAuthProvider struct {
	client *auth.Client
	logger *logrus.Logger
	apiKey string
}

// NewFirebaseAuthProvider creates a new instance of the Firebase Auth provider
func NewFirebaseAuthProvider(authClient *auth.Client, logger *logrus.Logger, apiKey string) ports.IdentityService {
	return &firebaseAuthProvider{
		client: authClient,
		logger: logger,
		apiKey: apiKey,
	}
}

func (p *firebaseAuthProvider) RegisterSvc(req domain.RegisterRequest) (*domain.User, string, error) {
	// First, create the user in Firebase Auth
	params := (&auth.UserToCreate{}).
		Email(req.Email).
		EmailVerified(false).
		Password(req.Password).
		DisplayName(fmt.Sprintf("%s %s", req.FirstName, req.LastName)).
		Disabled(false)

	userRecord, err := p.client.CreateUser(context.Background(), params)
	if err != nil {
		p.logger.Errorf("Failed to create Firebase user: %v", err)
		return nil, "", fmt.Errorf("failed to create user: %w", err)
	}

	// Generate email verification link
	emailVerificationLink, err := p.client.EmailVerificationLink(context.Background(), req.Email)
	if err != nil {
		p.logger.Errorf("Failed to generate email verification link: %v", err)
		// Continue without failing since we can still create the user
	}

	// Map Firebase user to our domain user
	user := &domain.User{
		ID:        userRecord.UID,
		Email:     userRecord.Email,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		// Firebase handles email verification status
		IsEmailVerified: userRecord.EmailVerified,
	}

	return user, emailVerificationLink, nil
}

func (p *firebaseAuthProvider) verifyPassword(email, password string) (*auth.UserRecord, error) {
	// Get the user by email to check if they exist
	userRecord, err := p.client.GetUserByEmail(context.Background(), email)
	if err != nil {
		if auth.IsUserNotFound(err) {
			p.logger.Debugf("Login attempt for non-existent user: %s", email)
			return nil, dcerrors.ErrInvalidAuth
		}
		p.logger.Errorf("Failed to get user by email: %v", err)
		return nil, dcerrors.ErrInternal
	}

	// Use Firebase REST API to verify the password
	authURL := fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=%s", p.apiKey)
	payload := map[string]any{
		"email":             email,
		"password":          password,
		"returnSecureToken": true,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		p.logger.Errorf("Failed to marshal auth payload: %v", err)
		return nil, dcerrors.ErrInternal
	}

	req, err := http.NewRequest("POST", authURL, bytes.NewBuffer(jsonData))
	if err != nil {
		p.logger.Errorf("Failed to create auth request: %v", err)
		return nil, dcerrors.ErrInternal
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 10 * time.Second, // Add timeout to prevent hanging
	}

	resp, err := client.Do(req)
	if err != nil {
		p.logger.Errorf("Failed to verify password: %v", err)
		return nil, dcerrors.ErrInternal
	}
	defer resp.Body.Close()

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		p.logger.Errorf("Failed to decode auth response: %v", err)
		return nil, dcerrors.ErrInternal
	}

	if resp.StatusCode != http.StatusOK {
		errMsg, _ := result["error"].(map[string]interface{})["message"].(string)
		p.logger.Debugf("Authentication failed for user %s: %v", email, errMsg)

		// Return appropriate error based on Firebase error type
		switch {
		case strings.Contains(errMsg, "INVALID_PASSWORD"):
			return nil, dcerrors.ErrInvalidAuth
		case strings.Contains(errMsg, "TOO_MANY_ATTEMPTS_TRY_LATER"):
			return nil, dcerrors.ErrTooManyAttempts
		case strings.Contains(errMsg, "USER_DISABLED"):
			return nil, dcerrors.ErrAccountDisabled
		default:
			return nil, dcerrors.ErrInvalidAuth
		}
	}

	p.logger.Debugf("Successfully verified password for user: %s", email)
	return userRecord, nil
}

func (p *firebaseAuthProvider) LoginSvc(req domain.LoginRequest, user *domain.User) (string, error) {
	if user == nil {
		p.logger.Error("Login attempt with nil user")
		return "", dcerrors.ErrInvalidAuth
	}

	// Verify the password with Firebase
	userRecord, err := p.verifyPassword(req.Email, req.Password)
	if err != nil {
		// verifyPassword returns standard domain errors
		p.logger.Debugf("Login failed for user %s: %v", user.ID, err)
		return "", err
	}

	// Double-check that the user ID matches
	if userRecord.UID != user.ID {
		err := fmt.Errorf("user ID mismatch: expected %s, got %s", user.ID, userRecord.UID)
		p.logger.Errorf("Authentication failed: %v", err)
		return "", dcerrors.ErrInternal
	}

	// Generate a custom token for the user
	token, err := p.client.CustomToken(context.Background(), user.ID)
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
	// In Firebase, email verification is handled via a link sent to the user's email
	// This method would be called after the user clicks the verification link
	// So I just need to check if the user's email is verified

	// Get user by ID token
	decoded, err := p.client.VerifyIDToken(context.Background(), token)
	if err != nil {
		p.logger.Errorf("Failed to verify ID token: %v", err)
		return "", fmt.Errorf("invalid or expired token")
	}

	// Get user record to check email verification status
	userRecord, err := p.client.GetUser(context.Background(), decoded.UID)
	if err != nil {
		p.logger.Errorf("Failed to get user record: %v", err)
		return "", fmt.Errorf("user not found")
	}

	if !userRecord.EmailVerified {
		return "", fmt.Errorf("email not verified")
	}

	return userRecord.UID, nil
}

// RequestPasswordResetSvc sends a password reset email to the user
func (p *firebaseAuthProvider) RequestPasswordResetSvc(email string) (string, error) {
	// Firebase will handle sending the password reset email
	// I don't need to generate a token manually
	link, err := p.client.PasswordResetLink(context.Background(), email)
	if err != nil {
		p.logger.Errorf("Failed to generate password reset link: %v", err)
		// Don't reveal if the email exists for security reasons
		return "", nil
	}

	return link, nil
}

// ResetPasswordSvc resets a user's password using a reset token
func (p *firebaseAuthProvider) ResetPasswordSvc(token, newPassword string) (string, string, error) {
	// In Firebase, the reset token is part of the password reset link
	// The client should have already verified the token and sent the new password
	// So this method might not be needed if using Firebase's built-in password reset flow

	// If I need to implement this, I would verify the token and update the password
	// But this is generally not needed with Firebase's default flow

	return "", "", fmt.Errorf("not implemented: use Firebase's password reset link flow instead")
}

// ChangePasswordSvc changes a user's password
func (p *firebaseAuthProvider) ChangePasswordSvc(userID, oldPassword, newPassword string) (string, error) {
	// Update the user's password
	params := (&auth.UserToUpdate{}).Password(newPassword)
	_, err := p.client.UpdateUser(context.Background(), userID, params)
	if err != nil {
		p.logger.Errorf("Failed to update password: %v", err)
		return "", fmt.Errorf("failed to update password")
	}

	// Generate a new token since the old one might be invalidated
	newToken, err := p.client.CustomToken(context.Background(), userID)
	if err != nil {
		p.logger.Errorf("Failed to generate new token: %v", err)
		// Still return success since password was changed
		return "", nil
	}

	return newToken, nil
}
