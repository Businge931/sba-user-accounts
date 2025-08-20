package firebase

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"firebase.google.com/go/v4/auth"
	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/sirupsen/logrus"
)

type FirebaseClient struct {
	*firebaseClient // Embedded to promote all methods
	logger *logrus.Logger
}

type firebaseClient struct {
	sdk        FirebaseSDK
	httpClient HTTPClient
	config     ConfigProvider
	logger     *logrus.Logger
}


func NewFirebaseClient(ctx context.Context, cfg *FirebaseConfig, logger *logrus.Logger) (*FirebaseClient, error) {
	if cfg == nil {
		return nil, errors.New("firebase config cannot be nil")
	}
  
	// Create configuration provider
	configProvider := NewConfigProvider(cfg)

	// Initialize Firebase SDK
	sdk, err := NewFirebaseSDK(ctx, configProvider)
	if err != nil {
		return nil, fmt.Errorf("error initializing firebase SDK: %w", err)
	}

	// Test connection by getting auth client
	if _, err := sdk.Auth(ctx); err != nil {
		return nil, fmt.Errorf("error getting auth client: %w", err)
	}

	// Create HTTP client with timeout
	timeout := time.Duration(configProvider.GetHTTPTimeout()) * time.Second
	httpClient := NewHTTPClient(timeout)

	// Create and return the client
	client := &firebaseClient{
		sdk:        sdk,
		httpClient: httpClient,
		config:     configProvider,
		logger:     logger,
	}

	// Create the composite client
	return &FirebaseClient{
		firebaseClient: client,
		logger:         logger,
	}, nil
}

// NewFirebaseClientForTesting creates a FirebaseClient with injected dependencies for testing
func NewFirebaseClientForTesting(sdk FirebaseSDK, httpClient HTTPClient, config ConfigProvider, logger *logrus.Logger) *FirebaseClient {
	client := &firebaseClient{
		sdk:        sdk,
		httpClient: httpClient,
		config:     config,
		logger:     logger,
	}

	return &FirebaseClient{
		firebaseClient: client,
		logger:         logger,
	}
}

func (c *firebaseClient) CreateUser(ctx context.Context, email, password, firstName, lastName string) (*domain.User, error) {
	authClient, err := c.sdk.Auth(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting auth client: %w", err)
	}

	userParams := (&auth.UserToCreate{}).
		Email(email).
		Password(password).
		DisplayName(fmt.Sprintf("%s %s", firstName, lastName)).
		EmailVerified(false).
		Disabled(false)

	userRecord, err := authClient.CreateUser(ctx, userParams)
	if err != nil {
		return nil, fmt.Errorf("error creating user: %w", err)
	}

	return &domain.User{
		ID:              userRecord.UID,
		Email:           userRecord.Email,
		FirstName:       firstName,
		LastName:        lastName,
		IsEmailVerified: userRecord.EmailVerified,
	}, nil
}

func (c *firebaseClient) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	authClient, err := c.sdk.Auth(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting auth client: %w", err)
	}

	userRecord, err := authClient.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("error getting user by email: %w", err)
	}

	// Extract first and last name from display name
	var firstName, lastName string
	if userRecord.DisplayName != "" {
		names := strings.SplitN(userRecord.DisplayName, " ", 2)
		if len(names) > 0 {
			firstName = names[0]
		}
		if len(names) > 1 {
			lastName = names[1]
		}
	}

	return &domain.User{
		ID:              userRecord.UID,
		Email:           userRecord.Email,
		FirstName:       firstName,
		LastName:        lastName,
		IsEmailVerified: userRecord.EmailVerified,
	}, nil
}

func (c *firebaseClient) UpdateUser(ctx context.Context, userID string, updates map[string]any) error {
	authClient, err := c.sdk.Auth(ctx)
	if err != nil {
		return fmt.Errorf("error getting auth client: %w", err)
	}

	// Convert updates to UserToUpdate
	userUpdate := &auth.UserToUpdate{}
	for k, v := range updates {
		switch k {
		case "email":
			if email, ok := v.(string); ok {
				userUpdate = userUpdate.Email(email)
			}
		case "password":
			if password, ok := v.(string); ok {
				userUpdate = userUpdate.Password(password)
			}
		case "displayName":
			if name, ok := v.(string); ok {
				userUpdate = userUpdate.DisplayName(name)
			}
		case "emailVerified":
			if verified, ok := v.(bool); ok {
				userUpdate = userUpdate.EmailVerified(verified)
			}
		case "disabled":
			if disabled, ok := v.(bool); ok {
				userUpdate = userUpdate.Disabled(disabled)
			}
		}
	}

	_, err = authClient.UpdateUser(ctx, userID, userUpdate)
	return err
}

// AuthProvider implementation
func (c *firebaseClient) VerifyIDToken(ctx context.Context, token string) (string, error) {
	authClient, err := c.sdk.Auth(ctx)
	if err != nil {
		return "", fmt.Errorf("error getting auth client: %w", err)
	}

	tokenInfo, err := authClient.VerifyIDToken(ctx, token)
	if err != nil {
		return "", fmt.Errorf("error verifying ID token: %w", err)
	}

	return tokenInfo.UID, nil
}

func (c *firebaseClient) CreateCustomToken(ctx context.Context, userID string) (string, error) {
	authClient, err := c.sdk.Auth(ctx)
	if err != nil {
		return "", fmt.Errorf("error getting auth client: %w", err)
	}

	token, err := authClient.CustomToken(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("error creating custom token: %w", err)
	}

	return token, nil
}

func (c *firebaseClient) VerifyPassword(ctx context.Context, email, password string) (string, error) {
	authClient, err := c.sdk.Auth(ctx)
	if err != nil {
		return "", fmt.Errorf("error getting auth client: %w", err)
	}

	// Try to sign in with email and password
	token, err := c.signInWithEmailAndPassword(ctx, email, password)
	if err != nil {
		return "", fmt.Errorf("error signing in: %w", err)
	}

	// Verify the ID token to get the user ID
	tokenInfo, err := authClient.VerifyIDToken(ctx, token)
	if err != nil {
		return "", fmt.Errorf("error verifying ID token: %w", err)
	}

	return tokenInfo.UID, nil
}

func (c *firebaseClient) UpdatePassword(ctx context.Context, userID, newPassword string) error {
	authClient, err := c.sdk.Auth(ctx)
	if err != nil {
		return fmt.Errorf("error getting auth client: %w", err)
	}

	_, err = authClient.UpdateUser(ctx, userID, (&auth.UserToUpdate{}).Password(newPassword))
	return err
}

func (c *firebaseClient) SendVerificationEmail(ctx context.Context, email string) (string, error) {
	authClient, err := c.sdk.Auth(ctx)
	if err != nil {
		return "", fmt.Errorf("error getting auth client: %w", err)
	}

	link, err := authClient.EmailVerificationLink(ctx, email)
	if err != nil {
		return "", fmt.Errorf("error generating verification link: %w", err)
	}

	return link, nil
}

func (c *firebaseClient) SendPasswordResetEmail(ctx context.Context, email string) (string, error) {
	authClient, err := c.sdk.Auth(ctx)
	if err != nil {
		return "", fmt.Errorf("error getting auth client: %w", err)
	}

	link, err := authClient.PasswordResetLink(ctx, email)
	if err != nil {
		return "", fmt.Errorf("error generating password reset link: %w", err)
	}

	return link, nil
}

func (c *firebaseClient) VerifyEmail(ctx context.Context, token string) error {
	authClient, err := c.sdk.Auth(ctx)
	if err != nil {
		return fmt.Errorf("error getting auth client: %w", err)
	}

	tokenInfo, err := authClient.VerifyIDToken(ctx, token)
	if err != nil {
		return fmt.Errorf("error verifying token: %w", err)
	}

	// Update the user's email verification status
	_, err = authClient.UpdateUser(ctx, tokenInfo.UID, (&auth.UserToUpdate{}).EmailVerified(true))
	return err
}

// Helper methods
func (c *firebaseClient) signInWithEmailAndPassword(ctx context.Context, email, password string) (string, error) {
	// This is a simplified implementation. In the future, I would use the Firebase REST API
	// or Firebase Admin SDK's custom token generation.
	// For now, I'll use the Firebase REST API.

	url := fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=%s", c.config.GetAPIKey())

	reqBody := map[string]any{
		"email":             email,
		"password":          password,
		"returnSecureToken": true,
	}

	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("error marshaling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(reqJSON))
	if err != nil {
		return "", fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		IDToken string `json:"idToken"`
		Error   struct {
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("error decoding response: %w", err)
	}

	if result.IDToken == "" {
		return "", fmt.Errorf("authentication failed: %s", result.Error.Message)
	}

	return result.IDToken, nil
}
