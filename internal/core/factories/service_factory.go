package factories

import (
	"context"
	"fmt"
	"time"

	"github.com/Businge931/sba-user-accounts/env"
	emailprovider "github.com/Businge931/sba-user-accounts/internal/adapters/secondary/email_provider"
	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/identity_direct/token"
	firebaseclient "github.com/Businge931/sba-user-accounts/internal/adapters/secondary/identity_provider/firebase"
	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/postgres"
	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/validation"
	"github.com/Businge931/sba-user-accounts/internal/config"
	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/Businge931/sba-user-accounts/internal/core/ports"
	"github.com/Businge931/sba-user-accounts/internal/core/services"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// ServiceFactory creates and initializes all services
type ServiceFactory struct {
	db               *gorm.DB
	config           *config.Config
	logger           ports.Logger
	validator        ports.ValidationService
	userRepo         ports.UserRepository
	authRepo         ports.AuthRepository
	tokenSvc         ports.TokenService
	emailSvc         ports.EmailService
	identityProvider ports.IdentityService
	firebaseApp      *firebaseclient.FirebaseClient
}

func NewServiceFactory(db *gorm.DB, config *config.Config) *ServiceFactory {
	ctx := context.Background()
	logger := logrus.New()

	// Initialize Firebase client
	firebaseClient, err := initializeFirebase(ctx, config, logger)
	if err != nil {
		logger.Fatalf("Failed to initialize Firebase: %v", err)
	}

	// Initialize repositories
	userRepo := postgres.NewUserRepository(db)
	authRepo := postgres.NewAuthRepository(db)

	// Initialize validator
	validator := validation.NewValidator()

	// Initialize token service
	tokenSvc := token.NewJWTTokenService(config.Auth.JWTSecret, config.Auth.TokenExpiryMin)

	// Initialize email service
	frontendURL := fmt.Sprintf("http://localhost:%s", config.Server.GRPCPort)
	emailSvc := emailprovider.NewSendGridEmailService(
		config.SendGrid.APIKey,
		config.SendGrid.FromEmail,
		config.SendGrid.FromName,
		frontendURL,
	)

	// Create an adapter that implements ports.IdentityService using the Firebase client
	identityProvider := &firebaseIdentityServiceAdapter{
		firebaseClient: firebaseClient,
		logger:         logger,
	}

	return &ServiceFactory{
		db:               db,
		config:           config,
		logger:           logger,
		validator:        validator,
		userRepo:         userRepo,
		authRepo:         authRepo,
		tokenSvc:         tokenSvc,
		emailSvc:         emailSvc,
		identityProvider: identityProvider,
	}
}

// AutoMigrate runs database migrations
func (f *ServiceFactory) AutoMigrate() error {
	return f.db.AutoMigrate(
		&domain.User{},
		&domain.Token{},
		// Add other models here
	)
}

func (f *ServiceFactory) InitializeRepositories() {
	f.userRepo = postgres.NewUserRepository(f.db)
	f.authRepo = postgres.NewAuthRepository(f.db)
}

func (f *ServiceFactory) InitializeServices() {
	// First initialize supporting services
	tokenExpiry := time.Duration(f.config.Auth.TokenExpiryMin) * time.Minute
	f.tokenSvc = token.NewJWTTokenService([]byte(f.config.Auth.JWTSecret), tokenExpiry)

	// Create email service with SendGrid
	appBaseURL := "http://localhost:" + f.config.Server.GRPCPort
	f.emailSvc = emailprovider.NewSendGridEmailService(
		f.config.SendGrid.APIKey,
		f.config.SendGrid.FromEmail,
		f.config.SendGrid.FromName,
		appBaseURL,
	)
}

// GetAuthService returns the authentication service
func (f *ServiceFactory) GetAuthService() ports.AuthService {
	return services.NewAuthService(
		f.userRepo,
		f.authRepo,
		f.validator,
		f.identityProvider,
		f.emailSvc,
		f.logger,
	)
}

// initializeFirebase initializes the Firebase client with the given configuration
func initializeFirebase(ctx context.Context, config *config.Config, logger *logrus.Logger) (*firebaseclient.FirebaseClient, error) {
	credentialsFile := env.GetEnv("FIREBASE_CREDENTIALS_FILE", "")
	if credentialsFile == "" {
		return nil, fmt.Errorf("FIREBASE_CREDENTIALS_FILE environment variable not set")
	}

	// Create Firebase config
	firebaseCfg := &firebaseclient.FirebaseConfig{
		ServiceAccountKeyPath: credentialsFile,
		ProjectID:             config.Firebase.ProjectID,
		StorageBucket:         config.Firebase.StorageBucket,
		APIKey:                config.Firebase.APIKey,
		HTTPClientTimeout:     30 * time.Second,
	}

	// Initialize Firebase client
	client, err := firebaseclient.NewFirebaseClient(ctx, firebaseCfg, logger)
	if err != nil {
		return nil, fmt.Errorf("error initializing firebase client: %v", err)
	}

	return client, nil
}

// firebaseIdentityServiceAdapter adapts the Firebase client to implement ports.IdentityService
type firebaseIdentityServiceAdapter struct {
	firebaseClient *firebaseclient.FirebaseClient
	logger         *logrus.Logger
}

// ChangePasswordSvc implements the ChangePasswordSvc method of ports.IdentityService
func (a *firebaseIdentityServiceAdapter) ChangePasswordSvc(userID, oldPassword, newPassword string) (string, error) {
	// Verify the old password first
	_, err := a.firebaseClient.VerifyPassword(context.Background(), userID, oldPassword)
	if err != nil {
		return "", fmt.Errorf("invalid old password: %w", err)
	}

	// Update to the new password
	err = a.firebaseClient.UpdatePassword(context.Background(), userID, newPassword)
	if err != nil {
		return "", fmt.Errorf("failed to update password: %w", err)
	}

	// Generate a new token after password change
	token, err := a.firebaseClient.CreateCustomToken(context.Background(), userID)
	if err != nil {
		return "", fmt.Errorf("failed to generate new token: %w", err)
	}

	return token, nil
}

// LoginSvc implements the LoginSvc method of ports.IdentityService
func (a *firebaseIdentityServiceAdapter) LoginSvc(loginReq domain.LoginRequest, user *domain.User) (string, error) {
	// Verify the password and get the user ID
	userID, err := a.firebaseClient.VerifyPassword(context.Background(), loginReq.Email, loginReq.Password)
	if err != nil {
		return "", fmt.Errorf("authentication failed: %w", err)
	}

	// Update the user object with the ID from Firebase
	user.ID = userID

	// Generate a new token for the user
	token, err := a.firebaseClient.CreateCustomToken(context.Background(), userID)
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	return token, nil
}

// RegisterSvc implements the RegisterSvc method of ports.IdentityService
func (a *firebaseIdentityServiceAdapter) RegisterSvc(registerReq domain.RegisterRequest) (*domain.User, string, error) {
	// Create the user in Firebase
	user, err := a.firebaseClient.CreateUser(
		context.Background(),
		registerReq.Email,
		registerReq.Password,
		registerReq.FirstName,
		registerReq.LastName,
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create user: %w", err)
	}

	// Generate a verification token using the token generator from the firebase client
	token := a.firebaseClient.TokenGenerator.GenerateVerificationToken()

	return user, token, nil
}

// RequestPasswordResetSvc implements the RequestPasswordResetSvc method of ports.IdentityService
func (a *firebaseIdentityServiceAdapter) RequestPasswordResetSvc(email string) (string, error) {
	// Generate a password reset email
	resetLink, err := a.firebaseClient.SendPasswordResetEmail(context.Background(), email)
	if err != nil {
		return "", fmt.Errorf("failed to send password reset email: %w", err)
	}

	return resetLink, nil
}

// ResetPasswordSvc implements the ResetPasswordSvc method of ports.IdentityService
func (a *firebaseIdentityServiceAdapter) ResetPasswordSvc(token, newPassword string) (string, string, error) {
	// Verify the token and get the user ID
	userID, err := a.firebaseClient.VerifyIDToken(context.Background(), token)
	if err != nil {
		return "", "", fmt.Errorf("invalid or expired token: %w", err)
	}

	// Update the user's password
	err = a.firebaseClient.UpdatePassword(context.Background(), userID, newPassword)
	if err != nil {
		return "", "", fmt.Errorf("failed to update password: %w", err)
	}

	// Generate a new token for the user
	newToken, err := a.firebaseClient.CreateCustomToken(context.Background(), userID)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate new token: %w", err)
	}

	return userID, newToken, nil
}

// VerifyEmailSvc implements the VerifyEmailSvc method of ports.IdentityService
func (a *firebaseIdentityServiceAdapter) VerifyEmailSvc(token string) (string, error) {
	// Verify the email verification token and get the user ID
	userID, err := a.firebaseClient.VerifyIDToken(context.Background(), token)
	if err != nil {
		return "", fmt.Errorf("invalid or expired verification token: %w", err)
	}

	// Mark the user's email as verified
	err = a.firebaseClient.UpdateUser(context.Background(), userID, map[string]interface{}{
		"emailVerified": true,
	})
	if err != nil {
		return "", fmt.Errorf("failed to verify email: %w", err)
	}

	// Generate a new token for the user
	newToken, err := a.firebaseClient.CreateCustomToken(context.Background(), userID)
	if err != nil {
		return "", fmt.Errorf("failed to generate new token: %w", err)
	}

	return newToken, nil
}

// GetAccountManagementService returns the account management service
func (f *ServiceFactory) GetAccountManagementService() ports.AccountManagementService {
	return services.NewAccountManagementService(
		f.userRepo,
		f.authRepo,
		f.tokenSvc,
		f.emailSvc,
		f.validator,
		f.logger,
		f.identityProvider,
	)
}

// GetTokenService returns the token service
func (f *ServiceFactory) GetTokenService() ports.TokenService {
	return f.tokenSvc
}

// GetEmailService returns the email service
func (f *ServiceFactory) GetEmailService() ports.EmailService {
	return f.emailSvc
}
