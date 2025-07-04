package factories

import (
	"context"
	"fmt"
	"time"

	firebase "firebase.google.com/go/v4"
	"github.com/Businge931/sba-user-accounts/env"
	emailprovider "github.com/Businge931/sba-user-accounts/internal/adapters/secondary/email_provider"
	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/identity_direct/token"
	identityprovider "github.com/Businge931/sba-user-accounts/internal/adapters/secondary/identity_provider"
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
	firebaseApp      *firebase.App
}

func NewServiceFactory(db *gorm.DB, config *config.Config) *ServiceFactory {
	// Initialize logger
	logger := logrus.New()

	// Initialize repositories
	authRepo := postgres.NewAuthRepository(db)
	userRepo := postgres.NewUserRepository(db)

	// Initialize Firebase Admin SDK
	ctx := context.Background()
	firebaseApp, err := initializeFirebase(ctx, config)
	if err != nil {
		logger.Fatalf("Failed to initialize Firebase: %v", err)
	}

	// Initialize Firebase Auth client
	authClient, err := firebaseApp.Auth(ctx)
	if err != nil {
		logger.Fatalf("Failed to get Firebase Auth client: %v", err)
	}

	// Create Firebase Auth provider
	apiKey := env.GetEnv("FIREBASE_API_KEY", "")
	identityProvider := identityprovider.NewFirebaseAuthProvider(authClient, logger, apiKey)

	// Initialize email service
	appBaseURL := "http://localhost:" + config.Server.GRPCPort
	emailSvc := emailprovider.NewSendGridEmailService(
		config.SendGrid.APIKey,
		config.SendGrid.FromEmail,
		config.SendGrid.FromName,
		appBaseURL,
	)

	// Initialize validator
	validator := validation.NewValidator()

	return &ServiceFactory{
		db:               db,
		config:           config,
		logger:           logger,
		validator:        validator,
		userRepo:         userRepo,
		authRepo:         authRepo,
		emailSvc:         emailSvc,
		identityProvider: identityProvider,
		firebaseApp:      firebaseApp,
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

// initializeFirebase initializes the Firebase Admin SDK client
func initializeFirebase(ctx context.Context, config *config.Config) (*firebase.App, error) {
	credentialsFile := env.GetEnv("FIREBASE_CREDENTIALS_FILE", "")
	if credentialsFile == "" {
		return nil, fmt.Errorf("FIREBASE_CREDENTIALS_FILE environment variable not set")
	}

	// Use the firebase package's NewClient to initialize Firebase
	client, err := firebaseclient.NewClient(ctx, config.Firebase, credentialsFile)
	if err != nil {
		return nil, fmt.Errorf("error initializing firebase client: %v", err)
	}
	return client.App, nil
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
