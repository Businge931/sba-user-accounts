package factories

import (
	"gorm.io/gorm"

	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/email"
	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/identity/token"
	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/logging"
	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/postgres"
	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/validation"
	"github.com/Businge931/sba-user-accounts/internal/config"
	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/Businge931/sba-user-accounts/internal/core/ports"
	"github.com/Businge931/sba-user-accounts/internal/core/services"
)

// ServiceFactory creates and initializes all application services
type ServiceFactory struct {
	db                *gorm.DB
	config            *config.Config
	logger            ports.Logger
	validator         ports.ValidationService
	userRepo          ports.UserRepository
	authRepo          ports.AuthRepository
	tokenSvc          ports.TokenService
	emailSvc          ports.EmailService
	indentityProvider ports.IdentityService
}

func NewServiceFactory(db *gorm.DB, config *config.Config) *ServiceFactory {
	logger := logging.NewLogrusAdapter()
	validator := validation.NewValidator()

	return &ServiceFactory{
		db:        db,
		config:    config,
		logger:    logger,
		validator: validator,
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
	f.tokenSvc = token.NewJWTTokenService(f.config.Auth.JWTSecret, f.config.Auth.TokenExpiryMin)

	// Create a simple email service implementation
	appBaseURL := "http://localhost:" + f.config.Server.GRPCPort
	f.emailSvc = email.NewLoggingEmailService(appBaseURL)
}

// GetAuthService returns the authentication service
func (f *ServiceFactory) GetAuthService() ports.AuthService {
	return services.NewAuthService(f.userRepo, f.validator, f.indentityProvider, f.logger)
}

// GetAccountManagementService returns the account management service
func (f *ServiceFactory) GetAccountManagementService() ports.AccountManagementService {
	return services.NewAccountManagementService(f.userRepo, f.authRepo, f.tokenSvc, f.emailSvc, f.validator, f.logger, f.indentityProvider)
}

// GetTokenService returns the token service
func (f *ServiceFactory) GetTokenService() ports.TokenService {
	return f.tokenSvc
}

// GetEmailService returns the email service
func (f *ServiceFactory) GetEmailService() ports.EmailService {
	return f.emailSvc
}
