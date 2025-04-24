package factories

import (
	"database/sql"

	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/email"
	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/logging"
	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/postgres"
	"github.com/Businge931/sba-user-accounts/internal/config"
	"github.com/Businge931/sba-user-accounts/internal/core/ports"
	"github.com/Businge931/sba-user-accounts/internal/core/services"
	"github.com/Businge931/sba-user-accounts/internal/core/validation"
)

// ServiceFactory creates and initializes all application services
type ServiceFactory struct {
	db        *sql.DB
	config    *config.Config
	logger    ports.Logger
	validator *validation.Validator
	userRepo  ports.UserRepository
	authRepo  ports.AuthRepository
	tokenSvc  ports.TokenService
	emailSvc  ports.EmailService
}

// NewServiceFactory creates a new service factory
func NewServiceFactory(db *sql.DB, config *config.Config) *ServiceFactory {
	logger := logging.NewLogrusAdapter()
	validator := validation.NewValidator()

	return &ServiceFactory{
		db:        db,
		config:    config,
		logger:    logger,
		validator: validator,
	}
}

// InitializeRepositories initializes all repositories
func (f *ServiceFactory) InitializeRepositories() {
	f.userRepo = postgres.NewUserRepository(f.db)
	f.authRepo = postgres.NewAuthRepository(f.db)
}

// InitializeServices initializes all services
func (f *ServiceFactory) InitializeServices() {
	// First initialize supporting services
	f.tokenSvc = services.NewJWTTokenService(f.config.Auth.JWTSecret, f.config.Auth.TokenExpiryMin)

	// Create a simple email service implementation
	appBaseURL := "http://localhost:" + f.config.Server.GRPCPort // This would come from config in a real app
	f.emailSvc = email.NewLoggingEmailService(appBaseURL)
}

// GetAuthService returns the authentication service
func (f *ServiceFactory) GetAuthService() ports.AuthService {
	return services.NewAuthService(f.userRepo, f.authRepo, f.tokenSvc, f.validator, f.logger)
}

// GetAccountManagementService returns the account management service
func (f *ServiceFactory) GetAccountManagementService() ports.AccountManagementService {
	return services.NewAccountManagementService(f.userRepo, f.authRepo, f.tokenSvc, f.emailSvc, f.validator, f.logger)
}

// GetTokenService returns the token service
func (f *ServiceFactory) GetTokenService() ports.TokenService {
	return f.tokenSvc
}

// GetEmailService returns the email service
func (f *ServiceFactory) GetEmailService() ports.EmailService {
	return f.emailSvc
}
