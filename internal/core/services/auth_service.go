package services

import (
	"errors"
	"fmt"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	apperrors "github.com/Businge931/sba-user-accounts/internal/core/errors"
	"github.com/Businge931/sba-user-accounts/internal/core/ports"
)

type authService struct {
	userRepo         ports.UserRepository
	authRepo         ports.AuthRepository
	validator        ports.ValidationService
	logger           ports.Logger
	identityProvider ports.IdentityService
	emailService     ports.EmailService
}

func NewAuthService(
	userRepo ports.UserRepository,
	authRepo ports.AuthRepository,
	validator ports.ValidationService,
	identityProvider ports.IdentityService,
	emailService ports.EmailService,
	logger ports.Logger,
) ports.AuthService {
	return &authService{
		userRepo:         userRepo,
		authRepo:         authRepo,
		validator:        validator,
		identityProvider: identityProvider,
		emailService:     emailService,
		logger:           logger,
	}
}

func (svc *authService) Register(req domain.RegisterRequest) (*domain.User, error) {
	if err := svc.validator.ValidateRegisterRequest(req); err != nil {
		return nil, err
	}

	// Check if user already exists
	existing, err := svc.userRepo.GetByEmail(req.Email)
	if err != nil && !errors.Is(err, apperrors.ErrUserNotFound) {
		// If it's not a "not found" error, return the actual error
		svc.logger.Errorf("Error checking for existing user: %v", err)
		return nil, fmt.Errorf("failed to check for existing user: %w", err)
	}
	if existing != nil {
		svc.logger.Infof("Registration attempt with existing email: %s", req.Email)
		return nil, apperrors.ErrEmailAlreadyExists
	}

	// Register user using identity provider
	user, token, err := svc.identityProvider.RegisterSvc(req)
	if err != nil {
		return nil, fmt.Errorf("failed to register user,%w", err)
	}

	// Save user to repository
	if err := svc.userRepo.Create(user); err != nil {
		return nil, fmt.Errorf("failed to save user: %w", err)
	}

	// Store verification token now that user exists in the database
	if err := svc.authRepo.StoreVerificationToken(user.ID, token); err != nil {
		svc.logger.Warnf("Failed to store verification token for user %s: %v", user.ID, err)
		// Continue with registration even if token storage fails
	}

	// Send registration email with verification token
	if err := svc.emailService.SendRegistrationEmail(user.Email, token); err != nil {
		svc.logger.Warnf("Failed to send registration email to %s: %v", user.Email, err)
	}

	return user, nil
}

func (svc *authService) Login(req domain.LoginRequest) (string, error) {
	if err := svc.validator.ValidateLoginRequest(req); err != nil {
		return "", err
	}

	// Check if user exists
	user, err := svc.userRepo.GetByEmail(req.Email)
	if err != nil {
		svc.logger.Debugf("Error getting user by email: %v", err)
		return "", apperrors.NewNotFoundError(apperrors.ErrUserNotFound.Error(), err)
	}

	token, err := svc.identityProvider.LoginSvc(req, user)
	if err != nil {
		return "", err
	}
	return token, nil
}
