package services

import (
	"strings"

	"github.com/Businge931/sba-user-accounts/internal/core/errors"
	"github.com/Businge931/sba-user-accounts/internal/core/ports"
)

// accountManagementService implements the AccountManagementService interface
type accountManagementService struct {
	userRepo         ports.UserRepository
	authRepo         ports.AuthRepository
	tokenSvc         ports.TokenService
	emailSvc         ports.EmailService
	validator        ports.ValidationService
	logger           ports.Logger
	identityProvider ports.IdentityService
}

func NewAccountManagementService(
	userRepo ports.UserRepository,
	authRepo ports.AuthRepository,
	tokenSvc ports.TokenService,
	emailSvc ports.EmailService,
	validator ports.ValidationService,
	logger ports.Logger,
	identityProvider ports.IdentityService,
) ports.AccountManagementService {
	return &accountManagementService{
		userRepo:         userRepo,
		authRepo:         authRepo,
		tokenSvc:         tokenSvc,
		emailSvc:         emailSvc,
		validator:        validator,
		logger:           logger,
		identityProvider: identityProvider,
	}
}

// VerifyEmail verifies a user's email using a token
func (svc *accountManagementService) VerifyEmail(token string) error {
	// verify email with provider
	userID, err := svc.identityProvider.VerifyEmail(token)
	if err != nil {
		return err
	}

	// verify user exists
	user, err := svc.userRepo.GetByID(userID)
	if err != nil {
		return err
	}

	user.IsEmailVerified = true
	return svc.userRepo.Update(user)
}

// RequestPasswordReset initiates the password reset process
func (svc *accountManagementService) RequestPasswordReset(email string) error {
	// Validate email
	if err := svc.validator.ValidateEmail(email); err != nil {
		return err
	}

	svc.logger.Infof("Password reset requested for email: %s", email)

	token, err := svc.identityProvider.RequestPasswordReset(email)
	if err != nil {
		svc.logger.Errorf("Failed to process password reset: %v", err)
		return errors.NewInternalError("failed to process password reset", err)
	}

	// If token is empty, it means user doesn't exist, but we don't reveal this
	if token == "" {
		return nil
	}

	if svc.emailSvc != nil {
		return svc.emailSvc.SendPasswordResetEmail(email, token)
	}

	return nil
}

// ChangePassword changes a user's password
func (svc *accountManagementService) ChangePassword(userID, oldPassword, newPassword string) error {
	// Validate new password
	if err := svc.validator.ValidatePassword(newPassword); err != nil {
		return err
	}

	svc.logger.Infof("Password change requested for user: %s", userID)
	user, err := svc.userRepo.GetByID(userID)
	if err != nil {
		svc.logger.Warnf("Password change failed, user not found: %v", err)
		return errors.NewNotFoundError("user not found", err)
	}

	hashedPassword, err := svc.identityProvider.ChangePassword(userID, oldPassword, newPassword)
	if err != nil {
		// Check if it's an invalid password error
		if strings.Contains(err.Error(), "invalid current password") {
			return errors.NewInvalidAuthError("invalid current password", err)
		}
		return err
	}

	user.HashedPassword = string(hashedPassword)
	return svc.userRepo.Update(user)
}

// ResetPassword resets a user's password using a token
func (svc *accountManagementService) ResetPassword(token, newPassword string) error {
	// Validate password
	if err := svc.validator.ValidatePassword(newPassword); err != nil {
		return err
	}

	svc.logger.Infof("Attempting password reset with token")

	hashedPassword, userID, err := svc.identityProvider.ResetPassword(token, newPassword)
	if err != nil {
		return err
	}

	user, err := svc.userRepo.GetByID(userID)
	if err != nil {
		return err
	}

	user.HashedPassword = string(hashedPassword)
	return svc.userRepo.Update(user)
}
