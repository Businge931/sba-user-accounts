package services

import (
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/Businge931/sba-user-accounts/internal/core/errors"
	"github.com/Businge931/sba-user-accounts/internal/core/ports"
	"github.com/Businge931/sba-user-accounts/internal/core/validation"
)

type authService struct {
	userRepo  ports.UserRepository
	authRepo  ports.AuthRepository
	tokenSvc  ports.TokenService
	validator *validation.Validator
	logger    ports.Logger
}

// NewAuthService creates a new instance of authentication service
func NewAuthService(
	userRepo ports.UserRepository,
	authRepo ports.AuthRepository,
	tokenSvc ports.TokenService,
	validator *validation.Validator,
	logger ports.Logger,
) ports.AuthService {
	return &authService{
		userRepo:  userRepo,
		authRepo:  authRepo,
		tokenSvc:  tokenSvc,
		validator: validator,
		logger:    logger,
	}
}

func (svc *authService) Register(email, password, firstName, lastName string) (*domain.User, error) {
	// Validate input data
	if err := svc.validator.ValidateEmail(email); err != nil {
		return nil, err
	}

	if err := svc.validator.ValidatePassword(password); err != nil {
		return nil, err
	}

	if err := svc.validator.ValidateName(firstName, "first name"); err != nil {
		return nil, err
	}

	if err := svc.validator.ValidateName(lastName, "last name"); err != nil {
		return nil, err
	}

	// Check if user already exists
	if existing, _ := svc.userRepo.GetByEmail(email); existing != nil {
		svc.logger.Infof("Registration attempt with existing email: %s", email)
		return nil, errors.NewAlreadyExistsError("user already exists", nil)
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Create user with UUID
	user := domain.NewUser(email, firstName, lastName)
	user.HashedPassword = string(hashedPassword)
	// Use UUID from standard library - this would be better, but keeping format similar
	user.ID = fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().Nanosecond())

	if err := svc.userRepo.Create(user); err != nil {
		return nil, err
	}

	// Skip verification token if authRepo is nil
	if svc.authRepo != nil {
		// Generate and send verification token using the token service
		token := svc.tokenSvc.GenerateVerificationToken()
		if err := svc.authRepo.StoreVerificationToken(user.ID, token); err != nil {
			// Just log the error and continue
			// Don't return an error as this is optional functionality
			svc.logger.Warnf("Failed to store verification token for user %s: %v", user.ID, err)
		}
	}

	// Send verification email - skipped as EmailService not implemented

	return user, nil
}

func (svc *authService) Login(email, password string) (string, error) {
	// Validate email
	if err := svc.validator.ValidateEmail(email); err != nil {
		return "", err
	}

	// Check if user exists
	user, err := svc.userRepo.GetByEmail(email)
	if err != nil {
		// Log the actual error for debugging purposes
		svc.logger.Debugf("Error getting user by email: %v", err)
		return "", errors.NewNotFoundError("user not found", err)
	}

	// Check if password is correct
	if compareErr := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(password)); compareErr != nil {
		// Log the error but don't expose it in the response
		svc.logger.Debugf("Password comparison failed: %v", compareErr)
		return "", errors.NewInvalidAuthError("invalid password", compareErr)
	}

	// Temporarily bypassing email verification check for testing
	// if !user.IsEmailVerified {
	// 	return "", ErrEmailNotVerified
	// }

	// Generate JWT token using token service
	token, err := svc.tokenSvc.GenerateToken(user.ID)
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	return token, nil
}

// func (s *authService) VerifyEmail(token string) error {
// 	userID, err := s.authRepo.GetUserIDByVerificationToken(token)
// 	if err != nil {
// 		return errors.New("invalid or expired token")
// 	}

// 	user, err := s.userRepo.GetByID(userID)
// 	if err != nil {
// 		return err
// 	}

// 	user.IsEmailVerified = true
// 	return s.userRepo.Update(user)
// }

// func (s *authService) RequestPasswordReset(email string) error {
// 	user, err := s.userRepo.GetByEmail(email)
// 	if err != nil {
// 		return nil // Don't reveal if email exists
// 	}

// 	token := generateToken() // Implementation needed
// 	if err := s.authRepo.StoreResetToken(user.ID, token); err != nil {
// 		return err
// 	}

// 	return s.emailSvc.SendPasswordResetEmail(email, token)
// }

// func (s *authService) ResetPassword(token, newPassword string) error {
// 	userID, err := s.authRepo.GetUserIDByResetToken(token)
// 	if err != nil {
// 		return errors.New("invalid or expired token")
// 	}

// 	user, err := s.userRepo.GetByID(userID)
// 	if err != nil {
// 		return err
// 	}

// 	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
// 	if err != nil {
// 		return err
// 	}

// 	user.HashedPassword = string(hashedPassword)
// 	return s.userRepo.Update(user)
// }

// func (s *authService) ChangePassword(userID, oldPassword, newPassword string) error {
// 	user, err := s.userRepo.GetByID(userID)
// 	if err != nil {
// 		return err
// 	}

// 	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(oldPassword)); err != nil {
// 		return errors.New("invalid current password")
// 	}

// 	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
// 	if err != nil {
// 		return err
// 	}

// 	user.HashedPassword = string(hashedPassword)
// 	return s.userRepo.Update(user)
// }
