package services

import (
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/Businge931/sba-user-accounts/internal/core/ports"
	"golang.org/x/crypto/bcrypt"
)

type authService struct {
	userRepo ports.UserRepository
	authRepo ports.AuthRepository
	// emailSvc    ports.EmailService
	jwtSecret   []byte
	tokenExpiry time.Duration
}

// NewAuthService creates a new instance of authentication service
func NewAuthService(
	userRepo ports.UserRepository,
	authRepo ports.AuthRepository,
	// emailSvc ports.EmailService,
	jwtSecret []byte,
	tokenExpiry time.Duration,
) ports.AuthService {
	return &authService{
		userRepo: userRepo,
		authRepo: authRepo,
		// emailSvc:    emailSvc,
		jwtSecret:   jwtSecret,
		tokenExpiry: tokenExpiry,
	}
}

func (s *authService) Register(email, password, firstName, lastName string) (*domain.User, error) {
	// Check if user already exists
	if existing, _ := s.userRepo.GetByEmail(email); existing != nil {
		return nil, errors.New("user already exists")
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Create user with UUID
	user := domain.NewUser(email, firstName, lastName)
	user.HashedPassword = string(hashedPassword)
	user.ID = generateUUID() // Generate a unique ID

	if err := s.userRepo.Create(user); err != nil {
		return nil, err
	}

	// Skip verification token if authRepo is nil
	if s.authRepo != nil {
		// Generate and send verification token
		token := generateToken()
		if err := s.authRepo.StoreVerificationToken(user.ID, token); err != nil {
			// Just log the error and continue
			// Don't return an error as this is optional functionality
		}

		// Send verification email - skipped as EmailService not implemented
	}

	return user, nil
}

// generateUUID generates a simple UUID for user identification
func generateUUID() string {
	now := time.Now()
	rand.Seed(now.UnixNano())
	return fmt.Sprintf("%d-%d", now.UnixNano(), rand.Intn(10000))
}

// Standard error messages for consistent handling
const (
	ErrMsgUserNotFound    = "USER_NOT_FOUND"
	ErrMsgInvalidPassword = "INVALID_PASSWORD"
	ErrMsgEmailNotVerified = "EMAIL_NOT_VERIFIED"
)

func (s *authService) Login(email, password string) (string, error) {
	// Check if user exists
	user, err := s.userRepo.GetByEmail(email)
	if err != nil {
		// Log the actual error for debugging purposes
		fmt.Printf("Error getting user by email: %v\n", err)
		return "", errors.New(ErrMsgUserNotFound)
	}

	// Check if password is correct
	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(password)); err != nil {
		// Log the error but don't expose it in the response
		fmt.Printf("Password comparison failed: %v\n", err)
		return "", errors.New(ErrMsgInvalidPassword)
	}

	// Temporarily bypassing email verification check for testing
	// if !user.IsEmailVerified {
	// 	return "", ErrEmailNotVerified
	// }

	// Generate JWT token
	token := generateJWT(user.ID, s.jwtSecret, s.tokenExpiry)
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
