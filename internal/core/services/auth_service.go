package services

import (
	"errors"
	"time"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/Businge931/sba-user-accounts/internal/core/ports"
	"golang.org/x/crypto/bcrypt"
)

type authService struct {
	userRepo    ports.UserRepository
	authRepo    ports.AuthRepository
	emailSvc    ports.EmailService
	jwtSecret   []byte
	tokenExpiry time.Duration
}

// NewAuthService creates a new instance of authentication service
func NewAuthService(
	userRepo ports.UserRepository,
	authRepo ports.AuthRepository,
	emailSvc ports.EmailService,
	jwtSecret []byte,
	tokenExpiry time.Duration,
) ports.AuthService {
	return &authService{
		userRepo:    userRepo,
		authRepo:    authRepo,
		emailSvc:    emailSvc,
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

	// Create user
	user := domain.NewUser(email, firstName, lastName)
	user.HashedPassword = string(hashedPassword)

	if err := s.userRepo.Create(user); err != nil {
		return nil, err
	}

	// Generate and send verification token
	token := generateToken() // Implementation needed
	if err := s.authRepo.StoreVerificationToken(user.ID, token); err != nil {
		return nil, err
	}

	// Send verification email
	if err := s.emailSvc.SendVerificationEmail(user.Email, token); err != nil {
		return nil, err
	}

	return user, nil
}

func (s *authService) Login(email, password string) (string, error) {
	user, err := s.userRepo.GetByEmail(email)
	if err != nil {
		return "", errors.New("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(password)); err != nil {
		return "", errors.New("invalid credentials")
	}

	if !user.IsEmailVerified {
		return "", errors.New("email not verified")
	}

	// Generate JWT token
	token := generateJWT(user.ID, s.jwtSecret, s.tokenExpiry) // Implementation needed
	return token, nil
}

func (s *authService) VerifyEmail(token string) error {
	userID, err := s.authRepo.GetUserIDByVerificationToken(token)
	if err != nil {
		return errors.New("invalid or expired token")
	}

	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return err
	}

	user.IsEmailVerified = true
	return s.userRepo.Update(user)
}

func (s *authService) RequestPasswordReset(email string) error {
	user, err := s.userRepo.GetByEmail(email)
	if err != nil {
		return nil // Don't reveal if email exists
	}

	token := generateToken() // Implementation needed
	if err := s.authRepo.StoreResetToken(user.ID, token); err != nil {
		return err
	}

	return s.emailSvc.SendPasswordResetEmail(email, token)
}

func (s *authService) ResetPassword(token, newPassword string) error {
	userID, err := s.authRepo.GetUserIDByResetToken(token)
	if err != nil {
		return errors.New("invalid or expired token")
	}

	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user.HashedPassword = string(hashedPassword)
	return s.userRepo.Update(user)
}

func (s *authService) ChangePassword(userID, oldPassword, newPassword string) error {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(oldPassword)); err != nil {
		return errors.New("invalid current password")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user.HashedPassword = string(hashedPassword)
	return s.userRepo.Update(user)
}


