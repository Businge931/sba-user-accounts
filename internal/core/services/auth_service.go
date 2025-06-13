package services

import (
	"fmt"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/Businge931/sba-user-accounts/internal/core/errors"
	"github.com/Businge931/sba-user-accounts/internal/core/ports"
)

type authService struct {
	userRepo          ports.UserRepository
	validator         ports.ValidationService
	logger            ports.Logger
	indentityProvider ports.IdentityService
	// authRepo ports.AuthRepository
	// tokenSvc          ports.TokenService
}

func NewAuthService(
	userRepo ports.UserRepository,
	validator ports.ValidationService,
	indentityProvider ports.IdentityService,
	logger ports.Logger,
	// authRepo ports.AuthRepository,
	// tokenSvc ports.TokenService,
) ports.AuthService {
	return &authService{
		userRepo:          userRepo,
		validator:         validator,
		indentityProvider: indentityProvider,
		logger:            logger,
		// authRepo: authRepo,
		// tokenSvc:  tokenSvc,
	}
}

func (svc *authService) Register(req domain.RegisterRequest) (*domain.User, error) {
	if err := svc.validator.ValidateRegisterRequest(req); err != nil {
		return nil, err
	}

	// Check if user already exists
	if existing, _ := svc.userRepo.GetByEmail(req.Email); existing != nil {
		svc.logger.Infof("Registration attempt with existing email: %s", req.Email)
		return nil, errors.NewAlreadyExistsError("user with this email already exists", nil)
	}

	// Register user using identity provider
	user, err := svc.indentityProvider.Register(req)
	if err != nil {
		return nil, fmt.Errorf("failed to register user,%w", err)
	}

	//save user to repository
	if err := svc.userRepo.Create(user); err != nil {
		return nil, err
	}

	// Send verification email - skipped as EmailService not implemented

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
		return "", errors.NewNotFoundError("user not found", err)
	}

	token, err := svc.indentityProvider.Login(req, user)
	if err != nil {
		return "", err
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
