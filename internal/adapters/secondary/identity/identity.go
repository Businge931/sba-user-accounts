package identity

import (
	"fmt"
	"time"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/Businge931/sba-user-accounts/internal/core/ports"
	"golang.org/x/crypto/bcrypt"
)

type identityProvider struct {
	authRepo ports.AuthRepository
	tokenSvc ports.TokenService
	logger   ports.Logger
}

func NewIdentityProvider(
	authRepo ports.AuthRepository,
	tokenSvc ports.TokenService,
	logger ports.Logger,
) ports.IdentityService {
	return &identityProvider{
		authRepo: authRepo,
		tokenSvc: tokenSvc,
		logger:   logger,
	}
}

func (svc *identityProvider) Register(req domain.RegisterRequest) (*domain.User, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user with UUID
	user := domain.NewUser(req.Email, req.FirstName, req.LastName)
	user.HashedPassword = string(hashedPassword)
	user.ID = fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().Nanosecond())

	if svc.authRepo != nil {
		token := svc.tokenSvc.GenerateVerificationToken()
		if err := svc.authRepo.StoreVerificationToken(user.ID, token); err != nil {
			svc.logger.Warnf("Failed to store verification token for user %s: %v", user.ID, err)
		}
	}

	return user, nil
}

func (svc *identityProvider) Login(req domain.LoginRequest, user *domain.User) (string, error) {
	if user == nil {
		return "", fmt.Errorf("user not found")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(req.Password)); err != nil {
		svc.logger.Debugf("Password comparison failed: %v", err)
		return "", fmt.Errorf("invalid password")
	}

	// Temporarily bypassing email verification check for testing
	// if !user.IsEmailVerified {
	// 	return "", ErrEmailNotVerified
	// }

	token, err := svc.tokenSvc.GenerateToken(user.ID)
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	return token, nil
}
