package firebase

import (
	"context"
	"time"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
)

type (
	// UserManager handles user-related operations
	UserManager interface {
		CreateUser(ctx context.Context, email, password, firstName, lastName string) (*domain.User, error)
		GetUserByEmail(ctx context.Context, email string) (*domain.User, error)
		UpdateUser(ctx context.Context, userID string, updates map[string]any) error
	}

	// AuthProvider handles authentication operations
	AuthProvider interface {
		VerifyIDToken(ctx context.Context, token string) (string, error)
		CreateCustomToken(ctx context.Context, userID string) (string, error)
	}

	// PasswordHandler handles password-related operations
	PasswordHandler interface {
		VerifyPassword(ctx context.Context, email, password string) (string, error)
		UpdatePassword(ctx context.Context, userID, newPassword string) error
	}

	// EmailHandler handles email-related operations
	EmailHandler interface {
		SendVerificationEmail(ctx context.Context, email string) (string, error)
		SendPasswordResetEmail(ctx context.Context, email string) (string, error)
		VerifyEmail(ctx context.Context, token string) error
	}

	// TokenGenerator handles token generation and validation
	TokenGenerator interface {
		GenerateVerificationToken() string
		GenerateResetToken() string
	}

	// FirebaseConfig holds configuration for Firebase client
	FirebaseConfig struct {
		ServiceAccountKeyPath string
		ProjectID             string
		StorageBucket         string
		APIKey                string
		HTTPClientTimeout     time.Duration
	}
)
