package ports

import "github.com/Businge931/sba-user-accounts/internal/core/domain"

type 
(
	// UserRepository defines the interface for user data persistence
	UserRepository interface {
	Create(user *domain.User) error
	GetByID(id string) (*domain.User, error)
	GetByEmail(email string) (*domain.User, error)
	Update(user *domain.User) error
	Delete(id string) error
	}

	// AuthRepository defines the interface for authentication-related operations
 	AuthRepository interface {
	StoreVerificationToken(userID, token string) error
	GetUserIDByVerificationToken(token string) (string, error)
	GetVerificationTokenByUserID(userID string) (string, error)
	StoreResetToken(userID, token string) error
	GetUserIDByResetToken(token string) (string, error)
	}
)
