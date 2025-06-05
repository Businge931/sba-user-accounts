package postgres

import (
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
)

// AuthRepository implements the ports.AuthRepository interface using PostgreSQL
type AuthRepository struct {
	db *gorm.DB
}

// NewAuthRepository creates a new instance of PostgreSQL AuthRepository
func NewAuthRepository(db *gorm.DB) *AuthRepository {
	return &AuthRepository{
		db: db,
	}
}

// StoreVerificationToken stores a verification token for a user
func (repo *AuthRepository) StoreVerificationToken(userID, token string) error {
	// Set token expiry (e.g., 24 hours from now)
	tokenRecord := &domain.Token{
		TokenID:   token,
		UserID:    userID,
		TokenType: domain.VerificationToken,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	// Use FirstOrCreate to handle upsert
	result := repo.db.Where(domain.Token{TokenID: token}).
		Attrs(tokenRecord).
		FirstOrCreate(tokenRecord)

	if result.Error != nil {
		return result.Error
	}

	// Update the token if it already existed
	if result.RowsAffected == 0 {
		result = repo.db.Model(tokenRecord).
			Where("token_id = ?", token).
			Updates(map[string]interface{}{
				"user_id":    userID,
				"token_type": domain.VerificationToken,
				"expires_at": time.Now().Add(24 * time.Hour),
			})
	}

	return result.Error
}

// GetUserIDByVerificationToken retrieves the user ID associated with a verification token
func (repo *AuthRepository) GetUserIDByVerificationToken(token string) (string, error) {
	var tokenRecord domain.Token
	
	result := repo.db.Where("token_id = ? AND token_type = ?", token, domain.VerificationToken).First(&tokenRecord)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", gorm.ErrRecordNotFound
		}
		return "", result.Error
	}

	// Check if token has expired
	if time.Now().After(tokenRecord.ExpiresAt) {
		return "", errors.New("token has expired")
	}

	return tokenRecord.UserID, nil
}

// StoreResetToken stores a password reset token for a user
func (repo *AuthRepository) StoreResetToken(userID, token string) error {
	// Set token expiry (e.g., 1 hour from now)
	tokenRecord := &domain.Token{
		TokenID:   token,
		UserID:    userID,
		TokenType: domain.ResetToken,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	// Use FirstOrCreate to handle upsert
	result := repo.db.Where(domain.Token{TokenID: token}).
		Attrs(tokenRecord).
		FirstOrCreate(tokenRecord)

	if result.Error != nil {
		return result.Error
	}

	// Update the token if it already existed
	if result.RowsAffected == 0 {
		result = repo.db.Model(tokenRecord).
			Where("token_id = ?", token).
			Updates(map[string]interface{}{
				"user_id":    userID,
				"token_type": domain.ResetToken,
				"expires_at": time.Now().Add(1 * time.Hour),
			})
	}

	return result.Error
}

// GetUserIDByResetToken retrieves the user ID associated with a reset token
func (repo *AuthRepository) GetUserIDByResetToken(token string) (string, error) {
	var tokenRecord domain.Token
	
	result := repo.db.Where("token_id = ? AND token_type = ?", token, domain.ResetToken).First(&tokenRecord)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", gorm.ErrRecordNotFound
		}
		return "", result.Error
	}

	// Check if token has expired
	if time.Now().After(tokenRecord.ExpiresAt) {
		return "", errors.New("token has expired")
	}

	return tokenRecord.UserID, nil
}
