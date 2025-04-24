package postgres

import (
	"database/sql"
	"errors"
	"time"
)

// Errors returned by the repository
var (
	ErrNotFound     = errors.New("record not found")
	ErrTokenExpired = errors.New("token has expired")
)

// TokenType represents the type of token
type TokenType string

const (
	// VerificationToken is used for email verification
	VerificationToken TokenType = "verification"
	// ResetToken is used for password reset
	ResetToken TokenType = "reset"
)

// AuthRepository implements the ports.AuthRepository interface using PostgreSQL
type AuthRepository struct {
	db *sql.DB
}

// NewAuthRepository creates a new instance of PostgreSQL AuthRepository
func NewAuthRepository(db *sql.DB) *AuthRepository {
	return &AuthRepository{
		db: db,
	}
}

// ensureTokenTable creates the tokens table if it doesn't exist
func (repo *AuthRepository) ensureTokenTable() error {
	// Create tokens table if it doesn't exist
	query := `
	CREATE TABLE IF NOT EXISTS tokens (
		token_id VARCHAR(255) PRIMARY KEY,
		user_id VARCHAR(255) NOT NULL,
		token_type VARCHAR(50) NOT NULL,
		expiry_time TIMESTAMP NOT NULL,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)
	`
	_, err := repo.db.Exec(query)
	return err
}

// StoreVerificationToken stores a verification token for a user
func (repo *AuthRepository) StoreVerificationToken(userID, token string) error {
	// Ensure the tokens table exists
	if err := repo.ensureTokenTable(); err != nil {
		return err
	}

	// First, delete any existing verification tokens for this user
	deleteQuery := `DELETE FROM tokens WHERE user_id = $1 AND token_type = $2`
	_, err := repo.db.Exec(deleteQuery, userID, VerificationToken)
	if err != nil {
		return err
	}

	// Store the new token with an expiry of 24 hours
	query := `INSERT INTO tokens (user_id, token_type, token, created_at, expires_at)
	VALUES ($1, 'verification', $2, NOW(), NOW() + INTERVAL '24 hours')`

	_, err = repo.db.Exec(query, userID, token)
	return err
}

// GetUserIDByVerificationToken retrieves the user ID associated with a verification token
func (repo *AuthRepository) GetUserIDByVerificationToken(token string) (string, error) {
	query := `
	SELECT user_id, expiry_time FROM tokens 
	WHERE token_id = $1 AND token_type = $2
	`
	var userID string
	var expiryTime time.Time

	err := repo.db.QueryRow(query, token, VerificationToken).Scan(&userID, &expiryTime)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}

	// Check if token has expired
	if time.Now().After(expiryTime) {
		return "", ErrTokenExpired
	}

	return userID, nil
}

// StoreResetToken stores a password reset token for a user
func (repo *AuthRepository) StoreResetToken(userID, token string) error {
	// Ensure the tokens table exists
	if err := repo.ensureTokenTable(); err != nil {
		return err
	}

	// First, delete any existing reset tokens for this user
	deleteQuery := `DELETE FROM tokens WHERE user_id = $1 AND token_type = $2`
	_, err := repo.db.Exec(deleteQuery, userID, ResetToken)
	if err != nil {
		return err
	}

	// Store the new token with an expiry of 1 hour
	query := `INSERT INTO tokens (user_id, token_type, token, created_at, expires_at)
	VALUES ($1, 'reset', $2, NOW(), NOW() + INTERVAL '1 hour')`

	_, err = repo.db.Exec(query, userID, token)
	return err
}

// GetUserIDByResetToken retrieves the user ID associated with a reset token
func (repo *AuthRepository) GetUserIDByResetToken(token string) (string, error) {
	query := `
	SELECT user_id, expiry_time FROM tokens 
	WHERE token_id = $1 AND token_type = $2
	`
	var userID string
	var expiryTime time.Time

	err := repo.db.QueryRow(query, token, ResetToken).Scan(&userID, &expiryTime)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}

	// Check if token has expired
	if time.Now().After(expiryTime) {
		return "", ErrTokenExpired
	}

	return userID, nil
}
