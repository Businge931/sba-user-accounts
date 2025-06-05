package domain

import (
	"time"
)

// TokenType represents the type of token
type TokenType string

const (
	// VerificationToken is used for email verification
	VerificationToken TokenType = "verification"
	// ResetToken is used for password reset
	ResetToken TokenType = "reset"
)

// Token represents an authentication token in the system
type Token struct {
	TokenID   string    `gorm:"primaryKey;column:token_id"`
	UserID    string    `gorm:"not null;index"`
	TokenType TokenType `gorm:"not null;type:varchar(50)"`
	ExpiresAt time.Time `gorm:"not null"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
}

// TableName specifies the table name for the Token model
func (Token) TableName() string {
	return "tokens"
}
