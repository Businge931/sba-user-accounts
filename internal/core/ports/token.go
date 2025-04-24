package ports

// TokenService defines the interface for token generation and validation
type TokenService interface {
	GenerateToken(userID string) (string, error)
	ValidateToken(token string) (string, error)
	GenerateVerificationToken() string
	GenerateResetToken() string
}
