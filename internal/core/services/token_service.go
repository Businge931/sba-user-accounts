package services

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Businge931/sba-user-accounts/internal/core/ports"
)

// jwtTokenService implements the TokenService interface using JWT tokens
type jwtTokenService struct {
	secret      []byte
	tokenExpiry time.Duration
}

// NewJWTTokenService creates a new JWT-based token service
func NewJWTTokenService(secret []byte, tokenExpiry time.Duration) ports.TokenService {
	return &jwtTokenService{
		secret:      secret,
		tokenExpiry: tokenExpiry,
	}
}

// GenerateToken creates a new JWT token with the user ID as the subject
func (s *jwtTokenService) GenerateToken(userID string) (string, error) {
	// Create the claims for the JWT
	claims := jwt.RegisteredClaims{
		Subject:   userID,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.tokenExpiry)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	// Create the token with the claims and sign it
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(s.secret)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// ValidateToken validates a JWT token and returns the user ID
func (s *jwtTokenService) ValidateToken(tokenString string) (string, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&jwt.RegisteredClaims{},
		func(token *jwt.Token) (interface{}, error) {
			// Validate the signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return s.secret, nil
		},
	)
	if err != nil {
		return "", err
	}

	if !token.Valid {
		return "", errors.New("invalid token")
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return "", errors.New("invalid claims")
	}

	return claims.Subject, nil
}

// GenerateVerificationToken creates a token for email verification
func (s *jwtTokenService) GenerateVerificationToken() string {
	return GenerateToken()
}

// GenerateResetToken creates a token for password reset
func (s *jwtTokenService) GenerateResetToken() string {
	return GenerateToken()
}
