package services

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Helper functions to be implemented
func generateToken() string {
	// Generate a 32-byte random token
	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		panic("failed to generate random token: " + err.Error())
	}

	// Encode the token in URL-safe base64
	return base64.URLEncoding.EncodeToString(tokenBytes)
}

func generateJWT(userID string, secret []byte, expiry time.Duration) string {
	// Create the claims for the JWT
	claims := jwt.RegisteredClaims{
		Subject:   userID,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiry)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	// Create the token with the claims and sign it
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(secret)
	if err != nil {
		panic("failed to sign JWT token: " + err.Error())
	}

	return signedToken
}
