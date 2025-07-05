package token

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// randomReader is an interface that wraps the standard io.Reader interface.
// It's defined here so we can mock it in tests.
type randomReader interface {
	io.Reader
}

var defaultRandReader randomReader = rand.Reader

func GenerateToken() string {
	return generateTokenWithReader(defaultRandReader)
}

func generateTokenWithReader(reader randomReader) string {
	// Generate a 32-byte random token
	tokenBytes := make([]byte, 32)
	_, err := io.ReadFull(reader, tokenBytes)
	if err != nil {
		panic("failed to generate random token: " + err.Error())
	}

	// Encode the token in URL-safe base64
	return base64.URLEncoding.EncodeToString(tokenBytes)
}

func GenerateJWT(userID string, secret []byte, expiry time.Duration) string {
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
