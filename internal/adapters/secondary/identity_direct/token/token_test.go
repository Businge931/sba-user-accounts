package token

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateToken(t *testing.T) {
	type args struct {
		reader io.Reader
	}

	tests := []struct {
		name        string
		args        args
		validate    func(t *testing.T, token string)
		expectPanic bool
	}{
		{
			name: "successfully generates token",
			args: args{
				reader: defaultRandReader,
			},
			validate: func(t *testing.T, token string) {
				// Verify the token is URL-safe base64
				var decoded []byte
				var err error

				// First try with RawURLEncoding (no padding)
				decoded, err = base64.RawURLEncoding.DecodeString(token)
				if err != nil {
					// If that fails, try with standard URL encoding (with padding)
					decoded, err = base64.URLEncoding.DecodeString(token)
				}
				assert.NoError(t, err, "token should be valid base64 URL encoding")

				// Verify we got back 32 bytes (256 bits) of random data
				assert.Len(t, decoded, 32, "decoded token should be 32 bytes")

				// Verify the token is URL-safe (no '+' or '/')
				assert.False(t, strings.ContainsAny(token, "+/"), "token should be URL-safe (no + or / characters)")

				// Verify the token only contains valid base64 URL characters
				validChars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_="
				for _, c := range token {
					assert.True(t, strings.ContainsRune(validChars, c), "token contains invalid character: %c", c)
				}
			},
			expectPanic: false,
		},
		{
			name: "panics on random read error",
			args: args{
				reader: &errorReader{err: errors.New("test error")},
			},
			expectPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			if tt.expectPanic {
				assert.Panics(t, func() {
					generateTokenWithReader(tt.args.reader)
				}, "generateTokenWithReader should panic when random read fails")
				return
			}

			token := GenerateToken()
			if tt.validate != nil {
				tt.validate(t, token)
			}
		})
	}
}

func TestGenerateJWT(t *testing.T) {
	type args struct {
		userID string
		secret []byte
		expiry time.Duration
	}

	tests := []struct {
		name        string
		args        args
		setup       func() (cleanup func())
		validate    func(t *testing.T, tokenString string)
		expectPanic bool
	}{
		{
			name: "successfully generates JWT",
			args: args{
				userID: "user123",
				secret: []byte("test-secret"),
				expiry: time.Hour,
			},
			validate: func(t *testing.T, tokenString string) {
				assert.NotEmpty(t, tokenString, "token should not be empty")

				// Parse the token to verify its contents
				token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
					return []byte("test-secret"), nil
				})
				require.NoError(t, err, "should parse token without error")

				// Verify the claims
				claims, ok := token.Claims.(*jwt.RegisteredClaims)
				require.True(t, ok, "should be able to cast claims to RegisteredClaims")

				assert.Equal(t, "user123", claims.Subject, "subject should match user ID")
				assert.WithinDuration(t, time.Now().Add(time.Hour), claims.ExpiresAt.Time, 5*time.Second, "expiry time should be set correctly")
				assert.WithinDuration(t, time.Now(), claims.IssuedAt.Time, 5*time.Second, "issued at time should be now")
			},
			expectPanic: false,
		},
		{
			name: "expiry is set correctly",
			args: args{
				userID: "user123",
				secret: []byte("test-secret"),
				expiry: 2 * time.Hour,
			},
			validate: func(t *testing.T, tokenString string) {
				token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
					return []byte("test-secret"), nil
				})
				require.NoError(t, err)

				claims := token.Claims.(*jwt.RegisteredClaims)
				assert.WithinDuration(t, time.Now().Add(2*time.Hour), claims.ExpiresAt.Time, 5*time.Second, "expiry time should be set correctly")
			},
			expectPanic: false,
		},
		{
			name: "panics on signing error",
			args: args{
				userID: "user123",
				secret: []byte("test-secret"),
				expiry: time.Hour,
			},
			setup: func() (cleanup func()) {
				// Save original function
				oldSigningMethodHS256 := jwt.SigningMethodHS256

				// Create a mock signing method that will always fail
				mockSigningMethod := &jwt.SigningMethodHMAC{
					Name: "HS256",
				}
				mockSigningMethod.Hash = crypto.Hash(0) // This will make the signing fail

				// Override the default signing method
				jwt.SigningMethodHS256 = mockSigningMethod

				// Return cleanup function to restore original method
				return func() {
					jwt.SigningMethodHS256 = oldSigningMethodHS256
				}
			},
			expectPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Run setup if provided
			var cleanup func()
			if tt.setup != nil {
				cleanup = tt.setup()
				if cleanup != nil {
					defer cleanup()
				}
			}

			if tt.expectPanic {
				assert.Panics(t, func() {
					GenerateJWT(tt.args.userID, tt.args.secret, tt.args.expiry)
				}, "expected panic when signing fails")
				return
			}

			tokenString := GenerateJWT(tt.args.userID, tt.args.secret, tt.args.expiry)
			if tt.validate != nil {
				tt.validate(t, tokenString)
			}
		})
	}
}

// errorReader is a mock reader that always returns an error
type errorReader struct {
	err error
}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, e.err
}

// TestGenerateTokenWithFixedData tests token generation with fixed input data
func TestGenerateTokenWithFixedData(t *testing.T) {
	// Create a reader that returns fixed data
	fixedData := bytes.Repeat([]byte{0x01}, 32)
	reader := bytes.NewReader(fixedData)

	// Generate token with our fixed data
	token := generateTokenWithReader(reader)

	// The base64 encoding of 32 bytes of 0x01 (with padding)
	expected := "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	assert.Equal(t, expected, token, "token should match expected base64 encoding")
}
