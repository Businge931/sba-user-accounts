package firebase

import "crypto/rand"

// defaultTokenGenerator implements the TokenGenerator interface
type defaultTokenGenerator struct{}

// NewTokenGenerator creates a new instance of the default token generator
func NewTokenGenerator() TokenGenerator {
	return &defaultTokenGenerator{}
}

func (g *defaultTokenGenerator) GenerateVerificationToken() string {
	return generateRandomString(32)
}

func (g *defaultTokenGenerator) GenerateResetToken() string {
	return generateRandomString(32)
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic(err) // This should never happen with crypto/rand
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}
