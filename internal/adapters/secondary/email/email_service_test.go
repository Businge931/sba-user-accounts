package email

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// captureOutput captures log output for testing
func captureLogOutput(f func()) string {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stdout)

	f()
	return buf.String()
}

func TestLoggingEmailService_SendVerificationEmail(t *testing.T) {
	tests := []struct {
		name     string
		baseURL  string
		to       string
		token    string
		expected string
	}{
		{
			name:     "successful verification email",
			baseURL:  "https://example.com",
			to:       "test@example.com",
			token:    "test-verification-token",
			expected: "To: test@example.com, Subject: Email Verification, Body: Please verify your email by clicking on the following link: https://example.com/verify-email?token=test-verification-token",
		},
		{
			name:     "empty token",
			baseURL:  "https://example.com",
			to:       "test@example.com",
			token:    "",
			expected: "To: test@example.com, Subject: Email Verification, Body: Please verify your email by clicking on the following link: https://example.com/verify-email?token=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture log output
			output := captureLogOutput(func() {
				service := NewLoggingEmailService(tt.baseURL)
				err := service.SendVerificationEmail(tt.to, tt.token)
				assert.NoError(t, err)
			})

			// Clean up the output (remove timestamp and newline)
			output = strings.TrimSpace(output)
			logParts := strings.SplitN(output, "] ", 2)
			if len(logParts) > 1 {
				output = "[" + logParts[1]
			}

			assert.Contains(t, output, tt.expected)
		})
	}
}

func TestLoggingEmailService_SendPasswordResetEmail(t *testing.T) {
	tests := []struct {
		name     string
		baseURL  string
		to       string
		token    string
		expected string
	}{
		{
			name:     "successful password reset email",
			baseURL:  "https://example.com",
			to:       "user@example.com",
			token:    "test-reset-token",
			expected: "To: user@example.com, Subject: Password Reset, Body: Reset your password by clicking on the following link: https://example.com/reset-password?token=test-reset-token",
		},
		{
			name:     "empty token",
			baseURL:  "https://example.com",
			to:       "user@example.com",
			token:    "",
			expected: "To: user@example.com, Subject: Password Reset, Body: Reset your password by clicking on the following link: https://example.com/reset-password?token=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture log output
			output := captureLogOutput(func() {
				service := NewLoggingEmailService(tt.baseURL)
				err := service.SendPasswordResetEmail(tt.to, tt.token)
				assert.NoError(t, err)
			})

			// Clean up the output (remove timestamp and newline)
			output = strings.TrimSpace(output)
			logParts := strings.SplitN(output, "] ", 2)
			if len(logParts) > 1 {
				output = "[" + logParts[1]
			}

			assert.Contains(t, output, tt.expected)
		})
	}
}

func TestLoggingEmailService_EmptyBaseURL(t *testing.T) {
	tests := []struct {
		name     string
		baseURL  string
		to       string
		token    string
		expected string
	}{
		{
			name:     "empty base URL for verification email",
			baseURL:  "",
			to:       "test@example.com",
			token:    "test-token",
			expected: "/verify-email?token=test-token",
		},
		{
			name:     "empty base URL for password reset email",
			baseURL:  "",
			to:       "test@example.com",
			token:    "test-token",
			expected: "/reset-password?token=test-token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture log output
			output := captureLogOutput(func() {
				service := NewLoggingEmailService(tt.baseURL)
				
				var err error
				if strings.Contains(tt.name, "verification") {
					err = service.SendVerificationEmail(tt.to, tt.token)
				} else {
					err = service.SendPasswordResetEmail(tt.to, tt.token)
				}
				
				assert.NoError(t, err)
			})

			// Clean up the output (remove timestamp and newline)
			output = strings.TrimSpace(output)
			logParts := strings.SplitN(output, "] ", 2)
			if len(logParts) > 1 {
				output = "[" + logParts[1]
			}

			assert.Contains(t, output, tt.expected)
		})
	}
}
