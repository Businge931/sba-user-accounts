package email

import (
	"fmt"
	"log"

	"github.com/Businge931/sba-user-accounts/internal/core/ports"
)

// LoggingEmailService is a simple implementation of the EmailService interface
// that logs emails instead of sending them. A real implementation would use an email service. **TO BE ADDED LATER**
type LoggingEmailService struct {
	appBaseURL string
}

// NewLoggingEmailService creates a new instance of the LoggingEmailService
func NewLoggingEmailService(appBaseURL string) ports.EmailService {
	return &LoggingEmailService{
		appBaseURL: appBaseURL,
	}
}

// SendVerificationEmail logs the verification email instead of sending it
func (s *LoggingEmailService) SendVerificationEmail(to, token string) error {
	verificationLink := fmt.Sprintf("%s/verify-email?token=%s", s.appBaseURL, token)

	log.Printf("[EMAIL LOG] To: %s, Subject: Email Verification, Body: Please verify your email by clicking on the following link: %s",
		to, verificationLink)

	return nil
}

// SendPasswordResetEmail logs the password reset email instead of sending it
func (s *LoggingEmailService) SendPasswordResetEmail(to, token string) error {
	resetLink := fmt.Sprintf("%s/reset-password?token=%s", s.appBaseURL, token)

	log.Printf("[EMAIL LOG] To: %s, Subject: Password Reset, Body: Reset your password by clicking on the following link: %s",
		to, resetLink)

	return nil
}
