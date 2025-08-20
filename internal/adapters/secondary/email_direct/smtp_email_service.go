package email

import (
	"fmt"
	"log"

	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/validation"
	"github.com/Businge931/sba-user-accounts/internal/config"
	"github.com/Businge931/sba-user-accounts/internal/core/ports"

	"gopkg.in/gomail.v2"
)

// Dialer defines the interface for sending emails
type Dialer interface {
	DialAndSend(messages ...*gomail.Message) error
}

// SMTPEmailService is an implementation of EmailService that sends real emails via SMTP
type SMTPEmailService struct {
	dialer    Dialer
	from      string
	baseURL   string
	validator *validation.Validator
}

// NewSMTPEmailService creates a new instance of SMTPEmailService
func NewSMTPEmailService(cfg *config.SMTPConfig, baseURL string) ports.EmailService {
	dialer := gomail.NewDialer(
		cfg.Host,
		cfg.Port,
		cfg.Username,
		cfg.Password,
	)

	return NewSMTPEmailServiceWithDeps(dialer, cfg.From, baseURL, validation.NewValidator())
}

// NewSMTPEmailServiceWithDeps creates a new SMTPEmailService with all dependencies
// This is useful for testing
func NewSMTPEmailServiceWithDeps(dialer Dialer, from, baseURL string, validator *validation.Validator) *SMTPEmailService {
	return &SMTPEmailService{
		dialer:    dialer,
		from:      from,
		baseURL:   baseURL,
		validator: validator,
	}
}

// NewSMTPEmailServiceWithDialer creates a new SMTPEmailService with a custom dialer
// This is kept for backward compatibility
// Deprecated: Use NewSMTPEmailServiceWithDeps instead
func NewSMTPEmailServiceWithDialer(dialer Dialer, from, baseURL string) *SMTPEmailService {
	return NewSMTPEmailServiceWithDeps(dialer, from, baseURL, validation.NewValidator())
}

// SendVerificationEmail sends a verification email to the specified address
func (s *SMTPEmailService) SendVerificationEmail(to, token string) error {
	if err := s.validator.ValidateEmail(to); err != nil {
		return fmt.Errorf("invalid email: %w", err)
	}

	verificationLink := fmt.Sprintf("%s/verify-email?token=%s", s.baseURL, token)

	m := gomail.NewMessage()
	m.SetHeader("From", s.from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", "Verify Your Email Address")
	m.SetBody("text/plain", fmt.Sprintf(
		"Please verify your email by clicking on the following link: %s\n\n"+
			"If you did not request this, please ignore this email.", verificationLink))

	m.SetBody("text/html", fmt.Sprintf(
		`<p>Please verify your email by clicking the button below:</p>
		<p><a href="%s" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-align: center; text-decoration: none; display: inline-block; border-radius: 5px;">Verify Email</a></p>
		<p>Or copy and paste this link into your browser: %s</p>
		<p>If you did not request this, please ignore this email.</p>`, verificationLink, verificationLink))

	if err := s.dialer.DialAndSend(m); err != nil {
		log.Printf("Failed to send verification email: %v", err)
		return fmt.Errorf("failed to send verification email: %w", err)
	}

	log.Printf("Verification email sent to %s", to)
	return nil
}

// SendPasswordResetEmail sends a password reset email to the specified address
func (s *SMTPEmailService) SendPasswordResetEmail(to, token string) error {
	if err := s.validator.ValidateEmail(to); err != nil {
		return fmt.Errorf("invalid email: %w", err)
	}

	resetLink := fmt.Sprintf("%s/reset-password?token=%s", s.baseURL, token)

	m := gomail.NewMessage()
	m.SetHeader("From", s.from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", "Reset Your Password")
	m.SetBody("text/plain", fmt.Sprintf(
		"You have requested to reset your password. Click the following link to reset it: %s\n\n"+
			"If you did not request this, please ignore this email and your password will remain unchanged.", resetLink))

	m.SetBody("text/html", fmt.Sprintf(
		`<p>You have requested to reset your password. Click the button below to reset it:</p>
		<p><a href="%s" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-align: center; text-decoration: none; display: inline-block; border-radius: 5px;">Reset Password</a></p>
		<p>Or copy and paste this link into your browser: %s</p>
		<p>If you did not request this, please ignore this email and your password will remain unchanged.</p>`, resetLink, resetLink))

	if err := s.dialer.DialAndSend(m); err != nil {
		log.Printf("Failed to send password reset email: %v", err)
		return fmt.Errorf("failed to send password reset email: %w", err)
	}

	log.Printf("Password reset email sent to %s", to)
	return nil
}

// SendRegistrationEmail sends a registration confirmation email to the specified address
func (s *SMTPEmailService) SendRegistrationEmail(to, token string) error {
	if err := s.validator.ValidateEmail(to); err != nil {
		return fmt.Errorf("invalid email: %w", err)
	}

	// Create a confirmation link with the token
	confirmationLink := fmt.Sprintf("%s/confirm-registration?token=%s", s.baseURL, token)

	m := gomail.NewMessage()
	m.SetHeader("From", s.from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", "Welcome - Confirm Your Registration")

	// Plain text version
	m.SetBody("text/plain", fmt.Sprintf(
		"Welcome! Thank you for registering.\n\n"+
			"To complete your registration, please click the following link: %s\n\n"+
			"If you did not register, please ignore this email.", confirmationLink))

	// HTML version
	m.AddAlternative("text/html", fmt.Sprintf(
		`<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
		  <h2 style="color: #2c3e50;">Welcome!</h2>
		  <p>Thank you for registering with our service.</p>
		  <p>To complete your registration, please click the button below:</p>
		  <p style="margin: 30px 0;">
		    <a href="%s" style="background-color: #3498db; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold;">
		      Confirm Registration
		    </a>
		  </p>
		  <p>Or copy and paste this link into your browser:</p>
		  <p style="word-break: break-all; color: #7f8c8d;">%s</p>
		  <p style="margin-top: 30px; color: #7f8c8d; font-size: 0.9em;">
		    If you did not register, please ignore this email.
		  </p>
		</div>`, confirmationLink, confirmationLink))

	// Send the email
	if err := s.dialer.DialAndSend(m); err != nil {
		log.Printf("Failed to send registration email: %v", err)
		return fmt.Errorf("failed to send registration email: %w", err)
	}

	log.Printf("Registration email sent to %s", to)
	return nil
}
