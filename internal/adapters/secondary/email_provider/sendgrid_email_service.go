package emailprovider

import (
	"fmt"

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

type SendGridEmailService struct {
	client      *sendgrid.Client
	fromEmail   string
	fromName    string
	frontendURL string
}

// NewSendGridEmailService creates a new instance of SendGridEmailService
func NewSendGridEmailService(apiKey, fromEmail, fromName, frontendURL string) *SendGridEmailService {
	return &SendGridEmailService{
		client:      sendgrid.NewSendClient(apiKey),
		fromEmail:   fromEmail,
		fromName:    fromName,
		frontendURL: frontendURL,
	}
}

// SendVerificationEmail sends a verification email to the specified address
func (s *SendGridEmailService) SendVerificationEmail(to, token string) error {
	verificationURL := fmt.Sprintf("%s/verify-email?token=%s", s.frontendURL, token)
	subject := "Verify Your Email Address"
	content := fmt.Sprintf(`
		<h1>Welcome!</h1>
		<p>Thank you for registering. Please verify your email address by clicking the link below:</p>
		<p><a href="%s">Verify Email Address</a></p>
		<p>If you did not create an account, please ignore this email.</p>
	`, verificationURL)

	return s.sendEmail(to, subject, content)
}

// SendPasswordResetEmail sends a password reset email to the specified address
func (s *SendGridEmailService) SendPasswordResetEmail(to, token string) error {
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", s.frontendURL, token)

	subject := "Password Reset Request"
	content := fmt.Sprintf(`
		<h1>Password Reset</h1>
		<p>You requested to reset your password. Click the link below to set a new password:</p>
		<p><a href="%s">Reset Password</a></p>
		<p>This link will expire in 1 hour.</p>
		<p>If you did not request a password reset, please ignore this email.</p>
	`, resetURL)

	return s.sendEmail(to, subject, content)
}

// SendRegistrationEmail sends a registration confirmation email to the specified address
func (s *SendGridEmailService) SendRegistrationEmail(to, token string) error {
	// Create a confirmation link with the token
	confirmationLink := fmt.Sprintf("%s/confirm-registration?token=%s", s.frontendURL, token)

	subject := "Welcome - Confirm Your Registration"
	content := fmt.Sprintf(`
		<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
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
		</div>
	`, confirmationLink, confirmationLink)

	return s.sendEmail(to, subject, content)
}

// sendEmail is a helper function to send emails using SendGrid
func (s *SendGridEmailService) sendEmail(to, subject, content string) error {
	from := mail.NewEmail(s.fromName, s.fromEmail)
	receiver := mail.NewEmail("", to)
	message := mail.NewSingleEmail(from, subject, receiver, "", content)

	response, err := s.client.Send(message)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	// Check for error status codes
	if response.StatusCode >= 400 {
		return fmt.Errorf("email sending failed with status %d: %s", response.StatusCode, response.Body)
	}

	return nil
}