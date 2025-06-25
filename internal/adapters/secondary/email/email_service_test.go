package email

import (
	"os"
	"strconv"
	"testing"

	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/validation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/gomail.v2"
)

// TestSMTPEmailService_Unit tests the SMTP email service with a test dialer
func TestSMTPEmailService_Unit(t *testing.T) {
	tests := []struct {
		name           string
		args           testArgs
		before         func() (*testDependencies, func())
		after          func(*testing.T, *SMTPEmailService, testArgs) error
		wantErr        bool
		expectedErrMsg string
	}{
		{
			name: "SendVerificationEmail success",
			before: func() (*testDependencies, func()) {
				return testSetup(false)
			},
			args: testArgs{
				email: "test@example.com",
				token: "test-token",
			},
			wantErr: false,
			after: func(t *testing.T, s *SMTPEmailService, args testArgs) error {
				return s.SendVerificationEmail(args.email, args.token)
			},
		},
		{
			name: "SendPasswordResetEmail success",
			before: func() (*testDependencies, func()) {
				return testSetup(false)
			},
			args: testArgs{
				email: "test@example.com",
				token: "test-token",
			},
			wantErr: false,
			after: func(t *testing.T, s *SMTPEmailService, args testArgs) error {
				return s.SendPasswordResetEmail(args.email, args.token)
			},
		},
		{
			name: "SendVerificationEmail with empty email",
			before: func() (*testDependencies, func()) {
				return testSetup(false)
			},
			args: testArgs{
				email: "",
				token: "test-token",
			},
			wantErr:        true,
			expectedErrMsg: "email is required",
			after: func(t *testing.T, s *SMTPEmailService, args testArgs) error {
				return s.SendVerificationEmail(args.email, args.token)
			},
		},
		{
			name: "SendVerificationEmail with dialer error",
			before: func() (*testDependencies, func()) {
				return testSetup(true)
			},
			args: testArgs{
				email: "test@example.com",
				token: "test-token",
			},
			wantErr: true,
			after: func(t *testing.T, s *SMTPEmailService, args testArgs) error {
				return s.SendVerificationEmail(args.email, args.token)
			},
		},
		{
			name: "SendPasswordResetEmail with dialer error",
			before: func() (*testDependencies, func()) {
				return testSetup(true)
			},
			args: testArgs{
				email: "test@example.com",
				token: "test-token",
			},
			wantErr: true,
			after: func(t *testing.T, s *SMTPEmailService, args testArgs) error {
				return s.SendPasswordResetEmail(args.email, args.token)
			},
		},
		{
			name: "SendRegistrationEmail success",
			before: func() (*testDependencies, func()) {
				return testSetup(false)
			},
			args: testArgs{
				email: "test@example.com",
				token: "test-registration-token",
			},
			wantErr: false,
			after: func(t *testing.T, s *SMTPEmailService, args testArgs) error {
				return s.SendRegistrationEmail(args.email, args.token)
			},
		},
		{
			name: "SendRegistrationEmail with empty email",
			before: func() (*testDependencies, func()) {
				return testSetup(false)
			},
			args: testArgs{
				email: "",
				token: "test-registration-token",
			},
			wantErr:        true,
			expectedErrMsg: "email is required",
			after: func(t *testing.T, s *SMTPEmailService, args testArgs) error {
				return s.SendRegistrationEmail(args.email, args.token)
			},
		},
		{
			name: "SendRegistrationEmail with invalid email format",
			before: func() (*testDependencies, func()) {
				return testSetup(false)
			},
			args: testArgs{
				email: "invalid-email",
				token: "test-registration-token",
			},
			wantErr:        true,
			expectedErrMsg: "invalid email format",
			after: func(t *testing.T, s *SMTPEmailService, args testArgs) error {
				return s.SendRegistrationEmail(args.email, args.token)
			},
		},
		{
			name: "SendRegistrationEmail with dialer error",
			before: func() (*testDependencies, func()) {
				return testSetup(true)
			},
			args: testArgs{
				email: "test@example.com",
				token: "test-registration-token",
			},
			wantErr: true,
			after: func(t *testing.T, s *SMTPEmailService, args testArgs) error {
				return s.SendRegistrationEmail(args.email, args.token)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Setup test dependencies
			deps, teardown := tt.before()
			defer teardown()

			// Create service with test dependencies
			service := newTestService(deps)

			// Execute test function
			err := tt.after(t, service, tt.args)

			// Assert expectations
			if tt.wantErr {
				require.Error(t, err, "expected an error but got none")
				if tt.expectedErrMsg != "" {
					assert.Contains(t, err.Error(), tt.expectedErrMsg,
						"error message does not match expected")
				}
			} else {
				require.NoError(t, err, "unexpected error occurred")
			}
		})
	}
}

type testDependencies struct {
	dialer    *mockDialer
	validator *validation.Validator
}

type testArgs struct {
	email string
	token string
}

func testSetup(shouldError bool) (*testDependencies, func()) {
	deps := &testDependencies{
		dialer:    &mockDialer{shouldError: shouldError},
		validator: validation.NewValidator(),
	}

	teardown := func() {
		// Any cleanup code if needed
	}

	return deps, teardown
}

// newTestService creates a new SMTPEmailService for testing
func newTestService(deps *testDependencies) *SMTPEmailService {
	return NewSMTPEmailServiceWithDeps(
		deps.dialer,
		"test@example.com",
		"http://test.local",
		deps.validator,
	)
}

// TestSMTPEmailService_Integration tests the SMTP email service with a real SMTP server
// This test is skipped by default and requires SMTP environment variables to be set
func TestSMTPEmailService_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	host := os.Getenv("SMTP_HOST")
	if host == "" {
		t.Skip("SMTP_HOST environment variable not set, skipping integration test")
	}

	port, err := strconv.Atoi(os.Getenv("SMTP_PORT"))
	if err != nil {
		t.Fatalf("Invalid SMTP_PORT: %v", err)
	}

	username := os.Getenv("SMTP_USERNAME")
	password := os.Getenv("SMTP_PASSWORD")
	from := os.Getenv("SMTP_FROM")
	to := os.Getenv("TEST_EMAIL_RECIPIENT")

	if to == "" {
		t.Fatal("TEST_EMAIL_RECIPIENT environment variable not set")
	}

	dialer := gomail.NewDialer(host, port, username, password)
	service := &SMTPEmailService{
		dialer:    dialer,
		from:      from,
		baseURL:   "http://localhost:8080",
		validator: validation.NewValidator(),
	}

	tests := []struct {
		name        string
		token       string
		before      func(string, string) error
		expectedErr bool
	}{
		{
			name:        "SendVerificationEmail",
			token:       "test-verification-token",
			before:      service.SendVerificationEmail,
			expectedErr: false,
		},
		{
			name:        "SendPasswordResetEmail",
			token:       "test-reset-token",
			before:      service.SendPasswordResetEmail,
			expectedErr: false,
		},
		{
			name:        "SendRegistrationEmail",
			token:       "test-registration-token",
			before:      service.SendRegistrationEmail,
			expectedErr: false,
		},
	}

	for _, tc := range tests {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.before(to, tc.token)
			if tc.expectedErr {
				assert.Error(t, err, "expected error but got none")
			} else {
				assert.NoError(t, err, "unexpected error")
			}
		})
	}
}

// mockDialer is a test implementation of the Dialer interface
type mockDialer struct {
	shouldError bool
}

// DialAndSend implements the Dialer interface
func (m *mockDialer) DialAndSend(messages ...*gomail.Message) error {
	if m.shouldError {
		return assert.AnError
	}
	return nil
}
