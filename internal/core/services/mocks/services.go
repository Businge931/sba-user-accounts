package mocks

import (
	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/stretchr/testify/mock"
)

// MockTokenService mocks the TokenService interface for testing
type MockTokenService struct {
	mock.Mock
}

// GenerateToken mocks the GenerateToken method
func (m *MockTokenService) GenerateToken(userID string) (string, error) {
	args := m.Called(userID)
	return args.String(0), args.Error(1)
}

// ValidateToken mocks the ValidateToken method
func (m *MockTokenService) ValidateToken(tokenString string) (string, error) {
	args := m.Called(tokenString)
	return args.String(0), args.Error(1)
}

// GenerateVerificationToken mocks the GenerateVerificationToken method
func (m *MockTokenService) GenerateVerificationToken() string {
	args := m.Called()
	return args.String(0)
}

// GenerateResetToken mocks the GenerateResetToken method
func (m *MockTokenService) GenerateResetToken() string {
	args := m.Called()
	return args.String(0)
}

// MockEmailService mocks the EmailService interface for testing
type MockEmailService struct {
	mock.Mock
}

// SendVerificationEmail mocks the SendVerificationEmail method
func (m *MockEmailService) SendVerificationEmail(to, token string) error {
	args := m.Called(to, token)
	return args.Error(0)
}

// SendPasswordResetEmail mocks the SendPasswordResetEmail method
func (m *MockEmailService) SendPasswordResetEmail(to, token string) error {
	args := m.Called(to, token)
	return args.Error(0)
}

// SendRegistrationEmail mocks the SendRegistrationEmail method
func (m *MockEmailService) SendRegistrationEmail(to, token string) error {
	args := m.Called(to, token)
	return args.Error(0)
}

// MockAuthService mocks the AuthService interface for testing
type MockAuthService struct {
	mock.Mock
}

// Register mocks the Register method
func (m *MockAuthService) Register(req domain.RegisterRequest) (*domain.User, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

// RegisterSvc is an alias for Register for backward compatibility
func (m *MockAuthService) RegisterSvc(req domain.RegisterRequest) (*domain.User, error) {
	return m.Register(req)
}

// Login mocks the Login method
func (m *MockAuthService) Login(req domain.LoginRequest) (string, error) {
	args := m.Called(req)
	return args.String(0), args.Error(1)
}

// LoginSvc is an alias for Login for backward compatibility
func (m *MockAuthService) LoginSvc(req domain.LoginRequest) (string, error) {
	return m.Login(req)
}

// // MockAccountManagementService mocks the AccountManagementService interface for testing
// type MockAccountManagementService struct {
// 	mock.Mock
// }

// // VerifyEmail mocks the VerifyEmail method
// func (m *MockAccountManagementService) VerifyEmail(token string) error {
// 	args := m.Called(token)
// 	return args.Error(0)
// }

// // RequestPasswordReset mocks the RequestPasswordReset method
// func (m *MockAccountManagementService) RequestPasswordReset(email string) error {
// 	args := m.Called(email)
// 	return args.Error(0)
// }

// // ResetPassword mocks the ResetPassword method
// func (m *MockAccountManagementService) ResetPassword(token, newPassword string) error {
// 	args := m.Called(token, newPassword)
// 	return args.Error(0)
// }

// // ChangePassword mocks the ChangePassword method
// func (m *MockAccountManagementService) ChangePassword(userID, oldPassword, newPassword string) error {
// 	args := m.Called(userID, oldPassword, newPassword)
// 	return args.Error(0)
// }

// MockIdentityService mocks the IdentityService interface for testing
type MockIdentityService struct {
	mock.Mock
}

// Register mocks the Register method
func (m *MockIdentityService) RegisterSvc(req domain.RegisterRequest) (*domain.User, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

// Login mocks the Login method
func (m *MockIdentityService) LoginSvc(req domain.LoginRequest, user *domain.User) (string, error) {
	args := m.Called(req, user)
	return args.String(0), args.Error(1)
}

// VerifyEmail mocks the VerifyEmail method
func (m *MockIdentityService) VerifyEmailSvc(token string) (string, error) {
	args := m.Called(token)
	return args.String(0), args.Error(1)
}

// RequestPasswordReset mocks the RequestPasswordReset method
func (m *MockIdentityService) RequestPasswordResetSvc(email string) (string, error) {
	args := m.Called(email)
	return args.String(0), args.Error(1)
}

// ResetPassword mocks the ResetPassword method
func (m *MockIdentityService) ResetPasswordSvc(token, newPassword string) (string, string, error) {
	args := m.Called(token, newPassword)
	return args.String(0), args.String(1), args.Error(2)
}

// ChangePassword mocks the ChangePassword method
func (m *MockIdentityService) ChangePasswordSvc(userID, oldPassword, newPassword string) (string, error) {
	args := m.Called(userID, oldPassword, newPassword)
	return args.String(0), args.Error(1)
}
