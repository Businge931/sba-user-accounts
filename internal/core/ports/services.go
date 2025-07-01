package ports

import "github.com/Businge931/sba-user-accounts/internal/core/domain"

type (
	AuthService interface {
		Register(req domain.RegisterRequest) (*domain.User, error)
		Login(req domain.LoginRequest) (string, error) // returns JWT token

	}
	AccountManagementService interface {
		VerifyEmail(token string) error
		RequestPasswordReset(email string) error
		ResetPassword(token, newPassword string) error
		ChangePassword(userID, oldPassword, newPassword string) error
	}
	EmailService interface {
		SendVerificationEmail(to, token string) error
		SendPasswordResetEmail(to, token string) error
		SendRegistrationEmail(to, token string) error
	}

	TokenService interface {
		GenerateToken(userID string) (string, error)
		ValidateToken(token string) (string, error)
		GenerateVerificationToken() string
		GenerateResetToken() string
	}
	ValidationService interface {
		ValidateRegisterRequest(req domain.RegisterRequest) error
		ValidateLoginRequest(req domain.LoginRequest) error
		ValidateEmail(email string) error
		ValidatePassword(password string) error
		ValidateName(name, fieldName string) error
	}
	IdentityService interface {
		RegisterSvc(req domain.RegisterRequest) (*domain.User, string, error)
		LoginSvc(req domain.LoginRequest, user *domain.User) (string, error)
		ResetPasswordSvc(token string, newPassword string) (string, string, error)
		ChangePasswordSvc(userID string, oldPassword, newPassword string) (string, error)
		VerifyEmailSvc(token string) (string, error)
		RequestPasswordResetSvc(email string) (string, error)
	}
)
