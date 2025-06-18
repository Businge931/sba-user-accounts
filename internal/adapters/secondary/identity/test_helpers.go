package identity

import (
	"testing"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/Businge931/sba-user-accounts/internal/core/services/mocks"
)

// REGISTER HELPERS
type registerTestDependencies struct {
	svc      *identityProvider
	authRepo *mocks.MockAuthRepository
	userRepo *mocks.MockUserRepository
	tokenSvc *mocks.MockTokenService
	logger   *mocks.MockLogger
}

func setupRegisterMocks(*testing.T) (*identityProvider, *registerTestDependencies) {
	authRepo := new(mocks.MockAuthRepository)
	userRepo := new(mocks.MockUserRepository)
	tokenSvc := new(mocks.MockTokenService)
	logger := new(mocks.MockLogger)

	svc := NewIdentityProvider(authRepo, userRepo, tokenSvc, logger).(*identityProvider)

	return svc, &registerTestDependencies{
		svc:      svc,
		authRepo: authRepo,
		userRepo: userRepo,
		tokenSvc: tokenSvc,
		logger:   logger,
	}
}

type registerTestCase struct {
	name         string
	dependencies struct {
		authRepoMocks func(*mocks.MockAuthRepository)
		userRepoMocks func(*mocks.MockUserRepository)
		tokenSvcMocks func(*mocks.MockTokenService)
		loggerMocks   func(*mocks.MockLogger)
	}
	args struct {
		req domain.RegisterRequest
	}
	before  func(*testing.T, *registerTestDependencies)
	after   func(*testing.T, *registerTestDependencies)
	want    *domain.User
	wantErr bool
	err     error
}

// LOGIN HELPERS

type loginTestDependencies struct {
	svc      *identityProvider
	tokenSvc *mocks.MockTokenService
	logger   *mocks.MockLogger
}

type loginTestCase struct {
	name       string
	setupMocks func(*loginTestDependencies)
	args       struct {
		req  domain.LoginRequest
		user *domain.User
	}
	after    func(*testing.T, *loginTestDependencies)
	want     string
	wantErr  bool
	errorMsg string
}

// CHANGE PASSWORD HELPERS

type changePasswordDependencies struct {
	svc      *identityProvider
	userRepo *mocks.MockUserRepository
	logger   *mocks.MockLogger
}

type changePasswordArgs struct {
	userID      string
	oldPassword string
	newPassword string
}

type changePasswordExpectations struct {
	hashedPassword string
	err            error
}

func setupChangePasswordTest(*testing.T) (*identityProvider, *changePasswordDependencies) {
	userRepo := new(mocks.MockUserRepository)
	logger := new(mocks.MockLogger)

	svc := &identityProvider{
		userRepo: userRepo,
		logger:   logger,
	}

	return svc, &changePasswordDependencies{
		svc:      svc,
		userRepo: userRepo,
		logger:   logger,
	}
}

type changePasswordTestCase struct {
	name   string
	args   changePasswordArgs
	expect changePasswordExpectations
	before func(*testing.T, *changePasswordDependencies, changePasswordArgs)
	after  func(*testing.T, *changePasswordDependencies)
}

// REQUEST PASSWORD RESET HELPERS

type requestPasswordResetDependencies struct {
	svc      *identityProvider
	userRepo *mocks.MockUserRepository
	authRepo *mocks.MockAuthRepository
	tokenSvc *mocks.MockTokenService
	logger   *mocks.MockLogger
}

type requestPasswordResetArgs struct {
	email string
}

type requestPasswordResetExpectations struct {
	result string
	err    error
}

// setupRequestPasswordResetTest initializes common test dependencies
func setupRequestPasswordResetTest(*testing.T) (*identityProvider, *requestPasswordResetDependencies) {
	userRepo := new(mocks.MockUserRepository)
	authRepo := new(mocks.MockAuthRepository)
	tokenSvc := new(mocks.MockTokenService)
	logger := new(mocks.MockLogger)

	svc := &identityProvider{
		userRepo: userRepo,
		authRepo: authRepo,
		tokenSvc: tokenSvc,
		logger:   logger,
	}

	return svc, &requestPasswordResetDependencies{
		svc:      svc,
		userRepo: userRepo,
		authRepo: authRepo,
		tokenSvc: tokenSvc,
		logger:   logger,
	}
}

type requestPasswordResetTestCase struct {
	name   string
	args   requestPasswordResetArgs
	expect requestPasswordResetExpectations
	before func(*testing.T, *requestPasswordResetDependencies, requestPasswordResetArgs)
	after  func(*testing.T, *requestPasswordResetDependencies)
}

// RESET PASSWORD HELPERS

type resetPasswordDependencies struct {
	svc      *identityProvider
	authRepo *mocks.MockAuthRepository
	logger   *mocks.MockLogger
}

type resetPasswordArgs struct {
	token       string
	newPassword string
}

type resetPasswordExpectations struct {
	hashedPassword string
	userID         string
	err            error
}

func setupResetPasswordTest(*testing.T) (*identityProvider, *resetPasswordDependencies) {
	authRepo := new(mocks.MockAuthRepository)
	logger := new(mocks.MockLogger)

	svc := &identityProvider{
		authRepo: authRepo,
		logger:   logger,
	}

	return svc, &resetPasswordDependencies{
		svc:      svc,
		authRepo: authRepo,
		logger:   logger,
	}
}

type resetPasswordTestCase struct {
	name   string
	args   resetPasswordArgs
	expect resetPasswordExpectations
	before func(*testing.T, *resetPasswordDependencies, resetPasswordArgs)
	after  func(*testing.T, *resetPasswordDependencies)
}

// VERIFY EMAIL HELPERS

type verifyEmailTestDependencies struct {
	svc      *identityProvider
	authRepo *mocks.MockAuthRepository
	logger   *mocks.MockLogger
}

type verifyEmailTestArgs struct {
	token string
}

type verifyEmailTestExpectations struct {
	result  string
	err     error
	wantErr bool
}

func setupVerifyEmailTest(*testing.T) (*identityProvider, *verifyEmailTestDependencies) {
	authRepo := new(mocks.MockAuthRepository)
	logger := new(mocks.MockLogger)

	svc := &identityProvider{
		authRepo: authRepo,
		logger:   logger,
	}

	return svc, &verifyEmailTestDependencies{
		svc:      svc,
		authRepo: authRepo,
		logger:   logger,
	}
}

type verifyEmailTestCase struct {
	name   string
	args   verifyEmailTestArgs
	expect verifyEmailTestExpectations
	before func(*testing.T, *verifyEmailTestDependencies, verifyEmailTestArgs)
	after  func(*testing.T, *verifyEmailTestDependencies)
}
