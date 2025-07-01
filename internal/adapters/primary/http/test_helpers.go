package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/stretchr/testify/mock"
)

type registerTestdeps struct {
	authService    *MockAuthService
	accountService *MockAccountService
}

type registerTestargs struct {
	requestBody any // Can be map[string]string or string for invalid JSON
}

type registerTestCase struct {
	name   string
	deps   registerTestdeps
	args   registerTestargs
	before func(*testing.T, *registerTestdeps, registerTestargs) (*httptest.ResponseRecorder, *http.Request)
	after  func(*testing.T, *registerTestdeps, *httptest.ResponseRecorder)
}

type loginTestDeps struct {
	authService *MockAuthService
}

type loginTestArgs struct {
	requestBody any
}

type loginTestCase struct {
	name   string
	deps   loginTestDeps
	args   loginTestArgs
	before func(*testing.T, *loginTestDeps, loginTestArgs) (*httptest.ResponseRecorder, *http.Request)
	after  func(*testing.T, *loginTestDeps, *httptest.ResponseRecorder)
}

type MockAuthService struct {
	mock.Mock
}

type MockAccountService struct {
	mock.Mock
}

func (m *MockAuthService) Register(req domain.RegisterRequest) (*domain.User, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockAuthService) Login(req domain.LoginRequest) (string, error) {
	args := m.Called(req)
	return args.String(0), args.Error(1)
}

func (m *MockAuthService) GetUserByEmail(email string) (*domain.User, error) {
	args := m.Called(email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockAccountService) VerifyEmail(token string) error {
	args := m.Called(token)
	return args.Error(0)
}

func (m *MockAccountService) RequestPasswordReset(email string) error {
	args := m.Called(email)
	return args.Error(0)
}

func (m *MockAccountService) ResetPassword(token, newPassword string) error {
	args := m.Called(token, newPassword)
	return args.Error(0)
}

func (m *MockAccountService) ChangePassword(userID, oldPassword, newPassword string) error {
	args := m.Called(userID, oldPassword, newPassword)
	return args.Error(0)
}
