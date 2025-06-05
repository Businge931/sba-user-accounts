package http

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockAuthService is a mock implementation of the AuthService interface
type MockAuthService struct {
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

func (m *MockAuthService) VerifyEmail(token string) error {
	args := m.Called(token)
	return args.Error(0)
}

func (m *MockAuthService) RequestPasswordReset(email string) error {
	args := m.Called(email)
	return args.Error(0)
}

func (m *MockAuthService) ResetPassword(token, newPassword string) error {
	args := m.Called(token, newPassword)
	return args.Error(0)
}

func (m *MockAuthService) ChangePassword(userID, oldPassword, newPassword string) error {
	args := m.Called(userID, oldPassword, newPassword)
	return args.Error(0)
}

type testDependencies struct {
	mockAuth *MockAuthService
}

type testArgs struct {
	requestBody any
}

type testExpected struct {
	code   int
	body   string
	header string
}

func TestHandler_RegisterHandler(t *testing.T) {
	tests := []struct {
		name     string
		deps     testDependencies
		args     testArgs
		setup    func(*testDependencies)
		expected testExpected
	}{
		{
			name: "successful registration",
			deps: testDependencies{
				mockAuth: new(MockAuthService),
			},
			args: testArgs{
				requestBody: map[string]string{
					"email":      "test@example.com",
					"password":   "password123",
					"first_name": "John",
					"last_name":  "Doe",
				},
			},
			setup: func(d *testDependencies) {
				req := domain.RegisterRequest{
					Email:     "test@example.com",
					Password:  "password123",
					FirstName: "John",
					LastName:  "Doe",
				}
				d.mockAuth.On("Register", req).
					Return(&domain.User{
						ID:        "user-123",
						Email:     "test@example.com",
						FirstName: "John",
						LastName:  "Doe",
					}, nil)
			},
			expected: testExpected{
				code:   http.StatusCreated,
				body:   `"id":"user-123","email":"test@example.com","first_name":"John","last_name":"Doe","is_email_verified":false`,
				header: "application/json",
			},
		},
		{
			name: "invalid request body",
			deps: testDependencies{
				mockAuth: new(MockAuthService),
			},
			args: testArgs{
				requestBody: "invalid-json",
			},
			setup: func(d *testDependencies) {},
			expected: testExpected{
				code:   http.StatusBadRequest,
				body:   "Invalid request body\n",
				header: "text/plain; charset=utf-8",
			},
		},
		{
			name: "missing required fields",
			deps: testDependencies{
				mockAuth: new(MockAuthService),
			},
			args: testArgs{
				requestBody: map[string]string{
					"email": "test@example.com",
				},
			},
			setup: func(d *testDependencies) {},
			expected: testExpected{
				code:   http.StatusBadRequest,
				body:   "All fields are required\n",
				header: "text/plain; charset=utf-8",
			},
		},
		{
			name: "invalid email format",
			deps: testDependencies{
				mockAuth: new(MockAuthService),
			},
			args: testArgs{
				requestBody: map[string]string{
					"email":      "invalid-email",
					"password":   "password123",
					"first_name": "John",
					"last_name":  "Doe",
				},
			},
			setup: func(d *testDependencies) {
				req := domain.RegisterRequest{
					Email:     "invalid-email",
					Password:  "password123",
					FirstName: "John",
					LastName:  "Doe",
				}
				d.mockAuth.On("Register", req).Return(nil, errors.New("invalid email format"))
			},
			expected: testExpected{
				code:   http.StatusBadRequest,
				body:   "invalid email format\n",
				header: "text/plain; charset=utf-8",
			},
		},
		{
			name: "email already exists",
			deps: testDependencies{
				mockAuth: new(MockAuthService),
			},
			args: testArgs{
				requestBody: map[string]string{
					"email":      "test@example.com",
					"password":   "password123",
					"first_name": "John",
					"last_name":  "Doe",
				},
			},
			setup: func(d *testDependencies) {
				req := domain.RegisterRequest{
					Email:     "test@example.com",
					Password:  "password123",
					FirstName: "John",
					LastName:  "Doe",
				}
				d.mockAuth.On("Register", req).Return((*domain.User)(nil), errors.New("email already exists"))
			},
			expected: testExpected{
				code:   http.StatusBadRequest,
				body:   "email already exists\n",
				header: "text/plain; charset=utf-8",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock expectations
			if tt.setup != nil {
				tt.setup(&tt.deps)
			}

			// Create handler with test dependencies
			handler := NewHandler(tt.deps.mockAuth)

			// Create request
			var req *http.Request
			switch body := tt.args.requestBody.(type) {
			case string:
				req = httptest.NewRequest("POST", "/register", bytes.NewBufferString(body))
			default:
				jsonBody, _ := json.Marshal(body)
				req = httptest.NewRequest("POST", "/register", bytes.NewBuffer(jsonBody))
			}
			req.Header.Set("Content-Type", "application/json")

			// Create response recorder
			rr := httptest.NewRecorder()

			// Call handler
			handler.RegisterHandler(rr, req)


			// Assertions
			assert.Equal(t, tt.expected.code, rr.Code)
			assert.Contains(t, rr.Body.String(), tt.expected.body)
			if tt.expected.header != "" {
				assert.Equal(t, tt.expected.header, rr.Header().Get("Content-Type"))
			}

			// Verify mock expectations
			if tt.deps.mockAuth != nil {
				tt.deps.mockAuth.AssertExpectations(t)
			}
		})
	}
}

func TestHandler_LoginHandler(t *testing.T) {
	tests := []struct {
		name     string
		deps     testDependencies
		args     testArgs
		setup    func(*testDependencies)
		expected testExpected
	}{
		{
			name: "successful login",
			deps: testDependencies{
				mockAuth: new(MockAuthService),
			},
			args: testArgs{
				requestBody: map[string]string{
					"email":    "test@example.com",
					"password": "password123",
				},
			},
			setup: func(d *testDependencies) {
				req := domain.LoginRequest{
					Email:    "test@example.com",
					Password: "password123",
				}
				d.mockAuth.On("Login", req).
					Return("jwt.token.here", nil)
			},
			expected: testExpected{
				code:   http.StatusOK,
				body:   `{"token":"jwt.token.here"}`,
				header: "application/json",
			},
		},
		{
			name: "invalid request body",
			deps: testDependencies{
				mockAuth: new(MockAuthService),
			},
			args: testArgs{
				requestBody: "invalid-json",
			},
			setup: func(d *testDependencies) {},
			expected: testExpected{
				code:   http.StatusBadRequest,
				body:   "Invalid request body\n",
				header: "text/plain; charset=utf-8",
			},
		},
		{
			name: "missing email or password",
			deps: testDependencies{
				mockAuth: new(MockAuthService),
			},
			args: testArgs{
				requestBody: map[string]string{
					"email": "test@example.com",
				},
			},
			setup: func(d *testDependencies) {},
			expected: testExpected{
				code:   http.StatusBadRequest,
				body:   "Email and password are required\n",
				header: "text/plain; charset=utf-8",
			},
		},
		{
			name: "invalid credentials",
			deps: testDependencies{
				mockAuth: new(MockAuthService),
			},
			args: testArgs{
				requestBody: map[string]string{
					"email":    "test@example.com",
					"password": "wrongpassword",
				},
			},
			setup: func(d *testDependencies) {
				req := domain.LoginRequest{
					Email:    "test@example.com",
					Password: "wrongpassword",
				}
				d.mockAuth.On("Login", req).
					Return("", errors.New("invalid credentials"))
			},
			expected: testExpected{
				code:   http.StatusUnauthorized,
				body:   "invalid credentials\n",
				header: "text/plain; charset=utf-8",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock expectations
			if tt.setup != nil {
				tt.setup(&tt.deps)
			}

			// Create handler with test dependencies
			handler := NewHandler(tt.deps.mockAuth)

			// Create request
			var req *http.Request
			switch body := tt.args.requestBody.(type) {
			case string:
				req = httptest.NewRequest("POST", "/login", bytes.NewBufferString(body))
			default:
				jsonBody, _ := json.Marshal(body)
				req = httptest.NewRequest("POST", "/login", bytes.NewBuffer(jsonBody))
			}
			req.Header.Set("Content-Type", "application/json")

			// Create response recorder
			rr := httptest.NewRecorder()

			// Call handler
			handler.LoginHandler(rr, req)

			// Assertions
			assert.Equal(t, tt.expected.code, rr.Code)
			assert.Contains(t, rr.Body.String(), tt.expected.body)
			if tt.expected.header != "" {
				assert.Equal(t, tt.expected.header, rr.Header().Get("Content-Type"))
			}

			// Verify mock expectations
			if tt.deps.mockAuth != nil {
				tt.deps.mockAuth.AssertExpectations(t)
			}
		})
	}
}

func TestNewHandler(t *testing.T) {
	mockAuth := new(MockAuthService)
	handler := NewHandler(mockAuth)

	assert.NotNil(t, handler)
	assert.Equal(t, mockAuth, handler.authService)
}
