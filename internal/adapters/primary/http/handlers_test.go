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

func (m *MockAuthService) Register(email, password, firstName, lastName string) (*domain.User, error) {
	args := m.Called(email, password, firstName, lastName)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockAuthService) Login(email, password string) (string, error) {
	args := m.Called(email, password)
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

func TestHandler_RegisterHandler(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    interface{}
		setupMock      func(*MockAuthService)
		expectedCode   int
		expectedBody   string
		expectedHeader string
	}{
		{
			name: "successful registration",
			requestBody: map[string]string{
				"email":      "test@example.com",
				"password":   "password123",
				"first_name": "John",
				"last_name":  "Doe",
			},
			setupMock: func(m *MockAuthService) {
				m.On("Register", "test@example.com", "password123", "John", "Doe").
					Return(&domain.User{
						ID:        "user-123",
						Email:     "test@example.com",
						FirstName: "John",
						LastName:  "Doe",
					}, nil)
			},
			expectedCode:   http.StatusCreated,
			expectedBody:   `"id":"user-123","email":"test@example.com","first_name":"John","last_name":"Doe","is_email_verified":false`,
			expectedHeader: "application/json",
		},
		{
			name: "missing required fields",
			requestBody: map[string]string{
				"email": "test@example.com",
				// Missing password, first_name, last_name
			},
			setupMock: func(m *MockAuthService) {
				// No setup needed as the request should fail before calling the service
			},
			expectedCode:   http.StatusBadRequest,
			expectedBody:   "All fields are required\n",
			expectedHeader: "text/plain",
		},
		{
			name: "invalid email format",
			requestBody: map[string]string{
				"email":      "invalid-email",
				"password":   "password123",
				"first_name": "John",
				"last_name":  "Doe",
			},
			setupMock: func(m *MockAuthService) {
				m.On("Register", "invalid-email", "password123", "John", "Doe").
					Return(nil, errors.New("invalid email format"))
			},
			expectedCode:   http.StatusBadRequest,
			expectedBody:   "invalid email format\n",
			expectedHeader: "text/plain",
		},
		{
			name: "auth service error",
			requestBody: map[string]string{
				"email":      "test@example.com",
				"password":   "password123",
				"first_name": "John",
				"last_name":  "Doe",
			},
			setupMock: func(m *MockAuthService) {
				m.On("Register", "test@example.com", "password123", "John", "Doe").
					Return((*domain.User)(nil), errors.New("email already exists"))
			},
			expectedCode:   http.StatusBadRequest,
			expectedBody:   "email already exists\n",
			expectedHeader: "text/plain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockAuth := new(MockAuthService)
			handler := NewHandler(mockAuth)

			// Setup mock expectations
			tt.setupMock(mockAuth)

			// Create request
			jsonBody, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest("POST", "/register", bytes.NewBuffer(jsonBody))
			req.Header.Set("Content-Type", "application/json")

			// Create response recorder
			rr := httptest.NewRecorder()

			// Call handler
			handler.RegisterHandler(rr, req)

			// Assertions
			assert.Equal(t, tt.expectedCode, rr.Code)
			assert.Contains(t, rr.Body.String(), tt.expectedBody)
			assert.Contains(t, rr.Header().Get("Content-Type"), tt.expectedHeader)

			// Verify mock expectations
			mockAuth.AssertExpectations(t)
		})
	}
}

func TestHandler_LoginHandler(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    interface{}
		setupMock      func(*MockAuthService)
		expectedCode   int
		expectedBody   string
		expectedHeader string
	}{
		{
			name: "successful login",
			requestBody: map[string]string{
				"email":    "test@example.com",
				"password": "password123",
			},
			setupMock: func(m *MockAuthService) {
				m.On("Login", "test@example.com", "password123").
					Return("jwt.token.here", nil)
			},
			expectedCode:   http.StatusOK,
			expectedBody:   `{"token":"jwt.token.here"}`,
			expectedHeader: "application/json",
		},
		{
			name:           "invalid request body",
			requestBody:    "invalid-json",
			setupMock:      func(m *MockAuthService) {},
			expectedCode:   http.StatusBadRequest,
			expectedBody:   "Invalid request body\n",
			expectedHeader: "text/plain; charset=utf-8",
		},
		{
			name: "missing email or password",
			requestBody: map[string]string{
				"email": "test@example.com",
				// Missing password
			},
			setupMock:      func(m *MockAuthService) {},
			expectedCode:   http.StatusBadRequest,
			expectedBody:   "Email and password are required\n",
			expectedHeader: "text/plain; charset=utf-8",
		},
		{
			name: "invalid credentials",
			requestBody: map[string]string{
				"email":    "test@example.com",
				"password": "wrongpassword",
			},
			setupMock: func(m *MockAuthService) {
				m.On("Login", "test@example.com", "wrongpassword").
					Return("", errors.New("invalid credentials"))
			},
			expectedCode:   http.StatusUnauthorized,
			expectedBody:   "invalid credentials\n",
			expectedHeader: "text/plain; charset=utf-8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockAuth := new(MockAuthService)
			handler := NewHandler(mockAuth)

			// Setup mock expectations
			tt.setupMock(mockAuth)

			// Create request
			var req *http.Request
			switch body := tt.requestBody.(type) {
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
			assert.Equal(t, tt.expectedCode, rr.Code)
			assert.Contains(t, rr.Body.String(), tt.expectedBody)
			if tt.expectedHeader != "" {
				assert.Equal(t, tt.expectedHeader, rr.Header().Get("Content-Type"))
			}

			// Verify mock expectations
			mockAuth.AssertExpectations(t)
		})
	}
}

func TestNewHandler(t *testing.T) {
	mockAuth := new(MockAuthService)
	handler := NewHandler(mockAuth)

	assert.NotNil(t, handler)
	assert.Equal(t, mockAuth, handler.authService)
}
