package http

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/Businge931/sba-user-accounts/internal/core/errors"
	"github.com/Businge931/sba-user-accounts/internal/core/ports"
	"github.com/Businge931/sba-user-accounts/internal/core/services/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// mockAccountManagementService is a test double for the AccountManagementService interface
type mockAccountManagementService struct {
	mock.Mock
}

func (m *mockAccountManagementService) VerifyEmail(token string) error {
	args := m.Called(token)
	return args.Error(0)
}

func (m *mockAccountManagementService) RequestPasswordReset(email string) error {
	args := m.Called(email)
	return args.Error(0)
}

func (m *mockAccountManagementService) ResetPassword(token, newPassword string) error {
	args := m.Called(token, newPassword)
	return args.Error(0)
}

func (m *mockAccountManagementService) ChangePassword(userID, oldPassword, newPassword string) error {
	args := m.Called(userID, oldPassword, newPassword)
	return args.Error(0)
}

// Ensure mock implements the interface
var _ ports.AccountManagementService = (*mockAccountManagementService)(nil)

type testArgs struct {
	method      string
	path        string
	header      map[string]string
	queryParams map[string]string
	body        any
}

type testCase struct {
	name   string
	args   testArgs
	before func(t *testing.T, args testArgs, authSvc *mocks.MockAuthService, accountSvc *mockAccountManagementService) (*httptest.ResponseRecorder, *http.Request)
	after  func(t *testing.T, rr *httptest.ResponseRecorder)
}

func TestHandlers(t *testing.T) {
	tests := []testCase{
		// RegisterHandler tests
		{
			name: "register handler - successful registration",
			args: testArgs{
				method: http.MethodPost,
				path:   "/register",
				header: map[string]string{
					"Content-Type": "application/json",
				},
				body: map[string]string{
					"email":     "test@example.com",
					"password":  "password123",
					"firstName": "John",
					"lastName":  "Doe",
				},
			},
			before: func(t *testing.T, args testArgs, authSvc *mocks.MockAuthService, accountSvc *mockAccountManagementService) (*httptest.ResponseRecorder, *http.Request) {
				authSvc.On("Register", mock.MatchedBy(func(req domain.RegisterRequest) bool {
					return req.Email == "test@example.com" &&
						req.Password == "password123" &&
						req.FirstName == "" &&
						req.LastName == ""
				})).Return(&domain.User{
					Email:     "test@example.com",
					FirstName: "",
					LastName:  "",
				}, nil)

				reqBody, _ := json.Marshal(args.body)
				httpReq, _ := http.NewRequest(args.method, args.path, bytes.NewReader(reqBody))
				for k, v := range args.header {
					httpReq.Header.Set(k, v)
				}

				return httptest.NewRecorder(), httpReq
			},
			after: func(t *testing.T, rr *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusCreated, rr.Code)
			},
		},

		// LoginHandler tests
		{
			name: "login handler - successful login",
			args: testArgs{
				method: http.MethodPost,
				path:   "/login",
				header: map[string]string{
					"Content-Type": "application/json",
				},
				body: map[string]string{
					"email":    "test@example.com",
					"password": "password123",
				},
			},
			before: func(t *testing.T, args testArgs, authSvc *mocks.MockAuthService, accountSvc *mockAccountManagementService) (*httptest.ResponseRecorder, *http.Request) {
				authSvc.On("Login", domain.LoginRequest{
					Email:    "test@example.com",
					Password: "password123",
				}).Return("test-token", nil)

				reqBody, _ := json.Marshal(args.body)
				httpReq, _ := http.NewRequest(args.method, args.path, bytes.NewReader(reqBody))
				for k, v := range args.header {
					httpReq.Header.Set(k, v)
				}

				return httptest.NewRecorder(), httpReq
			},
			after: func(t *testing.T, rr *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusOK, rr.Code)
				var resp map[string]string
				err := json.Unmarshal(rr.Body.Bytes(), &resp)
				assert.NoError(t, err)
				assert.Equal(t, "test-token", resp["token"])
			},
		},

		// LoginHandler error cases
		{
			name: "login handler - invalid credentials",
			args: testArgs{
				method: http.MethodPost,
				path:   "/login",
				header: map[string]string{
					"Content-Type": "application/json",
				},
				body: map[string]string{
					"email":    "test@example.com",
					"password": "wrongpassword",
				},
			},
			before: func(t *testing.T, args testArgs, authSvc *mocks.MockAuthService, accountSvc *mockAccountManagementService) (*httptest.ResponseRecorder, *http.Request) {
				authSvc.On("Login", domain.LoginRequest{
					Email:    "test@example.com",
					Password: "wrongpassword",
				}).Return("", errors.ErrInvalidAuth)

				reqBody, _ := json.Marshal(args.body)
				httpReq, _ := http.NewRequest(args.method, args.path, bytes.NewReader(reqBody))
				for k, v := range args.header {
					httpReq.Header.Set(k, v)
				}

				return httptest.NewRecorder(), httpReq
			},
			after: func(t *testing.T, rr *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusUnauthorized, rr.Code)
				// Expecting plain text error response
				assert.Contains(t, rr.Body.String(), "invalid authentication")
				assert.Equal(t, "text/plain; charset=utf-8", rr.Header().Get("Content-Type"))
			},
		},

		{
			name: "login handler - missing credentials",
			args: testArgs{
				method: http.MethodPost,
				path:   "/login",
				header: map[string]string{
					"Content-Type": "application/json",
				},
				body: map[string]string{
					// Missing email and password
				},
			},
			before: func(t *testing.T, args testArgs, authSvc *mocks.MockAuthService, accountSvc *mockAccountManagementService) (*httptest.ResponseRecorder, *http.Request) {
				authSvc.On("Login", domain.LoginRequest{}).Return("", errors.ErrInvalidInput)

				reqBody, _ := json.Marshal(args.body)
				httpReq, _ := http.NewRequest(args.method, args.path, bytes.NewReader(reqBody))
				for k, v := range args.header {
					httpReq.Header.Set(k, v)
				}
				return httptest.NewRecorder(), httpReq
			},
			after: func(t *testing.T, rr *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusBadRequest, rr.Code)
				// Expecting plain text error response
				assert.Contains(t, rr.Body.String(), "invalid input")
				assert.Equal(t, "text/plain; charset=utf-8", rr.Header().Get("Content-Type"))
			},
		},

		// TODO:  Will add more test cases for other handlers...
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			mockAuthSvc := new(mocks.MockAuthService)
			mockAccountSvc := new(mockAccountManagementService)

			// Create handler with mocks
			h := &Handler{
				authService:    mockAuthSvc,
				accountService: mockAccountSvc,
			}

			// Call before function to set up test and get request/response
			rr, req := tt.before(t, tt.args, mockAuthSvc, mockAccountSvc)

			// Create a new request context and serve the request
			var handler http.HandlerFunc
			switch tt.name {
			case "register handler - successful registration":
				handler = h.RegisterHandler
			case "login handler - successful login":
				handler = h.LoginHandler
			case "login handler - invalid credentials":
				handler = h.LoginHandler
			case "login handler - missing credentials":
				handler = h.LoginHandler
			default:
				t.Fatalf("No handler defined for test case: %s", tt.name)
			}
			handler.ServeHTTP(rr, req)

			// Verify expectations
			tt.after(t, rr)

			// Assert all expectations were met
			mockAuthSvc.AssertExpectations(t)
			mockAccountSvc.AssertExpectations(t)
		})
	}
}
