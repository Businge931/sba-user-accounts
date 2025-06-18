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

func TestHandler_RegisterHandler(t *testing.T) {
	tests := []registerTestCase{
		{
			name: "successful registration",
			deps: registerTestdeps{
				authService: new(MockAuthService),
			},
			args: registerTestargs{
				requestBody: map[string]string{
					"email":      "test@example.com",
					"password":   "password123",
					"first_name": "John",
					"last_name":  "Doe",
				},
			},
			before: func(t *testing.T, d *registerTestdeps, args registerTestargs) (*httptest.ResponseRecorder, *http.Request) {
				req := domain.RegisterRequest{
					Email:     "test@example.com",
					Password:  "password123",
					FirstName: "John",
					LastName:  "Doe",
				}
				d.authService.On("Register", req).
					Return(&domain.User{
						ID:        "user-123",
						Email:     "test@example.com",
						FirstName: "John",
						LastName:  "Doe",
					}, nil)

				handler := NewHandler(d.authService)
				reqBody, _ := json.Marshal(args.requestBody)
				httpReq := httptest.NewRequest("POST", "/register", bytes.NewBuffer(reqBody))
				httpReq.Header.Set("Content-Type", "application/json")
				rr := httptest.NewRecorder()

				handler.RegisterHandler(rr, httpReq)
				return rr, httpReq
			},
			after: func(t *testing.T, d *registerTestdeps, rr *httptest.ResponseRecorder) {
				d.authService.AssertExpectations(t)
				assert.Equal(t, http.StatusCreated, rr.Code)
				assert.Contains(t, rr.Body.String(), `"id":"user-123","email":"test@example.com","first_name":"John","last_name":"Doe","is_email_verified":false`)
				assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
			},
		},
		{
			name: "missing required fields",
			deps: registerTestdeps{
				authService: new(MockAuthService),
			},
			args: registerTestargs{
				requestBody: map[string]string{
					"email": "test@example.com",
				},
			},
			before: func(t *testing.T, d *registerTestdeps, args registerTestargs) (*httptest.ResponseRecorder, *http.Request) {
				handler := NewHandler(d.authService)
				reqBody, _ := json.Marshal(args.requestBody)
				httpReq := httptest.NewRequest("POST", "/register", bytes.NewBuffer(reqBody))
				httpReq.Header.Set("Content-Type", "application/json")
				rr := httptest.NewRecorder()

				handler.RegisterHandler(rr, httpReq)
				return rr, httpReq
			},
			after: func(t *testing.T, d *registerTestdeps, rr *httptest.ResponseRecorder) {
				d.authService.AssertNotCalled(t, "Register", mock.Anything)
				d.authService.AssertExpectations(t)
				assert.Equal(t, http.StatusBadRequest, rr.Code)
				assert.Contains(t, rr.Body.String(), "All fields are required")
				assert.Equal(t, "text/plain; charset=utf-8", rr.Header().Get("Content-Type"))
			},
		},
		{
			name: "invalid email format",
			deps: registerTestdeps{
				authService: new(MockAuthService),
			},
			args: registerTestargs{
				requestBody: map[string]string{
					"email":      "invalid-email",
					"password":   "password123",
					"first_name": "John",
					"last_name":  "Doe",
				},
			},
			before: func(t *testing.T, d *registerTestdeps, args registerTestargs) (*httptest.ResponseRecorder, *http.Request) {
				req := domain.RegisterRequest{
					Email:     "invalid-email",
					Password:  "password123",
					FirstName: "John",
					LastName:  "Doe",
				}
				d.authService.On("Register", req).Return(nil, errors.New("invalid email format"))

				handler := NewHandler(d.authService)
				reqBody, _ := json.Marshal(args.requestBody)
				httpReq := httptest.NewRequest("POST", "/register", bytes.NewBuffer(reqBody))
				httpReq.Header.Set("Content-Type", "application/json")
				rr := httptest.NewRecorder()

				handler.RegisterHandler(rr, httpReq)
				return rr, httpReq
			},
			after: func(t *testing.T, d *registerTestdeps, rr *httptest.ResponseRecorder) {
				d.authService.AssertExpectations(t)
				assert.Equal(t, http.StatusBadRequest, rr.Code)
				assert.Contains(t, rr.Body.String(), "invalid email format")
				assert.Equal(t, "text/plain; charset=utf-8", rr.Header().Get("Content-Type"))
			},
		},
		{
			name: "email already exists",
			deps: registerTestdeps{
				authService: new(MockAuthService),
			},
			args: registerTestargs{
				requestBody: map[string]string{
					"email":      "test@example.com",
					"password":   "password123",
					"first_name": "John",
					"last_name":  "Doe",
				},
			},
			before: func(t *testing.T, d *registerTestdeps, args registerTestargs) (*httptest.ResponseRecorder, *http.Request) {
				req := domain.RegisterRequest{
					Email:     "test@example.com",
					Password:  "password123",
					FirstName: "John",
					LastName:  "Doe",
				}
				d.authService.On("Register", req).Return((*domain.User)(nil), errors.New("email already exists"))

				handler := NewHandler(d.authService)
				reqBody, _ := json.Marshal(args.requestBody)
				httpReq := httptest.NewRequest("POST", "/register", bytes.NewBuffer(reqBody))
				httpReq.Header.Set("Content-Type", "application/json")
				rr := httptest.NewRecorder()

				handler.RegisterHandler(rr, httpReq)
				return rr, httpReq
			},
			after: func(t *testing.T, d *registerTestdeps, rr *httptest.ResponseRecorder) {
				d.authService.AssertExpectations(t)
				assert.Equal(t, http.StatusBadRequest, rr.Code)
				assert.Contains(t, rr.Body.String(), "email already exists")
				assert.Equal(t, "text/plain; charset=utf-8", rr.Header().Get("Content-Type"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Execute test case
			rr, _ := tt.before(t, &tt.deps, tt.args)
			// Verify expectations
			tt.after(t, &tt.deps, rr)
		})
	}
}

func TestHandler_LoginHandler(t *testing.T) {
	tests := []loginTestCase{
		{
			name: "successful login",
			deps: loginTestDeps{
				authService: new(MockAuthService),
			},
			args: loginTestArgs{
				requestBody: map[string]string{
					"email":    "test@example.com",
					"password": "password123",
				},
			},
			before: func(t *testing.T, d *loginTestDeps, args loginTestArgs) (*httptest.ResponseRecorder, *http.Request) {
				req := domain.LoginRequest{
					Email:    "test@example.com",
					Password: "password123",
				}
				d.authService.On("Login", req).Return("jwt.token.here", nil)

				handler := NewHandler(d.authService)
				reqBody, _ := json.Marshal(args.requestBody)
				httpReq := httptest.NewRequest("POST", "/login", bytes.NewBuffer(reqBody))
				httpReq.Header.Set("Content-Type", "application/json")
				rr := httptest.NewRecorder()

				handler.LoginHandler(rr, httpReq)
				return rr, httpReq
			},
			after: func(t *testing.T, d *loginTestDeps, rr *httptest.ResponseRecorder) {
				d.authService.AssertExpectations(t)
				assert.Equal(t, http.StatusOK, rr.Code)
				assert.JSONEq(t, `{"token":"jwt.token.here"}`, rr.Body.String())
				assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
			},
		},
		{
			name: "invalid request body",
			deps: loginTestDeps{
				authService: new(MockAuthService),
			},
			args: loginTestArgs{
				requestBody: "invalid-json",
			},
			before: func(t *testing.T, d *loginTestDeps, args loginTestArgs) (*httptest.ResponseRecorder, *http.Request) {
				handler := NewHandler(d.authService)
				httpReq := httptest.NewRequest("POST", "/login", bytes.NewBufferString("invalid-json"))
				httpReq.Header.Set("Content-Type", "application/json")
				rr := httptest.NewRecorder()

				handler.LoginHandler(rr, httpReq)
				return rr, httpReq
			},
			after: func(t *testing.T, d *loginTestDeps, rr *httptest.ResponseRecorder) {
				d.authService.AssertNotCalled(t, "Login", mock.Anything)
				d.authService.AssertExpectations(t)
				assert.Equal(t, http.StatusBadRequest, rr.Code)
				assert.Contains(t, rr.Body.String(), "Invalid request body")
				assert.Equal(t, "text/plain; charset=utf-8", rr.Header().Get("Content-Type"))
			},
		},
		{
			name: "missing email or password",
			deps: loginTestDeps{
				authService: new(MockAuthService),
			},
			args: loginTestArgs{
				requestBody: map[string]string{
					"email": "test@example.com",
				},
			},
			before: func(t *testing.T, d *loginTestDeps, args loginTestArgs) (*httptest.ResponseRecorder, *http.Request) {
				handler := NewHandler(d.authService)
				reqBody, _ := json.Marshal(args.requestBody)
				httpReq := httptest.NewRequest("POST", "/login", bytes.NewBuffer(reqBody))
				httpReq.Header.Set("Content-Type", "application/json")
				rr := httptest.NewRecorder()

				handler.LoginHandler(rr, httpReq)
				return rr, httpReq
			},
			after: func(t *testing.T, d *loginTestDeps, rr *httptest.ResponseRecorder) {
				d.authService.AssertNotCalled(t, "Login", mock.Anything)
				d.authService.AssertExpectations(t)
				assert.Equal(t, http.StatusBadRequest, rr.Code)
				assert.Contains(t, rr.Body.String(), "Email and password are required")
				assert.Equal(t, "text/plain; charset=utf-8", rr.Header().Get("Content-Type"))
			},
		},
		{
			name: "invalid credentials",
			deps: loginTestDeps{
				authService: new(MockAuthService),
			},
			args: loginTestArgs{
				requestBody: map[string]string{
					"email":    "test@example.com",
					"password": "wrongpassword",
				},
			},
			before: func(t *testing.T, d *loginTestDeps, args loginTestArgs) (*httptest.ResponseRecorder, *http.Request) {
				req := domain.LoginRequest{
					Email:    "test@example.com",
					Password: "wrongpassword",
				}
				d.authService.On("Login", req).Return("", errors.New("invalid credentials"))

				handler := NewHandler(d.authService)
				reqBody, _ := json.Marshal(args.requestBody)
				httpReq := httptest.NewRequest("POST", "/login", bytes.NewBuffer(reqBody))
				httpReq.Header.Set("Content-Type", "application/json")
				rr := httptest.NewRecorder()

				handler.LoginHandler(rr, httpReq)
				return rr, httpReq
			},
			after: func(t *testing.T, d *loginTestDeps, rr *httptest.ResponseRecorder) {
				d.authService.AssertExpectations(t)
				assert.Equal(t, http.StatusUnauthorized, rr.Code)
				assert.Contains(t, rr.Body.String(), "invalid credentials")
				assert.Equal(t, "text/plain; charset=utf-8", rr.Header().Get("Content-Type"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Execute test case
			rr, _ := tt.before(t, &tt.deps, tt.args)
			// Verify expectations
			tt.after(t, &tt.deps, rr)
		})
	}
}

func TestNewHandler(t *testing.T) {
	mockAuth := new(MockAuthService)
	h := NewHandler(mockAuth)
	assert.NotNil(t, h)
	assert.Equal(t, mockAuth, h.authService)
}
