package grpc_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Businge931/sba-user-accounts/internal/adapters/primary/grpc"
	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/Businge931/sba-user-accounts/internal/core/services/mocks"
	"github.com/Businge931/sba-user-accounts/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestDependencies holds the mock dependencies for the test cases
type TestDependencies struct {
	authService  *mocks.MockAuthService
	tokenService *mocks.MockTokenService
	logger       *mocks.MockLogger
}

// TestArgs holds the input arguments for the test cases
type TestArgs struct {
	ctx     context.Context
	request any
}

// TestExpectations holds the expected results for the test cases
type TestExpectations struct {
	response any
	error    bool
	errorMsg string
	code     codes.Code
}

func TestAuthServer_Register(t *testing.T) {
	testCases := []struct {
		name     string
		deps     TestDependencies
		args     TestArgs
		before   func(deps TestDependencies)
		expected TestExpectations
	}{
		{
			name: "Register_Success",
			deps: TestDependencies{
				authService:  new(mocks.MockAuthService),
				tokenService: new(mocks.MockTokenService),
				logger:       new(mocks.MockLogger),
			},
			args: TestArgs{
				ctx: context.Background(),
				request: &proto.RegisterRequest{
					Username: "test@example.com",
					Password: "Password123!",
				},
			},
			before: func(deps TestDependencies) {
				deps.authService.On("Register", 
					"test@example.com", 
					"Password123!", 
					"test@example.com", 
					"").Return(&domain.User{
						ID:              "user1",
						Email:           "test@example.com",
						FirstName:       "test@example.com",
						LastName:        "",
						IsEmailVerified: false,
					}, nil)
			},
			expected: TestExpectations{
				response: &proto.RegisterResponse{
					Success: true,
					Message: "User registered successfully",
				},
				error: false,
			},
		},
		{
			name: "Register_MissingFields",
			deps: TestDependencies{
				authService:  new(mocks.MockAuthService),
				tokenService: new(mocks.MockTokenService),
				logger:       new(mocks.MockLogger),
			},
			args: TestArgs{
				ctx: context.Background(),
				request: &proto.RegisterRequest{
					Username: "",
					Password: "",
				},
			},
			before: func(deps TestDependencies) {
				// No expectations needed as validation happens before service call
			},
			expected: TestExpectations{
				error:    true,
				errorMsg: "missing required fields",
				code:     codes.InvalidArgument,
			},
		},
		{
			name: "Register_ServiceError",
			deps: TestDependencies{
				authService:  new(mocks.MockAuthService),
				tokenService: new(mocks.MockTokenService),
				logger:       new(mocks.MockLogger),
			},
			args: TestArgs{
				ctx: context.Background(),
				request: &proto.RegisterRequest{
					Username: "existing@example.com",
					Password: "Password123!",
				},
			},
			before: func(deps TestDependencies) {
				deps.authService.On("Register", 
					"existing@example.com", 
					"Password123!", 
					"existing@example.com", 
					"").Return(nil, errors.New("user already exists"))
			},
			expected: TestExpectations{
				error:    true,
				errorMsg: "user already exists",
				code:     codes.Internal,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			server := &grpc.AuthServer{
				AuthService:  tc.deps.authService,
				TokenService: tc.deps.tokenService,
				Logger:       tc.deps.logger,
			}
			
			// Set up expectations
			if tc.before != nil {
				tc.before(tc.deps)
			}
			
			// Execute
			resp, err := server.Register(tc.args.ctx, tc.args.request.(*proto.RegisterRequest))
			
			// Verify
			if tc.expected.error {
				assert.Error(t, err)
				st, ok := status.FromError(err)
				assert.True(t, ok)
				assert.Equal(t, tc.expected.code, st.Code())
				assert.Contains(t, st.Message(), tc.expected.errorMsg)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected.response, resp)
			}
			
			// Verify all expectations were met
			mock.AssertExpectationsForObjects(t, 
				tc.deps.authService, 
				tc.deps.tokenService, 
				tc.deps.logger)
		})
	}
}

func TestAuthServer_Login(t *testing.T) {
	testCases := []struct {
		name     string
		deps     TestDependencies
		args     TestArgs
		before   func(deps TestDependencies)
		expected TestExpectations
	}{
		{
			name: "Login_Success",
			deps: TestDependencies{
				authService:  new(mocks.MockAuthService),
				tokenService: new(mocks.MockTokenService),
				logger:       new(mocks.MockLogger),
			},
			args: TestArgs{
				ctx: context.Background(),
				request: &proto.LoginRequest{
					Username: "test@example.com",
					Password: "Password123!",
				},
			},
			before: func(deps TestDependencies) {
				deps.authService.On("Login", 
					"test@example.com", 
					"Password123!").Return("jwt-token", nil)
				deps.logger.On("Infof", mock.Anything, mock.Anything, mock.Anything).Maybe()
			},
			expected: TestExpectations{
				response: &proto.LoginResponse{
					Success: true,
					Token:   "jwt-token",
					Message: "Login successful",
				},
				error: false,
			},
		},
		{
			name: "Login_MissingFields",
			deps: TestDependencies{
				authService:  new(mocks.MockAuthService),
				tokenService: new(mocks.MockTokenService),
				logger:       new(mocks.MockLogger),
			},
			args: TestArgs{
				ctx: context.Background(),
				request: &proto.LoginRequest{
					Username: "",
					Password: "",
				},
			},
			before: func(deps TestDependencies) {
				// No expectations needed as validation happens before service call
			},
			expected: TestExpectations{
				error:    true,
				errorMsg: "Missing username or password",
				code:     codes.InvalidArgument,
			},
		},
		{
			name: "Login_UserNotFound",
			deps: TestDependencies{
				authService:  new(mocks.MockAuthService),
				tokenService: new(mocks.MockTokenService),
				logger:       new(mocks.MockLogger),
			},
			args: TestArgs{
				ctx: context.Background(),
				request: &proto.LoginRequest{
					Username: "nonexistent@example.com",
					Password: "Password123!",
				},
			},
			before: func(deps TestDependencies) {
				deps.authService.On("Login", 
					"nonexistent@example.com", 
					"Password123!").Return("", errors.New("USER_NOT_FOUND"))
				deps.logger.On("Infof", mock.Anything, mock.Anything, mock.Anything).Once()
			},
			expected: TestExpectations{
				error:    true,
				errorMsg: "Account not found",
				code:     codes.NotFound,
			},
		},
		{
			name: "Login_InvalidPassword",
			deps: TestDependencies{
				authService:  new(mocks.MockAuthService),
				tokenService: new(mocks.MockTokenService),
				logger:       new(mocks.MockLogger),
			},
			args: TestArgs{
				ctx: context.Background(),
				request: &proto.LoginRequest{
					Username: "test@example.com",
					Password: "WrongPassword!",
				},
			},
			before: func(deps TestDependencies) {
				deps.authService.On("Login", 
					"test@example.com", 
					"WrongPassword!").Return("", errors.New("INVALID_PASSWORD"))
				deps.logger.On("Infof", mock.Anything, mock.Anything, mock.Anything).Once()
			},
			expected: TestExpectations{
				error:    true,
				errorMsg: "Incorrect password",
				code:     codes.Unauthenticated,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			server := &grpc.AuthServer{
				AuthService:  tc.deps.authService,
				TokenService: tc.deps.tokenService,
				Logger:       tc.deps.logger,
			}
			
			// Set up expectations
			if tc.before != nil {
				tc.before(tc.deps)
			}
			
			// Execute
			resp, err := server.Login(tc.args.ctx, tc.args.request.(*proto.LoginRequest))
			
			// Verify
			if tc.expected.error {
				assert.Error(t, err)
				st, ok := status.FromError(err)
				assert.True(t, ok)
				assert.Equal(t, tc.expected.code, st.Code())
				assert.Contains(t, st.Message(), tc.expected.errorMsg)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected.response, resp)
			}
			
			// Verify all expectations were met
			mock.AssertExpectationsForObjects(t, 
				tc.deps.authService, 
				tc.deps.tokenService, 
				tc.deps.logger)
		})
	}
}

func TestAuthServer_VerifyToken(t *testing.T) {
	testCases := []struct {
		name     string
		deps     TestDependencies
		args     TestArgs
		before   func(deps TestDependencies)
		expected TestExpectations
	}{
		{
			name: "VerifyToken_Success",
			deps: TestDependencies{
				authService:  new(mocks.MockAuthService),
				tokenService: new(mocks.MockTokenService),
				logger:       new(mocks.MockLogger),
			},
			args: TestArgs{
				ctx: context.Background(),
				request: &proto.VerifyTokenRequest{
					Token: "valid-token",
				},
			},
			before: func(deps TestDependencies) {
				deps.tokenService.On("ValidateToken", "valid-token").Return("user123", nil)
			},
			expected: TestExpectations{
				response: &proto.VerifyTokenResponse{
					Success: true,
					Message: "Token is valid",
				},
				error: false,
			},
		},
		{
			name: "VerifyToken_MissingToken",
			deps: TestDependencies{
				authService:  new(mocks.MockAuthService),
				tokenService: new(mocks.MockTokenService),
				logger:       new(mocks.MockLogger),
			},
			args: TestArgs{
				ctx: context.Background(),
				request: &proto.VerifyTokenRequest{
					Token: "",
				},
			},
			before: func(deps TestDependencies) {
				// No expectations needed as validation happens before service call
			},
			expected: TestExpectations{
				error:    true,
				errorMsg: "token is required",
				code:     codes.InvalidArgument,
			},
		},
		{
			name: "VerifyToken_InvalidToken",
			deps: TestDependencies{
				authService:  new(mocks.MockAuthService),
				tokenService: new(mocks.MockTokenService),
				logger:       new(mocks.MockLogger),
			},
			args: TestArgs{
				ctx: context.Background(),
				request: &proto.VerifyTokenRequest{
					Token: "invalid-token",
				},
			},
			before: func(deps TestDependencies) {
				deps.tokenService.On("ValidateToken", "invalid-token").Return("", errors.New("invalid token"))
				deps.logger.On("Warnf", mock.Anything, mock.Anything).Once()
			},
			expected: TestExpectations{
				error:    true,
				errorMsg: "Invalid or expired token",
				code:     codes.Unauthenticated,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			server := &grpc.AuthServer{
				AuthService:  tc.deps.authService,
				TokenService: tc.deps.tokenService,
				Logger:       tc.deps.logger,
			}
			
			// Set up expectations
			if tc.before != nil {
				tc.before(tc.deps)
			}
			
			// Execute
			resp, err := server.VerifyToken(tc.args.ctx, tc.args.request.(*proto.VerifyTokenRequest))
			
			// Verify
			if tc.expected.error {
				assert.Error(t, err)
				st, ok := status.FromError(err)
				assert.True(t, ok)
				assert.Equal(t, tc.expected.code, st.Code())
				assert.Contains(t, st.Message(), tc.expected.errorMsg)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected.response, resp)
			}
			
			// Verify all expectations were met
			mock.AssertExpectationsForObjects(t, 
				tc.deps.authService, 
				tc.deps.tokenService, 
				tc.deps.logger)
		})
	}
}