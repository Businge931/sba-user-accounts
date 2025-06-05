package grpc_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Businge931/sba-user-accounts/internal/adapters/primary/grpc"
	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	dcerrors "github.com/Businge931/sba-user-accounts/internal/core/errors"
	"github.com/Businge931/sba-user-accounts/internal/core/services/mocks"
	pb "github.com/Businge931/sba-user-accounts/proto"
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
				request: &pb.RegisterRequest{
					Email:     "test@example.com",
					Password:  "Password123!",
					FirstName: "Test",
					LastName:  "User",
				},
			},
			before: func(deps TestDependencies) {
				deps.authService.On("Register", mock.MatchedBy(func(req domain.RegisterRequest) bool {
					return req.Email == "test@example.com" &&
						req.Password == "Password123!" &&
						req.FirstName == "Test" &&
						req.LastName == "User"
				})).Return(&domain.User{
					ID:              "user1",
					Email:           "test@example.com",
					FirstName:       "Test",
					LastName:        "User",
					IsEmailVerified: false,
				}, nil)
			},
			expected: TestExpectations{
				response: &pb.RegisterResponse{
					Success: true,
					Message: "User registered successfully. Please check your email to verify your account.",
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
				request: &pb.RegisterRequest{
					Email:     "",
					Password:  "",
					FirstName: "",
					LastName:  "",
				},
			},
			before: func(deps TestDependencies) {
				// No expectations needed as validation happens before service call
			},
			expected: TestExpectations{
				error:    true,
				errorMsg: "missing required fields: email, password, first_name, and last_name are required",
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
				request: &pb.RegisterRequest{
					Email:     "existing@example.com",
					Password:  "Password123!",
					FirstName: "Existing",
					LastName:  "User",
				},
			},
			before: func(deps TestDependencies) {
				deps.authService.On("Register", mock.MatchedBy(func(req domain.RegisterRequest) bool {
					return req.Email == "existing@example.com" &&
						req.Password == "Password123!" &&
						req.FirstName == "Existing" &&
						req.LastName == "User"
				})).Return(nil, errors.New("user already exists"))
				deps.logger.On("Errorf", mock.Anything, mock.Anything).Maybe()
				deps.logger.On("Infof", mock.Anything, mock.Anything, mock.Anything).Maybe()
			},
			expected: TestExpectations{
				error:    true,
				errorMsg: "Failed to register user",
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
			resp, err := server.Register(tc.args.ctx, tc.args.request.(*pb.RegisterRequest))

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
				request: &pb.LoginRequest{
					Email:    "test@example.com",
					Password: "Password123!",
				},
			},
			before: func(deps TestDependencies) {
				deps.authService.On("Login", mock.MatchedBy(func(req domain.LoginRequest) bool {
					return req.Email == "test@example.com" && req.Password == "Password123!"
				})).Return("valid-jwt-token", nil)
				deps.logger.On("Infof", mock.Anything, mock.Anything, mock.Anything).Maybe()
			},
			expected: TestExpectations{
				response: &pb.LoginResponse{
					Success: true,
					Token:   "valid-jwt-token",
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
				request: &pb.LoginRequest{
					Email:    "",
					Password: "",
				},
			},
			before: func(deps TestDependencies) {
				// No expectations needed as validation happens before service call
			},
			expected: TestExpectations{
				error:    true,
				errorMsg: "Missing email or password",
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
				request: &pb.LoginRequest{
					Email:    "nonexistent@example.com",
					Password: "Password123!",
				},
			},
			before: func(deps TestDependencies) {
				deps.authService.On("Login", mock.MatchedBy(func(req domain.LoginRequest) bool {
					return req.Email == "nonexistent@example.com" && req.Password == "Password123!"
				})).Return("", errors.New("USER_NOT_FOUND"))
				deps.logger.On("Infof", mock.Anything, mock.Anything, mock.Anything).Once()
			},
			expected: TestExpectations{
				error:    true,
				errorMsg: "An unexpected error occurred. Please try again later.",
				code:     codes.Internal,
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
				request: &pb.LoginRequest{
					Email:    "test@example.com",
					Password: "WrongPassword!",
				},
			},
			before: func(deps TestDependencies) {
				deps.authService.On("Login", mock.MatchedBy(func(req domain.LoginRequest) bool {
					return req.Email == "test@example.com" && req.Password == "WrongPassword!"
				})).Return("", dcerrors.ErrInvalidAuth)
				deps.logger.On("Infof", mock.Anything, mock.Anything, mock.Anything).Once()
			},
			expected: TestExpectations{
				error:    true,
				errorMsg: "Incorrect username or password. Please try again.",
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
			resp, err := server.Login(tc.args.ctx, tc.args.request.(*pb.LoginRequest))

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
				request: &pb.VerifyTokenRequest{
					Token: "valid-token",
				},
			},
			before: func(deps TestDependencies) {
				deps.tokenService.On("ValidateToken", "valid-token").Return("user123", nil)
			},
			expected: TestExpectations{
				response: &pb.VerifyTokenResponse{
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
				request: &pb.VerifyTokenRequest{
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
				request: &pb.VerifyTokenRequest{
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
			resp, err := server.VerifyToken(tc.args.ctx, tc.args.request.(*pb.VerifyTokenRequest))

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
