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

// registerTestCase represents a test case for the register handler
type registerTestCase struct {
	name   string
	deps   registerTestDeps
	args   registerTestArgs
	before func(*testing.T, *registerTestDeps, registerTestArgs) (*grpc.AuthServer, *pb.RegisterResponse, error)
	after  func(*testing.T, *registerTestDeps, *pb.RegisterResponse, error)
}

func TestAuthServer_Register(t *testing.T) {
	tests := []registerTestCase{
		{
			name: "successful registration",
			deps: registerTestDeps{
				authService:  new(mocks.MockAuthService),
				tokenService: new(mocks.MockTokenService),
				logger:       new(mocks.MockLogger),
			},
			args: registerTestArgs{
				ctx: context.Background(),
				request: &pb.RegisterRequest{
					Email:     "test@example.com",
					Password:  "Password123!",
					FirstName: "Test",
					LastName:  "User",
				},
			},
			before: func(t *testing.T, d *registerTestDeps, args registerTestArgs) (*grpc.AuthServer, *pb.RegisterResponse, error) {
				d.authService.On("Register", mock.MatchedBy(func(req domain.RegisterRequest) bool {
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

				server := &grpc.AuthServer{
					AuthService:  d.authService,
					TokenService: d.tokenService,
					Logger:       d.logger,
				}

				return server, nil, nil
			},
			after: func(t *testing.T, d *registerTestDeps, resp *pb.RegisterResponse, err error) {
				d.authService.AssertExpectations(t)
				d.tokenService.AssertExpectations(t)
				d.logger.AssertExpectations(t)

				assert.NoError(t, err)
				assert.Equal(t, true, resp.Success)
				assert.Contains(t, resp.Message, "User registered successfully")
			},
		},

		{
			name: "service error during registration",
			deps: registerTestDeps{
				authService:  new(mocks.MockAuthService),
				tokenService: new(mocks.MockTokenService),
				logger:       new(mocks.MockLogger),
			},
			args: registerTestArgs{
				ctx: context.Background(),
				request: &pb.RegisterRequest{
					Email:     "existing@example.com",
					Password:  "Password123!",
					FirstName: "Existing",
					LastName:  "User",
				},
			},
			before: func(t *testing.T, d *registerTestDeps, args registerTestArgs) (*grpc.AuthServer, *pb.RegisterResponse, error) {
				d.authService.On("Register", mock.MatchedBy(func(req domain.RegisterRequest) bool {
					return req.Email == "existing@example.com"
				})).Return(nil, errors.New("user already exists"))

				d.logger.On("Errorf", mock.Anything, mock.Anything).Maybe()

				server := &grpc.AuthServer{
					AuthService:  d.authService,
					TokenService: d.tokenService,
					Logger:       d.logger,
				}

				return server, nil, nil
			},
			after: func(t *testing.T, d *registerTestDeps, resp *pb.RegisterResponse, err error) {
				d.authService.AssertExpectations(t)
				d.logger.AssertExpectations(t)

				assert.Error(t, err)
				assert.Nil(t, resp)

				st, ok := status.FromError(err)
				assert.True(t, ok)
				assert.Equal(t, codes.Internal, st.Code())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test
			server, _, _ := tt.before(t, &tt.deps, tt.args)

			// Execute
			resp, err := server.Register(tt.args.ctx, tt.args.request)

			// Verify
			tt.after(t, &tt.deps, resp, err)
		})
	}
}

// loginTestCase represents a test case for the login handler
type loginTestCase struct {
	name   string
	deps   loginTestDeps
	args   loginTestArgs
	before func(*testing.T, *loginTestDeps, loginTestArgs) (*grpc.AuthServer, *pb.LoginResponse, error)
	after  func(*testing.T, *loginTestDeps, *pb.LoginResponse, error)
}

func TestAuthServer_Login(t *testing.T) {
	testCases := []loginTestCase{
		{
			name: "Login_Success",
			deps: loginTestDeps{
				authService:  new(mocks.MockAuthService),
				tokenService: new(mocks.MockTokenService),
				logger:       new(mocks.MockLogger),
			},
			args: loginTestArgs{
				ctx: context.Background(),
				request: &pb.LoginRequest{
					Email:    "test@example.com",
					Password: "Password123!",
				},
			},
			before: func(t *testing.T, d *loginTestDeps, _ loginTestArgs) (*grpc.AuthServer, *pb.LoginResponse, error) {
				d.authService.On("Login", mock.MatchedBy(func(req domain.LoginRequest) bool {
					return req.Email == "test@example.com" && req.Password == "Password123!"
				})).Return("valid-jwt-token", nil)
				d.logger.On("Infof", mock.Anything, mock.Anything, mock.Anything).Maybe()

				server := &grpc.AuthServer{
					AuthService:  d.authService,
					TokenService: d.tokenService,
					Logger:       d.logger,
				}

				return server, &pb.LoginResponse{
					Success: true,
					Token:   "valid-jwt-token",
					Message: "Login successful",
				}, nil
			},
			after: func(t *testing.T, d *loginTestDeps, _ *pb.LoginResponse, _ error) {
				d.authService.AssertExpectations(t)
				d.tokenService.AssertExpectations(t)
				d.logger.AssertExpectations(t)
			},
		},
		{
			name: "Login_UserNotFound",
			deps: loginTestDeps{
				authService:  new(mocks.MockAuthService),
				tokenService: new(mocks.MockTokenService),
				logger:       new(mocks.MockLogger),
			},
			args: loginTestArgs{
				ctx: context.Background(),
				request: &pb.LoginRequest{
					Email:    "nonexistent@example.com",
					Password: "Password123!",
				},
			},
			before: func(t *testing.T, d *loginTestDeps, args loginTestArgs) (*grpc.AuthServer, *pb.LoginResponse, error) {
				d.authService.On("Login", mock.MatchedBy(func(req domain.LoginRequest) bool {
					return req.Email == "nonexistent@example.com" && req.Password == "Password123!"
				})).Return("", errors.New("USER_NOT_FOUND"))
				d.logger.On("Infof", mock.Anything, mock.Anything, mock.Anything).Once()

				server := &grpc.AuthServer{
					AuthService:  d.authService,
					TokenService: d.tokenService,
					Logger:       d.logger,
				}

				return server, nil, status.Error(codes.Internal, "An unexpected error occurred. Please try again later.")
			},
			after: func(t *testing.T, d *loginTestDeps, _ *pb.LoginResponse, err error) {
				assert.Error(t, err)
				st, ok := status.FromError(err)
				assert.True(t, ok)
				assert.Equal(t, codes.Internal, st.Code())
				assert.Contains(t, st.Message(), "An unexpected error occurred")
				d.authService.AssertExpectations(t)
				d.logger.AssertExpectations(t)
			},
		},
		{
			name: "Login_InvalidPassword",
			deps: loginTestDeps{
				authService:  new(mocks.MockAuthService),
				tokenService: new(mocks.MockTokenService),
				logger:       new(mocks.MockLogger),
			},
			args: loginTestArgs{
				ctx: context.Background(),
				request: &pb.LoginRequest{
					Email:    "test@example.com",
					Password: "WrongPassword!",
				},
			},
			before: func(t *testing.T, d *loginTestDeps, args loginTestArgs) (*grpc.AuthServer, *pb.LoginResponse, error) {
				d.authService.On("Login", mock.MatchedBy(func(req domain.LoginRequest) bool {
					return req.Email == "test@example.com" && req.Password == "WrongPassword!"
				})).Return("", dcerrors.ErrInvalidAuth)
				d.logger.On("Infof", mock.Anything, mock.Anything, mock.Anything).Once()

				server := &grpc.AuthServer{
					AuthService:  d.authService,
					TokenService: d.tokenService,
					Logger:       d.logger,
				}

				return server, nil, status.Error(codes.Unauthenticated, "Incorrect username or password. Please try again.")
			},
			after: func(t *testing.T, d *loginTestDeps, _ *pb.LoginResponse, err error) {
				assert.Error(t, err)
				st, ok := status.FromError(err)
				assert.True(t, ok)
				assert.Equal(t, codes.Unauthenticated, st.Code())
				assert.Contains(t, st.Message(), "Incorrect username or password")
				d.authService.AssertExpectations(t)
				d.logger.AssertExpectations(t)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup and execute
			server, want, wantErr := tc.before(t, &tc.deps, tc.args)
			got, err := server.Login(tc.args.ctx, tc.args.request)

			// Verify
			if wantErr != nil {
				assert.Error(t, err)
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, want, got)
			}

			// Custom verification
			tc.after(t, &tc.deps, got, err)
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

// registerTestDeps contains test dependencies for register handler tests
type registerTestDeps struct {
	authService  *mocks.MockAuthService
	tokenService *mocks.MockTokenService
	logger       *mocks.MockLogger
}

// registerTestArgs contains input arguments for register handler tests
type registerTestArgs struct {
	ctx     context.Context
	request *pb.RegisterRequest
}

// loginTestDeps contains test dependencies for login handler tests
type loginTestDeps struct {
	authService  *mocks.MockAuthService
	tokenService *mocks.MockTokenService
	logger       *mocks.MockLogger
}

// loginTestArgs contains input arguments for login handler tests
type loginTestArgs struct {
	ctx     context.Context
	request *pb.LoginRequest
}
