package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/Businge931/sba-user-accounts/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestAuthService_Integration(t *testing.T) {
	testCases := []struct {
		name     string
		testFunc func(t *testing.T, client proto.AuthServiceClient)
		setup    func(mockAuthSvc *mock.Mock, mockTokenSvc *mock.Mock)
	}{
		{
			name: "Register_Success",
			testFunc: func(t *testing.T, client proto.AuthServiceClient) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()

				resp, err := client.Register(ctx, &proto.RegisterRequest{
					Username: "test@example.com",
					Password: "Password123!",
				})

				require.NoError(t, err)
				assert.True(t, resp.Success)
				assert.Equal(t, "Registration successful", resp.Message)
			},
			setup: func(mockAuthSvc *mock.Mock, mockTokenSvc *mock.Mock) {
				// Set up mock expectations for successful registration
				mockAuthSvc.On("Register",
					"test@example.com", "Password123!", "Test", "User").
					Return(&domain.User{
						ID:              "test-user-id",
						Email:           "test@example.com",
						FirstName:       "Test",
						LastName:        "User",
						IsEmailVerified: false,
					}, nil)
			},
		},
		{
			name: "Register_Failure",
			testFunc: func(t *testing.T, client proto.AuthServiceClient) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()

				resp, err := client.Register(ctx, &proto.RegisterRequest{
					Username: "existing@example.com",
					Password: "Password123!",
				})

				require.NoError(t, err) // gRPC error is not expected, only business logic error
				assert.False(t, resp.Success)
				assert.Contains(t, resp.Message, "already exists")
			},
			setup: func(mockAuthSvc *mock.Mock, mockTokenSvc *mock.Mock) {
				// Set up mock expectations for failed registration (user already exists)
				mockAuthSvc.On("Register",
					"existing@example.com", "Password123!", "Test", "User").
					Return(nil, errors.New("user already exists"))
			},
		},
		{
			name: "Login_Success",
			testFunc: func(t *testing.T, client proto.AuthServiceClient) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()

				resp, err := client.Login(ctx, &proto.LoginRequest{
					Username: "valid@example.com",
					Password: "Password123!",
				})

				require.NoError(t, err)
				assert.True(t, resp.Success)
				assert.Equal(t, "test-jwt-token", resp.Token)
				assert.Equal(t, "Login successful", resp.Message)
			},
			setup: func(mockAuthSvc *mock.Mock, mockTokenSvc *mock.Mock) {
				// Set up mock expectations for successful login
				mockAuthSvc.On("Login",
					"valid@example.com", "Password123!").
					Return("test-jwt-token", nil)
			},
		},
		{
			name: "Login_InvalidCredentials",
			testFunc: func(t *testing.T, client proto.AuthServiceClient) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()

				resp, err := client.Login(ctx, &proto.LoginRequest{
					Username: "valid@example.com",
					Password: "WrongPassword!",
				})

				require.NoError(t, err) // gRPC error is not expected, only business logic error
				assert.False(t, resp.Success)
				assert.Contains(t, resp.Message, "invalid password")
			},
			setup: func(mockAuthSvc *mock.Mock, mockTokenSvc *mock.Mock) {
				// Set up mock expectations for failed login (invalid credentials)
				mockAuthSvc.On("Login",
					"valid@example.com", "WrongPassword!").
					Return("", errors.New("invalid password"))
			},
		},
		{
			name: "VerifyToken_Valid",
			testFunc: func(t *testing.T, client proto.AuthServiceClient) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()

				resp, err := client.VerifyToken(ctx, &proto.VerifyTokenRequest{
					Token: "valid-token",
				})

				require.NoError(t, err)
				assert.True(t, resp.Success)
				assert.Equal(t, "Token is valid", resp.Message)
			},
			setup: func(mockAuthSvc *mock.Mock, mockTokenSvc *mock.Mock) {
				// Set up mock expectations for valid token verification
				mockTokenSvc.On("ValidateToken", "valid-token").
					Return("test-user-id", nil)
			},
		},
		{
			name: "VerifyToken_Invalid",
			testFunc: func(t *testing.T, client proto.AuthServiceClient) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()

				resp, err := client.VerifyToken(ctx, &proto.VerifyTokenRequest{
					Token: "invalid-token",
				})

				require.NoError(t, err) // gRPC error is not expected, only business logic error
				assert.False(t, resp.Success)
				assert.Contains(t, resp.Message, "invalid token")
			},
			setup: func(mockAuthSvc *mock.Mock, mockTokenSvc *mock.Mock) {
				// Set up mock expectations for invalid token verification
				mockTokenSvc.On("ValidateToken", "invalid-token").
					Return("", errors.New("invalid token"))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set up mock services
			mockAuthSvc, mockTokenSvc, mockLogger := setupMockServices(t)

			// Configure mocks based on test case
			tc.setup(&mockAuthSvc.Mock, &mockTokenSvc.Mock)

			// Set up an in-memory gRPC server for testing
			server, listener := setupGRPCServer(mockAuthSvc, mockTokenSvc, mockLogger)
			defer server.Stop()

			// Create a client connection to our in-memory server
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			conn, err := grpc.DialContext(
				ctx,
				"bufnet",
				grpc.WithContextDialer(bufDialer(listener)),
				grpc.WithTransportCredentials(insecure.NewCredentials()),
			)
			require.NoError(t, err)
			defer conn.Close()

			client := proto.NewAuthServiceClient(conn)

			// Run the specific test case
			tc.testFunc(t, client)

			// Verify all expectations were met
			mockAuthSvc.AssertExpectations(t)
			mockTokenSvc.AssertExpectations(t)
		})
	}
}
