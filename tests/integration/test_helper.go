package integration

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	"github.com/Businge931/sba-user-accounts/internal/core/ports"
	"github.com/Businge931/sba-user-accounts/proto"
	"github.com/Businge931/sba-user-accounts/tests/unit/mocks"
)

const bufSize = 1024 * 1024

// setupGRPCServer creates an in-memory gRPC server using bufconn listener
func setupGRPCServer(
	authSvc ports.AuthService,
	tokenSvc ports.TokenService,
	logger ports.Logger,
) (*grpc.Server, *bufconn.Listener) {
	lis := bufconn.Listen(bufSize)
	s := grpc.NewServer()
	proto.RegisterAuthServiceServer(s, newAuthServiceHandler(authSvc, tokenSvc, logger))
	go func() {
		if err := s.Serve(lis); err != nil {
			logger.Errorf("Server exited with error: %v", err)
		}
	}()
	return s, lis
}

// bufDialer is a helper for connecting to the bufconn listener
func bufDialer(lis *bufconn.Listener) func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, url string) (net.Conn, error) {
		return lis.Dial()
	}
}

// authServiceHandler is a simplified version of the gRPC handler that sits between
// the gRPC server and our core AuthService
type authServiceHandler struct {
	proto.UnimplementedAuthServiceServer
	authSvc  ports.AuthService
	tokenSvc ports.TokenService
	logger   ports.Logger
}

func newAuthServiceHandler(
	authSvc ports.AuthService,
	tokenSvc ports.TokenService,
	logger ports.Logger,
) proto.AuthServiceServer {
	return &authServiceHandler{
		authSvc:  authSvc,
		tokenSvc: tokenSvc,
		logger:   logger,
	}
}

// Login implements the Login RPC method
func (h *authServiceHandler) Login(ctx context.Context, req *proto.LoginRequest) (*proto.LoginResponse, error) {
	token, err := h.authSvc.Login(req.Username, req.Password)
	if err != nil {
		return &proto.LoginResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}
	return &proto.LoginResponse{
		Success: true,
		Token:   token,
		Message: "Login successful",
	}, nil
}

// Register implements the Register RPC method
func (h *authServiceHandler) Register(ctx context.Context, req *proto.RegisterRequest) (*proto.RegisterResponse, error) {
	// Note: In a real implementation, we would parse more fields from the request
	// For simplicity in tests, we're using dummy values for firstName and lastName
	_, err := h.authSvc.Register(req.Username, req.Password, "Test", "User")
	if err != nil {
		return &proto.RegisterResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}
	return &proto.RegisterResponse{
		Success: true,
		Message: "Registration successful",
	}, nil
}

// VerifyToken implements the VerifyToken RPC method
func (h *authServiceHandler) VerifyToken(ctx context.Context, req *proto.VerifyTokenRequest) (*proto.VerifyTokenResponse, error) {
	_, err := h.tokenSvc.ValidateToken(req.Token)
	if err != nil {
		return &proto.VerifyTokenResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}
	return &proto.VerifyTokenResponse{
		Success: true,
		Message: "Token is valid",
	}, nil
}

// setupMockServices creates and returns mock services for testing
func setupMockServices(t *testing.T) (*mocks.MockAuthService, *mocks.MockTokenService, *mocks.MockLogger) {
	mockAuthSvc := new(mocks.MockAuthService)
	mockTokenSvc := new(mocks.MockTokenService)
	mockLogger := new(mocks.MockLogger)

	// Configure mockLogger to avoid unexpected interaction errors
	mockLogger.On("Debug", mock.Anything).Maybe().Return()
	mockLogger.On("Debugf", mock.Anything, mock.Anything).Maybe().Return()
	mockLogger.On("Info", mock.Anything).Maybe().Return()
	mockLogger.On("Infof", mock.Anything, mock.Anything).Maybe().Return()
	mockLogger.On("Warn", mock.Anything).Maybe().Return()
	mockLogger.On("Warnf", mock.Anything, mock.Anything).Maybe().Return()
	mockLogger.On("Error", mock.Anything).Maybe().Return()
	mockLogger.On("Errorf", mock.Anything, mock.Anything).Maybe().Return()

	return mockAuthSvc, mockTokenSvc, mockLogger
}
