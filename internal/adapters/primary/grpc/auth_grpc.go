package grpc

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/Businge931/sba-user-accounts/internal/core/ports"
	"github.com/Businge931/sba-user-accounts/proto"
)

// AuthServer implements the gRPC AuthService server interface
type AuthServer struct {
	AuthService  ports.AuthService
	TokenService ports.TokenService
	Logger       ports.Logger
	proto.UnimplementedAuthServiceServer
}

// Register handles user registration requests from the API gateway
func (server *AuthServer) Register(_ context.Context, req *proto.RegisterRequest) (*proto.RegisterResponse, error) {

	// Create register request with all required fields
	registerReq := domain.RegisterRequest{
		Email:     req.GetEmail(),
		Password:  req.GetPassword(),
		FirstName: req.GetFirstName(),
		LastName:  req.GetLastName(),
	}

	// Call the service with the request struct
	_, err := server.AuthService.Register(registerReq)
	if err != nil {
		server.Logger.Errorf("Registration failed: %v", err)
		return nil, MapError(err)
	}

	return &proto.RegisterResponse{
		Success: true,
		Message: "User registered successfully. Please check your email to verify your account.",
	}, nil
}

// Login handles user login requests from the API gateway
func (server *AuthServer) Login(_ context.Context, req *proto.LoginRequest) (*proto.LoginResponse, error) {

	// Create login request
	loginReq := domain.LoginRequest{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
	}

	// Call the core auth service to handle login logic
	token, err := server.AuthService.Login(loginReq)
	if err != nil {
		server.Logger.Infof("Login error for user %s: %v", req.GetEmail(), err)
		return nil, MapLoginError(err)
	}

	return &proto.LoginResponse{
		Success: true,
		Token:   token,
		Message: "Login successful",
	}, nil
}

// VerifyToken validates a JWT token and returns user information
func (server *AuthServer) VerifyToken(_ context.Context, req *proto.VerifyTokenRequest) (*proto.VerifyTokenResponse, error) {
	// Validate request
	if req.GetToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}

	// Attempt to verify the token using TokenService if available
	if server.TokenService != nil {
		_, err := server.TokenService.ValidateToken(req.GetToken())
		if err != nil {
			server.Logger.Warnf("Token validation failed: %v", err)
			return nil, MapError(err)
		}
	}

	return &proto.VerifyTokenResponse{
		Success: true,
		Message: "Token is valid",
	}, nil
}
