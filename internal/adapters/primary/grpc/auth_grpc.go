package grpc

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Businge931/sba-user-accounts/internal/core/ports"
	"github.com/Businge931/sba-user-accounts/proto"
)

// AuthServer implements the gRPC AuthService server interface
type AuthServer struct {
	AuthService  ports.AuthService
	tokenService ports.TokenService
	logger       ports.Logger
	proto.UnimplementedAuthServiceServer
}

// Register handles user registration requests from the API gateway
func (server *AuthServer) Register(_ context.Context, req *proto.RegisterRequest) (*proto.RegisterResponse, error) {
	// Validate request
	if req.GetUsername() == "" || req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing required fields")
	}

	// Call the core auth service to handle registration logic
	// Extract first and last name from username if possible, or use username for both
	firstName := req.GetUsername()
	lastName := ""

	// Call the service with parameters matching the actual interface
	_, err := server.AuthService.Register(req.GetUsername(), req.GetPassword(), firstName, lastName)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &proto.RegisterResponse{
		Success: true,
		Message: "User registered successfully",
	}, nil
}

// Login handles user login requests from the API gateway
func (server *AuthServer) Login(_ context.Context, req *proto.LoginRequest) (*proto.LoginResponse, error) {
	// Validate request
	if req.GetUsername() == "" || req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "Missing username or password")
	}

	// Call the core auth service to handle login logic
	// Use username as email for login
	token, err := server.AuthService.Login(req.GetUsername(), req.GetPassword())
	if err != nil {
		// Handle different error types based on the error message
		errMsg := err.Error()
		server.logger.Infof("Login error for user %s: %s", req.GetUsername(), errMsg)

		// Map error messages to appropriate gRPC status codes and user-friendly messages
		switch errMsg {
		case "USER_NOT_FOUND":
			return nil, status.Error(codes.NotFound, "Account not found. Please check your username or register.")
		case "INVALID_PASSWORD":
			return nil, status.Error(codes.Unauthenticated, "Incorrect password. Please try again.")
		case "EMAIL_NOT_VERIFIED":
			return nil, status.Error(codes.PermissionDenied, "Please verify your email before logging in.")
		default:
			// For any other unexpected errors
			return nil, status.Error(codes.Internal, "An unexpected error occurred. Please try again later.")
		}
	}

	return &proto.LoginResponse{
		Success: true,
		Token:   token,
		Message: "Login successful",
	}, nil
}

// VerifyToken validates a JWT token and returns user information
// This is a simplified implementation since we don't have a direct method in the AuthService
func (server *AuthServer) VerifyToken(_ context.Context, req *proto.VerifyTokenRequest) (*proto.VerifyTokenResponse, error) {
	// Validate request
	if req.GetToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}

	// Attempt to verify the token using TokenService if available
	if server.tokenService != nil {
		_, err := server.tokenService.ValidateToken(req.GetToken())
		if err != nil {
			server.logger.Warnf("Token validation failed: %v", err)
			return nil, status.Error(codes.Unauthenticated, "Invalid or expired token")
		}
	}

	return &proto.VerifyTokenResponse{
		Success: true,
		Message: "Token is valid",
	}, nil
}
