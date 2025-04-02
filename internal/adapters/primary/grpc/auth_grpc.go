package grpc

import (
	"context"
	"fmt"

	"github.com/Businge931/sba-user-accounts/internal/core/ports"
	"github.com/Businge931/sba-user-accounts/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AuthServer implements the gRPC AuthService server interface
type AuthServer struct {
	AuthService ports.AuthService
	proto.UnimplementedAuthServiceServer
}

// Register handles user registration requests from the API gateway
func (s *AuthServer) Register(ctx context.Context, req *proto.RegisterRequest) (*proto.RegisterResponse, error) {
	// Validate request
	if req.Username == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "missing required fields")
	}

	// Call the core auth service to handle registration logic
	// Extract first and last name from username if possible, or use username for both
	firstName := req.Username
	lastName := ""

	// Call the service with parameters matching the actual interface
	// user, err := s.AuthService.Register(req.Username, req.Password, firstName, lastName)
	_, err := s.AuthService.Register(req.Username, req.Password, firstName, lastName)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &proto.RegisterResponse{
		Success: true,
		Message: "User registered successfully",
	}, nil
}

// Login handles user login requests from the API gateway
func (s *AuthServer) Login(ctx context.Context, req *proto.LoginRequest) (*proto.LoginResponse, error) {
	// Validate request
	if req.Username == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "Missing username or password")
	}

	// Call the core auth service to handle login logic
	// Use username as email for login
	token, err := s.AuthService.Login(req.Username, req.Password)
	if err != nil {
		// Handle different error types based on the error message
		errMsg := err.Error()
		fmt.Printf("Login error for user %s: %s\n", req.Username, errMsg)
		
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
func (s *AuthServer) VerifyToken(ctx context.Context, req *proto.VerifyTokenRequest) (*proto.VerifyTokenResponse, error) {
	// Validate request
	if req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}

	// TODO: Implement actual token verification
	// Currently the AuthService doesn't have a method for token verification
	// This is a placeholder implementation that always succeeds
	// In a real implementation, we would call a method to validate the token

	// For now, return a success response
	// In production, this should be properly implemented
	return &proto.VerifyTokenResponse{
		Success: true,
		Message: "Token is valid",
	}, nil
}
