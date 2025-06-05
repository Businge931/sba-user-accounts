package grpc

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	dcerrors "github.com/Businge931/sba-user-accounts/internal/core/errors"
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
	// Validate request
	if req.GetEmail() == "" || req.GetPassword() == "" || req.GetFirstName() == "" || req.GetLastName() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing required fields: email, password, first_name, and last_name are required")
	}

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
		
		// Handle specific error types
		if errors.Is(err, dcerrors.ErrAlreadyExists) {
			return nil, status.Error(codes.AlreadyExists, "User already exists")
		}
		if errors.Is(err, dcerrors.ErrInvalidInput) {
			return nil, status.Error(codes.InvalidArgument, "Invalid input provided")
		}
		return nil, status.Error(codes.Internal, "Failed to register user")
	}

	return &proto.RegisterResponse{
		Success: true,
		Message: "User registered successfully. Please check your email to verify your account.",
	}, nil
}

// Login handles user login requests from the API gateway
func (server *AuthServer) Login(_ context.Context, req *proto.LoginRequest) (*proto.LoginResponse, error) {
	// Validate request
	if req.GetEmail() == "" || req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "Missing email or password")
	}

	// Create login request
	loginReq := domain.LoginRequest{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
	}

	// Call the core auth service to handle login logic
	token, err := server.AuthService.Login(loginReq)
	if err != nil {
		server.Logger.Infof("Login error for user %s: %v", req.GetEmail(), err)

		// Map domain errors to appropriate gRPC status codes and user-friendly messages
		switch {
		case errors.Is(err, dcerrors.ErrNotFound):
			return nil, status.Error(codes.NotFound, "Account not found. Please check your username or register.")
		case errors.Is(err, dcerrors.ErrInvalidAuth):
			return nil, status.Error(codes.Unauthenticated, "Incorrect username or password. Please try again.")
		case errors.Is(err, dcerrors.ErrUnauthorized):
			return nil, status.Error(codes.PermissionDenied, "Please verify your email before logging in.")
		}
		// For any other unexpected errors
		return nil, status.Error(codes.Internal, "An unexpected error occurred. Please try again later.")
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
	if server.TokenService != nil {
		_, err := server.TokenService.ValidateToken(req.GetToken())
		if err != nil {
			server.Logger.Warnf("Token validation failed: %v", err)
			return nil, status.Error(codes.Unauthenticated, "Invalid or expired token")
		}
	}

	return &proto.VerifyTokenResponse{
		Success: true,
		Message: "Token is valid",
	}, nil
}
