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
	AuthService    ports.AuthService
	TokenService   ports.TokenService
	AccountService ports.AccountManagementService
	Logger         ports.Logger
	proto.UnimplementedAuthServiceServer
}

// Register handles user registration requests from the API gateway
func (server *AuthServer) Register(_ context.Context, req *proto.RegisterRequest) (*proto.RegisterResponse, error) {

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

// RequestPasswordReset handles password reset requests
func (server *AuthServer) RequestPasswordReset(_ context.Context, req *proto.RequestPasswordResetRequest) (*proto.RequestPasswordResetResponse, error) {
	// Validate request
	if req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	server.Logger.Infof("Password reset requested for email: %s", req.GetEmail())

	// Call the account management service to handle password reset
	err := server.AccountService.RequestPasswordReset(req.GetEmail())
	if err != nil {
		server.Logger.Errorf("Password reset failed for email %s: %v", req.GetEmail(), err)
		return nil, MapError(err)
	}

	return &proto.RequestPasswordResetResponse{
		Success: true,
		Message: "Password reset email sent successfully",
	}, nil
}

// ChangePassword handles password change requests for authenticated users
func (server *AuthServer) ChangePassword(_ context.Context, req *proto.ChangePasswordRequest) (*proto.ChangePasswordResponse, error) {
	// Validate request
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	if req.GetOldPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "old_password is required")
	}
	if req.GetNewPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "new_password is required")
	}

	server.Logger.Infof("Password change requested for user: %s", req.GetUserId())

	// Call the account management service to handle password change
	err := server.AccountService.ChangePassword(req.GetUserId(), req.GetOldPassword(), req.GetNewPassword())
	if err != nil {
		server.Logger.Errorf("Password change failed for user %s: %v", req.GetUserId(), err)
		return nil, MapError(err)
	}

	return &proto.ChangePasswordResponse{
		Success: true,
		Message: "Password changed successfully",
	}, nil
}

// ResetPassword handles password reset using a token
func (server *AuthServer) ResetPassword(_ context.Context, req *proto.ResetPasswordRequest) (*proto.ResetPasswordResponse, error) {
	// Validate request
	if req.GetToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}
	if req.GetNewPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "new_password is required")
	}

	server.Logger.Infof("Password reset attempted with token: %s", req.GetToken()[:8]+"...")

	// Call the account management service to handle password reset
	err := server.AccountService.ResetPassword(req.GetToken(), req.GetNewPassword())
	if err != nil {
		server.Logger.Errorf("Password reset failed: %v", err)
		return nil, MapError(err)
	}

	return &proto.ResetPasswordResponse{
		Success: true,
		Message: "Password reset successfully",
		UserId:  "", // Note: AccountService.ResetPassword doesn't return user ID
	}, nil
}
