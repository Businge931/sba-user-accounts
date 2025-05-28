package grpc

import (
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/Businge931/sba-user-accounts/internal/core/ports"
	pb "github.com/Businge931/sba-user-accounts/proto"
)

// Server represents the gRPC server
type Server struct {
	grpcServer *grpc.Server
	port       string
	authServer *AuthServer
}

// NewServer creates a new gRPC server
func NewServer(port string, authService ports.AuthService, tokenService ports.TokenService, logger ports.Logger) *Server {
	// Initialize gRPC server
	grpcServer := grpc.NewServer()

	// Create and register auth server
	authServer := &AuthServer{
		AuthService:  authService,
		TokenService: tokenService,
		Logger:       logger,
	}
	pb.RegisterAuthServiceServer(grpcServer, authServer)

	// Register reflection service on gRPC server for debugging
	reflection.Register(grpcServer)

	return &Server{
		grpcServer: grpcServer,
		port:       port,
		authServer: authServer,
	}
}

// Start begins listening for gRPC requests
func (s *Server) Start() error {
	// Create TCP listener on configured port
	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", s.port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %s: %v", s.port, err)
	}

	log.Infof("Starting gRPC server on port %s", s.port)

	// Start serving gRPC requests
	return s.grpcServer.Serve(lis)
}

// GracefulStop stops the gRPC server gracefully
func (s *Server) GracefulStop() {
	s.grpcServer.GracefulStop()
}
