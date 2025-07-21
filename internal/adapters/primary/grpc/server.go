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

type Server struct {
	grpcServer *grpc.Server
	port       string
	authServer *AuthServer
}

// NewServer creates a new gRPC server
func NewServer(port string, authService ports.AuthService, tokenService ports.TokenService, accountService ports.AccountManagementService, logger ports.Logger) *Server {
	grpcServer := grpc.NewServer()

	// Create and register auth server
	authServer := &AuthServer{
		AuthService:           authService,
		TokenService:          tokenService,
		AccountService:        accountService,
		Logger:                logger,
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

func (s *Server) Start() error {
	// Create TCP listener on configured port
	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", s.port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %s: %v", s.port, err)
	}

	log.Infof("Starting gRPC server on port %s", s.port)

	return s.grpcServer.Serve(lis)
}

func (s *Server) GracefulStop() {
	s.grpcServer.GracefulStop()
}
