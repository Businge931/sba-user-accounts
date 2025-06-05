package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/lib/pq"

	"github.com/Businge931/sba-user-accounts/internal/adapters/primary/grpc"
	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/logging"
	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/postgres"
	"github.com/Businge931/sba-user-accounts/internal/config"
	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/Businge931/sba-user-accounts/internal/core/factories"
	"github.com/Businge931/sba-user-accounts/internal/core/ports"
)

func main() {
	// Set up logging using our adapter
	logger := logging.NewLogrusAdapter()

	logger.Info("Starting sba-user-accounts service")

	// Load configurations from environment variables
	cfg := config.Load()

	// Initialize database connection
	dbFactory := postgres.NewDBFactory(cfg.DB)
	db, err := dbFactory.Connect()
	if err != nil {
		logger.Fatalf("Failed to initialize database: %v", err)
	}
	dbFactory.AutoMigrate(db, &domain.User{}, &domain.Token{})
	logger.Info("Database connection and migration established")

	// Use the service factory to initialize all repositories and services
	serviceFactory := factories.NewServiceFactory(db, cfg)
	serviceFactory.InitializeRepositories()
	logger.Info("Repositories initialized")

	serviceFactory.InitializeServices()
	logger.Info("Services initialized")

	// Get the auth service from the factory
	authService := serviceFactory.GetAuthService()

	// Create a context that listens for interruption signals
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	setupGracefulShutdown(cancel, logger)

	// Get token service from factory
	tokenService := serviceFactory.GetTokenService()

	// Initialize and start gRPC server
	server := grpc.NewServer(cfg.Server.GRPCPort, authService, tokenService, logger)

	logger.Infof("Starting gRPC server on port %s", cfg.Server.GRPCPort)
	go func() {
		if err := server.Start(); err != nil {
			logger.Errorf("gRPC server failed: %v", err)
			cancel()
		}
	}()

	// Wait for context cancellation (i.e., interrupt signal)
	<-ctx.Done()

	// Graceful shutdown
	logger.Info("Shutting down servers")
	server.GracefulStop()
	logger.Info("Shutdown complete")
}

// setupGracefulShutdown sets up signal handling for graceful shutdown
func setupGracefulShutdown(cancel context.CancelFunc, logger ports.Logger) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-signalChan
		logger.Info("Received interrupt signal, initiating graceful shutdown")
		cancel()
	}()
}
