package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Businge931/sba-user-accounts/cmd/env"
	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/postgres"
	"github.com/Businge931/sba-user-accounts/internal/core/services"
	_ "github.com/lib/pq"
	log "github.com/sirupsen/logrus"
)

type dbConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Name     string
}

type authConfig struct {
	JWTSecret      string
	TokenExpiryMin int
}

type serverConfig struct {
	HTTPPort string
	GRPCPort string
}

func main() {
	// Set up logging
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)

	log.Info("Starting sba-user-accounts service")

	// Load configurations
	dbConfig := dbConfig{
		Host:     env.GetEnv("DB_HOST", "localhost"),
		Port:     env.GetEnv("DB_PORT", "5432"),
		User:     env.GetEnv("DB_USER", "admin"),
		Password: env.GetEnv("DB_PASSWORD", "adminpassword"),
		Name:     env.GetEnv("DB_NAME", "sba_users"),
	}

	authConfig := authConfig{
		JWTSecret:      env.GetEnv("JWT_SECRET", "your-secret-key"),
		TokenExpiryMin: env.GetInt("TOKEN_EXPIRY_MIN", 60),
	}

	serverConfig := serverConfig{
		// HTTPPort: env.GetEnv("HTTP_PORT", "8081"),
		GRPCPort: env.GetEnv("GRPC_PORT", "50051"), // Updated port for user-accounts service
	}

	// Initialize database connection
	db, err := initDB(dbConfig)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()
	log.Info("Database connection established")

	// Initialize repositories
	userRepo := postgres.NewUserRepository(db)
	authRepo := postgres.NewAuthRepository(db) // Using DB-backed auth repository
	log.Info("Repositories initialized")

	// Initialize services
	authService := services.NewAuthService(
		userRepo,
		authRepo, // Using the new DB-backed auth repository
		[]byte(authConfig.JWTSecret),
		time.Duration(authConfig.TokenExpiryMin)*time.Minute,
	)
	log.Info("Auth service initialized")

	// Create a context that listens for interruption signals
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	setupGracefulShutdown(cancel)

	// Initialize and start API with gRPC server
	api := NewAPI(Config{
		ServerPort: serverConfig.GRPCPort,
	}, authService)

	log.Infof("Starting gRPC server on port %s", serverConfig.GRPCPort)
	go func() {
		if err := api.Start(); err != nil {
			log.Errorf("gRPC server failed: %v", err)
			cancel()
		}
	}()

	// Wait for context cancellation (i.e., interrupt signal)
	<-ctx.Done()

	// Graceful shutdown
	log.Info("Shutting down servers")
	api.grpcServer.GracefulStop()
	log.Info("Shutdown complete")
}

// setupGracefulShutdown sets up signal handling for graceful shutdown
func setupGracefulShutdown(cancel context.CancelFunc) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-signalChan
		log.Info("Received interrupt signal, initiating graceful shutdown")
		cancel()
	}()
}
