package main

import (
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/Businge931/sba-user-accounts/cmd/env"
	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/postgres"
	"github.com/Businge931/sba-user-accounts/internal/core/services"
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

func main() {
	// Load database configuration
	dbConfig := dbConfig{
		Host:     env.GetEnv("DB_HOST", "localhost"),
		Port:     env.GetEnv("DB_PORT", "5432"),
		User:     env.GetEnv("DB_USER", "postgres"),
		Password: env.GetEnv("DB_PASSWORD", ""),
		Name:     env.GetEnv("DB_NAME", "user_auth"),
	}

	// Load auth configuration
	authConfig := authConfig{
		JWTSecret:      env.GetEnv("JWT_SECRET", "your-secret-key"),
		TokenExpiryMin: 60, // 1 hour
	}

	// Initialize database connection
	db, err := initDB(dbConfig)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Initialize repositories
	userRepo := postgres.NewUserRepository(db)

	// Initialize services
	authService := services.NewAuthService(
		userRepo,
		nil, // TODO: Implement and inject AuthRepository
		nil, // TODO: Implement and inject EmailService
		[]byte(authConfig.JWTSecret),
		time.Duration(authConfig.TokenExpiryMin)*time.Minute,
	)

	// Initialize and start API
	api := NewAPI(Config{
		ServerPort:   env.GetEnv("SERVER_PORT", "8080"),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}, authService)

	log.Printf("Starting server on port %s", env.GetEnv("SERVER_PORT", "8080"))
	if err := api.Start(); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
