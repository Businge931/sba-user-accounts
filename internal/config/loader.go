package config

import (
	"time"

	"github.com/Businge931/sba-user-accounts/env"
)

// Load creates a configuration from environment variables
func Load() *Config {
	return &Config{
		DB: DBConfig{
			Host:     env.GetEnv("DB_HOST", "localhost"),
			Port:     env.GetEnv("DB_PORT", "5432"),
			User:     env.GetEnv("DB_USER", "admin"),
			Password: env.GetEnv("DB_PASSWORD", "adminpassword"),
			Name:     env.GetEnv("DB_NAME", "sba_users"),
		},
		Auth: AuthConfig{
			JWTSecret:      []byte(env.GetEnv("JWT_SECRET", "your-secret-key")),
			TokenExpiryMin: time.Duration(env.GetInt("TOKEN_EXPIRY_MIN", 60)) * time.Minute,
		},
		Server: ServerConfig{
			GRPCPort: env.GetEnv("GRPC_PORT", "50051"),
		},
		SMTP: SMTPConfig{
			Host:     env.GetEnv("SMTP_HOST", "smtp.example.com"),
			Port:     env.GetInt("SMTP_PORT", 587),
			Username: env.GetEnv("SMTP_USERNAME", ""),
			Password: env.GetEnv("SMTP_PASSWORD", ""),
			From:     env.GetEnv("SMTP_FROM", "noreply@example.com"),
		},
	}
}
