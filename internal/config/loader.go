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
	}
}
