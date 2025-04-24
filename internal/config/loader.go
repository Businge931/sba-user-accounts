package config

import (
	"os"
	"strconv"
	"time"
)

// GetEnv returns the environment variable or a default value
func GetEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

// GetInt returns the environment variable as int or a default value
func GetInt(key string, fallback int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return fallback
}

// Load creates a configuration from environment variables
func Load() *Config {
	return &Config{
		DB: DBConfig{
			Host:     GetEnv("DB_HOST", "localhost"),
			Port:     GetEnv("DB_PORT", "5432"),
			User:     GetEnv("DB_USER", "admin"),
			Password: GetEnv("DB_PASSWORD", "adminpassword"),
			Name:     GetEnv("DB_NAME", "sba_users"),
		},
		Auth: AuthConfig{
			JWTSecret:      []byte(GetEnv("JWT_SECRET", "your-secret-key")),
			TokenExpiryMin: time.Duration(GetInt("TOKEN_EXPIRY_MIN", 60)) * time.Minute,
		},
		Server: ServerConfig{
			GRPCPort: GetEnv("GRPC_PORT", "50051"),
		},
	}
}
