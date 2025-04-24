package config

import (
	"time"
)

// Config represents the entire application configuration
type Config struct {
	DB     DBConfig
	Auth   AuthConfig
	Server ServerConfig
}

// DBConfig holds database connection configuration
type DBConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Name     string
}

// AuthConfig holds authentication related configuration
type AuthConfig struct {
	JWTSecret      []byte
	TokenExpiryMin time.Duration
}

// ServerConfig holds server related configuration
type ServerConfig struct {
	GRPCPort string
}
