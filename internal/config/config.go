package config

import (
	"time"
)

// Config represents the entire application configuration
type Config struct {
	DB       DBConfig
	Auth     AuthConfig
	Server   ServerConfig
	SMTP     SMTPConfig
	SendGrid SendGridConfig
	Firebase FirebaseConfig
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

// SMTPConfig holds SMTP server configuration
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

// SendGridConfig holds SendGrid API configuration
type SendGridConfig struct {
	APIKey     string `mapstructure:"api_key"`
	FromEmail  string `mapstructure:"from_email"`
	FromName   string `mapstructure:"from_name"`
}

// FirebaseConfig holds Firebase configuration
type FirebaseConfig struct {
	APIKey            string `mapstructure:"api_key"`
	AuthDomain        string `mapstructure:"auth_domain"`
	ProjectID         string `mapstructure:"project_id"`
	StorageBucket     string `mapstructure:"storage_bucket"`
	MessagingSenderID string `mapstructure:"messaging_sender_id"`
	AppID             string `mapstructure:"app_id"`
	MeasurementID     string `mapstructure:"measurement_id"`
}
