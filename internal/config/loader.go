package config

import (
	"time"

	"github.com/Businge931/sba-user-accounts/env"
)

// Load creates a configuration from environment variables
func Load() *Config {
	return &Config{
		DB: DBConfig{
			Host:     env.GetEnv("DB_HOST", ""),
			Port:     env.GetEnv("DB_PORT", ""),
			User:     env.GetEnv("DB_USER", ""),
			Name:     env.GetEnv("DB_NAME", ""),
			Password: env.GetEnv("DB_PASSWORD", ""),
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
		SendGrid: SendGridConfig{
			APIKey:    env.GetEnv("SENDGRID_API_KEY", ""),
			FromEmail: env.GetEnv("SENDGRID_FROM_EMAIL", "noreply@example.com"),
			FromName:  env.GetEnv("SENDGRID_FROM_NAME", "SBA User Accounts"),
		},
		Firebase: FirebaseConfig{
			APIKey:            env.GetEnv("FIREBASE_API_KEY", ""),
			AuthDomain:        env.GetEnv("FIREBASE_AUTH_DOMAIN", ""),
			ProjectID:         env.GetEnv("FIREBASE_PROJECT_ID", ""),
			StorageBucket:     env.GetEnv("FIREBASE_STORAGE_BUCKET", ""),
			MessagingSenderID: env.GetEnv("FIREBASE_MESSAGING_SENDER_ID", ""),
			AppID:             env.GetEnv("FIREBASE_APP_ID", ""),
			MeasurementID:     env.GetEnv("FIREBASE_MEASUREMENT_ID", ""),
		},
	}
}
