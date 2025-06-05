package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)



func TestLoad(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		validate func(t *testing.T, cfg *Config)
	}{
		{
			name: "load with default values",
			envVars: map[string]string{},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "localhost", cfg.DB.Host)
				assert.Equal(t, "5432", cfg.DB.Port)
				assert.Equal(t, "admin", cfg.DB.User)
				assert.Equal(t, "adminpassword", cfg.DB.Password)
				assert.Equal(t, "sba_users", cfg.DB.Name)
				assert.Equal(t, []byte("your-secret-key"), cfg.Auth.JWTSecret)
				assert.Equal(t, 60*time.Minute, cfg.Auth.TokenExpiryMin)
				assert.Equal(t, "50051", cfg.Server.GRPCPort)
			},
		},
		{
			name: "load with custom values",
			envVars: map[string]string{
				"DB_HOST":          "custom_host",
				"DB_PORT":          "5433",
				"DB_USER":          "custom_user",
				"DB_PASSWORD":      "custom_password",
				"DB_NAME":          "custom_db",
				"JWT_SECRET":       "custom_secret_key",
				"TOKEN_EXPIRY_MIN": "120",
				"GRPC_PORT":        "50052",
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "custom_host", cfg.DB.Host)
				assert.Equal(t, "5433", cfg.DB.Port)
				assert.Equal(t, "custom_user", cfg.DB.User)
				assert.Equal(t, "custom_password", cfg.DB.Password)
				assert.Equal(t, "custom_db", cfg.DB.Name)
				assert.Equal(t, []byte("custom_secret_key"), cfg.Auth.JWTSecret)
				assert.Equal(t, 120*time.Minute, cfg.Auth.TokenExpiryMin)
				assert.Equal(t, "50052", cfg.Server.GRPCPort)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up environment variables
			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}
			// Clean up environment variables after test
			defer func() {
				for k := range tt.envVars {
					os.Unsetenv(k)
				}
			}()

			// Execute
			cfg := Load()

			// Validate
			require.NotNil(t, cfg)
			tt.validate(t, cfg)
		})
	}
}

func TestLoad_InvalidTokenExpiry(t *testing.T) {
	// Set up environment with invalid TOKEN_EXPIRY_MIN
	os.Setenv("TOKEN_EXPIRY_MIN", "invalid")
	defer os.Unsetenv("TOKEN_EXPIRY_MIN")

	// Should not panic and should use default value
	cfg := Load()
	require.NotNil(t, cfg)
	assert.Equal(t, 60*time.Minute, cfg.Auth.TokenExpiryMin)
}
