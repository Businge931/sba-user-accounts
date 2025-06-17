package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testCase struct {
	name      string
	before     func(t *testing.T)
	after     func(t *testing.T)
	expect    func(t *testing.T, cfg *Config)
}

func TestLoader(t *testing.T) {
	defaultConfig := &Config{
		DB: DBConfig{
			Host:     "localhost",
			Port:     "5432",
			User:     "admin",
			Password: "adminpassword",
			Name:     "sba_users",
		},
		Auth: AuthConfig{
			JWTSecret:      []byte("your-secret-key"),
			TokenExpiryMin: 60 * time.Minute,
		},
		Server: ServerConfig{
			GRPCPort: "50051",
		},
	}

	tests := []testCase{
		{
			name: "load with default values",
			before: func(t *testing.T) {
				// No environment variables set
			},
			after: func(t *testing.T) {
				// Clean up any environment variables that might have been set
				for _, k := range []string{
					"DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME",
					"JWT_SECRET", "TOKEN_EXPIRY_MIN", "GRPC_PORT",
				} {
					os.Unsetenv(k)
				}
			},
			expect: func(t *testing.T, cfg *Config) {
				assert.Equal(t, defaultConfig, cfg)
			},
		},
		{
			name: "load with custom values",
			before: func(t *testing.T) {
				envVars := map[string]string{
					"DB_HOST":          "custom_host",
					"DB_PORT":          "5433",
					"DB_USER":          "custom_user",
					"DB_PASSWORD":      "custom_password",
					"DB_NAME":          "custom_db",
					"JWT_SECRET":       "custom_secret_key",
					"TOKEN_EXPIRY_MIN": "120",
					"GRPC_PORT":        "50052",
				}
				for k, v := range envVars {
					os.Setenv(k, v)
				}
			},
			after: func(t *testing.T) {
				// Clean up environment variables
				for _, k := range []string{
					"DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME",
					"JWT_SECRET", "TOKEN_EXPIRY_MIN", "GRPC_PORT",
				} {
					os.Unsetenv(k)
				}
			},
			expect: func(t *testing.T, cfg *Config) {
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
		{
			name: "load with invalid token expiry",
			before: func(t *testing.T) {
				os.Setenv("TOKEN_EXPIRY_MIN", "invalid")
			},
			after: func(t *testing.T) {
				os.Unsetenv("TOKEN_EXPIRY_MIN")
			},
			expect: func(t *testing.T, cfg *Config) {
				// Should use default value when invalid
				assert.Equal(t, 60*time.Minute, cfg.Auth.TokenExpiryMin)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// before
			if tc.before != nil {
				tc.before(t)
			}

			// Ensure cleanup runs even if test fails
			if tc.after != nil {
				defer tc.after(t)
			}

			// Execute
			cfg := Load()

			// Validate
			require.NotNil(t, cfg, "Config should not be nil")
			if tc.expect != nil {
				tc.expect(t, cfg)
			}
		})
	}
}
