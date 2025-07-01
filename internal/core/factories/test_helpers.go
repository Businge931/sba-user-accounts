package factories

import (
	"context"
	"testing"
	"time"

	"github.com/Businge931/sba-user-accounts/internal/config"
	"github.com/stretchr/testify/require"
	testcontainers "github.com/testcontainers/testcontainers-go"
	postgrescontainer "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	gormpostgres "gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// testConfig is a shared test configuration used across test cases
var testConfig = &config.Config{
	Server: config.ServerConfig{
		GRPCPort: "50051",
	},
	Auth: config.AuthConfig{
		JWTSecret:      []byte("test-secret"),
		TokenExpiryMin: 60,
	},
}

// createTestDBContainer creates a new PostgreSQL container for testing
func createTestDBContainer(t *testing.T) (testcontainers.Container, *gorm.DB, string) {
	ctx := context.Background()

	// Create a PostgreSQL container
	container, err := postgrescontainer.RunContainer(ctx,
		testcontainers.WithImage("docker.io/postgres:16-alpine"),
		postgrescontainer.WithDatabase("testdb"),
		postgrescontainer.WithUsername("postgres"),
		postgrescontainer.WithPassword("postgres"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second)),
	)
	require.NoError(t, err, "Failed to start container")

	// Get the connection string
	dbURL, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err, "Failed to get database URL")

	// Connect to the database
	db, err := gorm.Open(gormpostgres.Open(dbURL), &gorm.Config{})
	require.NoError(t, err, "Failed to connect to test database")

	return container, db, dbURL
}
