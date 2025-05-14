package integration

// import (
// 	"context"
// 	"database/sql"
// 	"fmt"
// 	"os"
// 	"path/filepath"
// 	"testing"
// 	"time"

// 	_ "github.com/lib/pq"
// 	"github.com/stretchr/testify/assert"
// 	"github.com/stretchr/testify/require"
// 	"github.com/testcontainers/testcontainers-go"
// 	"github.com/testcontainers/testcontainers-go/wait"
// 	"google.golang.org/grpc"
// 	"google.golang.org/grpc/credentials/insecure"

// 	"github.com/Businge931/sba-user-accounts/proto"
// )

// // TestWithContainers demonstrates using Testcontainers for e2e testing of the sba-user-accounts service
// func TestWithContainers(t *testing.T) {
// 	// Skip this test when running unit tests
// 	// This test is meant to be run in a separate integration test pipeline
// 	if os.Getenv("SKIP_CONTAINER_TESTS") == "true" {
// 		t.Skip("Skipping container-based test")
// 	}

// 	// Define a context with timeout
// 	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
// 	defer cancel()

// 	// Start a Postgres container for testing
// 	postgresC, err := setupPostgresContainer(ctx, t)
// 	if err != nil {
// 		t.Fatalf("Failed to start Postgres container: %s", err)
// 	}
// 	defer func() {
// 		if err := postgresC.Terminate(ctx); err != nil {
// 			t.Logf("Failed to terminate Postgres container: %s", err)
// 		}
// 	}()

// 	// Get connection details for Postgres
// 	pgHost, err := postgresC.Host(ctx)
// 	require.NoError(t, err)

// 	pgPort, err := postgresC.MappedPort(ctx, "5432/tcp")
// 	require.NoError(t, err)

// 	// Connect to the Postgres container to verify it's working and run migrations
// 	pgDsn := fmt.Sprintf("host=%s port=%s user=admin password=adminpassword dbname=sba_users sslmode=disable",
// 		pgHost, pgPort.Port())

// 	db, err := sql.Open("postgres", pgDsn)
// 	require.NoError(t, err)
// 	defer db.Close()

// 	// Verify connection
// 	require.NoError(t, db.Ping(), "Failed to connect to Postgres container")
// 	t.Log("Successfully connected to Postgres container")

// 	// Start the Auth Service container
// 	authServiceC, err := setupAuthServiceContainer(ctx, t, pgHost, pgPort.Port())
// 	if err != nil {
// 		t.Fatalf("Failed to start auth service container: %s", err)
// 	}
// 	defer func() {
// 		if err := authServiceC.Terminate(ctx); err != nil {
// 			t.Logf("Failed to terminate auth service container: %s", err)
// 		}
// 	}()

// 	// Get Auth Service endpoint
// 	authServiceHost, err := authServiceC.Host(ctx)
// 	require.NoError(t, err)

// 	authServicePort, err := authServiceC.MappedPort(ctx, "50051/tcp")
// 	require.NoError(t, err)

// 	endpoint := fmt.Sprintf("%s:%s", authServiceHost, authServicePort.Port())
// 	t.Logf("Auth service available at: %s", endpoint)

// 	// Create gRPC client
// 	conn, err := grpc.Dial(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
// 	require.NoError(t, err)
// 	defer conn.Close()

// 	client := proto.NewAuthServiceClient(conn)

// 	// Define test table
// 	testCases := []struct {
// 		name   string
// 		testFn func(t *testing.T, client proto.AuthServiceClient)
// 	}{
// 		{
// 			name: "Register_Success",
// 			testFn: func(t *testing.T, client proto.AuthServiceClient) {
// 				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
// 				defer cancel()

// 				resp, err := client.Register(ctx, &proto.RegisterRequest{
// 					Username: "testuser@example.com",
// 					Password: "SecurePassword123!",
// 				})

// 				require.NoError(t, err)
// 				assert.True(t, resp.Success)
// 				assert.Contains(t, resp.Message, "successful")
// 			},
// 		},
// 		{
// 			name: "Register_DuplicateUser",
// 			testFn: func(t *testing.T, client proto.AuthServiceClient) {
// 				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
// 				defer cancel()

// 				// Try to register the same user again
// 				resp, err := client.Register(ctx, &proto.RegisterRequest{
// 					Username: "testuser@example.com",
// 					Password: "SecurePassword123!",
// 				})

// 				require.NoError(t, err) // The gRPC call should succeed but with a business logic error
// 				assert.False(t, resp.Success)
// 				assert.Contains(t, resp.Message, "exists")
// 			},
// 		},
// 		{
// 			name: "Login_Success",
// 			testFn: func(t *testing.T, client proto.AuthServiceClient) {
// 				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
// 				defer cancel()

// 				resp, err := client.Login(ctx, &proto.LoginRequest{
// 					Username: "testuser@example.com",
// 					Password: "SecurePassword123!",
// 				})

// 				require.NoError(t, err)
// 				assert.True(t, resp.Success)
// 				assert.NotEmpty(t, resp.Token, "Token should not be empty")
// 				assert.Contains(t, resp.Message, "successful")
// 			},
// 		},
// 		{
// 			name: "Login_WrongPassword",
// 			testFn: func(t *testing.T, client proto.AuthServiceClient) {
// 				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
// 				defer cancel()

// 				resp, err := client.Login(ctx, &proto.LoginRequest{
// 					Username: "testuser@example.com",
// 					Password: "WrongPassword123!",
// 				})

// 				require.NoError(t, err) // The gRPC call should succeed but with a business logic error
// 				assert.False(t, resp.Success)
// 				assert.Empty(t, resp.Token, "Token should be empty for failed login")
// 			},
// 		},
// 		{
// 			name: "VerifyToken",
// 			testFn: func(t *testing.T, client proto.AuthServiceClient) {
// 				// First login to get a token
// 				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
// 				defer cancel()

// 				loginResp, err := client.Login(ctx, &proto.LoginRequest{
// 					Username: "testuser@example.com",
// 					Password: "SecurePassword123!",
// 				})
// 				require.NoError(t, err)
// 				require.True(t, loginResp.Success)
// 				require.NotEmpty(t, loginResp.Token)

// 				// Now verify the token
// 				verifyResp, err := client.VerifyToken(ctx, &proto.VerifyTokenRequest{
// 					Token: loginResp.Token,
// 				})

// 				require.NoError(t, err)
// 				assert.True(t, verifyResp.Success)
// 				assert.Contains(t, verifyResp.Message, "valid")
// 			},
// 		},
// 		{
// 			name: "VerifyToken_Invalid",
// 			testFn: func(t *testing.T, client proto.AuthServiceClient) {
// 				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
// 				defer cancel()

// 				resp, err := client.VerifyToken(ctx, &proto.VerifyTokenRequest{
// 					Token: "this.is.invalid",
// 				})

// 				require.NoError(t, err) // The gRPC call should succeed but with a business logic error
// 				assert.False(t, resp.Success)
// 				assert.Contains(t, resp.Message, "invalid")
// 			},
// 		},
// 	}

// 	// Run all test cases
// 	for _, tc := range testCases {
// 		t.Run(tc.name, func(t *testing.T) {
// 			tc.testFn(t, client)
// 		})
// 	}
// }

// // Helper function to set up the Postgres container
// func setupPostgresContainer(ctx context.Context, t *testing.T) (testcontainers.Container, error) {
// 	t.Log("Setting up Postgres container")

// 	req := testcontainers.ContainerRequest{
// 		Image:        "postgres:14-alpine",
// 		ExposedPorts: []string{"5432/tcp"},
// 		Env: map[string]string{
// 			"POSTGRES_USER":     "admin",
// 			"POSTGRES_PASSWORD": "adminpassword",
// 			"POSTGRES_DB":       "sba_users",
// 		},
// 		WaitingFor: wait.ForLog("database system is ready to accept connections").WithStartupTimeout(1 * time.Minute),
// 	}

// 	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
// 		ContainerRequest: req,
// 		Started:          true,
// 	})

// 	if err != nil {
// 		return nil, fmt.Errorf("failed to start Postgres container: %w", err)
// 	}

// 	// Get container connection info
// 	ip, err := container.Host(ctx)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get container host: %w", err)
// 	}

// 	mappedPort, err := container.MappedPort(ctx, "5432/tcp")
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get mapped port: %w", err)
// 	}

// 	endpoint := fmt.Sprintf("%s:%s", ip, mappedPort.Port())
// 	t.Logf("Postgres container is ready at: %s", endpoint)

// 	return container, nil
// }

// // Helper function to set up the Auth Service container from the Dockerfile
// func setupAuthServiceContainer(ctx context.Context, t *testing.T, dbHost, dbPort string) (testcontainers.Container, error) {
// 	t.Log("Building and setting up Auth Service container from Dockerfile")

// 	// Get service directory path
// 	serviceDir, err := filepath.Abs(filepath.Join("..", ".."))
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get service directory: %w", err)
// 	}
// 	t.Logf("Using service path: %s", serviceDir)

// 	// Container configuration with environment variables for DB connection
// 	req := testcontainers.ContainerRequest{
// 		FromDockerfile: testcontainers.FromDockerfile{
// 			Context:    serviceDir,
// 			Dockerfile: "Dockerfile",
// 		},
// 		ExposedPorts: []string{"50051/tcp"},
// 		Env: map[string]string{
// 			"DB_HOST":          dbHost,
// 			"DB_PORT":          dbPort,
// 			"DB_USER":          "admin",
// 			"DB_PASSWORD":      "adminpassword",
// 			"DB_NAME":          "sba_users",
// 			"JWT_SECRET":       "test-jwt-secret-for-e2e-tests",
// 			"TOKEN_EXPIRY_MIN": "60",
// 			"GRPC_PORT":        "50051",
// 		},
// 		WaitingFor: wait.ForAll(
// 			wait.ForLog("Starting gRPC server"),
// 			wait.ForLog("Auth service is running"),
// 		).WithStartupTimeout(2 * time.Minute),
// 	}

// 	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
// 		ContainerRequest: req,
// 		Started:          true,
// 	})

// 	if err != nil {
// 		return nil, fmt.Errorf("failed to start auth service container: %w", err)
// 	}

// 	// Get container connection info
// 	ip, err := container.Host(ctx)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get container host: %w", err)
// 	}

// 	mappedPort, err := container.MappedPort(ctx, "50051/tcp")
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get mapped port: %w", err)
// 	}

// 	endpoint := fmt.Sprintf("%s:%s", ip, mappedPort.Port())
// 	t.Logf("Auth service container is ready at: %s", endpoint)
// 	return container, nil
// }
