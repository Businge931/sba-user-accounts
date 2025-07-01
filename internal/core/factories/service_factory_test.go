package factories

import (
	"context"
	"reflect"
	"testing"

	"github.com/Businge931/sba-user-accounts/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go"
	"gorm.io/gorm"
)

// TestServiceFactory tests the happy path scenarios for the ServiceFactory
func TestServiceFactory(t *testing.T) {
	// Helper to create a new PostgreSQL database container for testing
	createTestDB := func(t *testing.T) *gorm.DB {
		container, db, _ := createTestDBContainer(t)
		t.Cleanup(func() {
			if err := container.Terminate(context.Background()); err != nil {
				t.Logf("Failed to terminate container: %v", err)
			}
		})
		return db
	}

	// Test configuration
	testConfig := &config.Config{
		Server: config.ServerConfig{
			GRPCPort: "50051",
		},
		Auth: config.AuthConfig{
			JWTSecret:      []byte("test-secret"),
			TokenExpiryMin: 60,
		},
	}

	type testDependencies struct {
		db *gorm.DB
	}

	type testArgs struct {
		sf *ServiceFactory
	}

	type testCase struct {
		name      string
		deps      *testDependencies
		args      *testArgs
		before    func(t *testing.T, deps *testDependencies, args *testArgs)
		after     func(t *testing.T, deps *testDependencies, args *testArgs) error
		expect    func(t *testing.T, result any, err error)
		expectErr bool
	}

	tests := []testCase{
		{
			name: "NewServiceFactory initializes with default dependencies",
			deps: &testDependencies{},
			args: &testArgs{
				sf: NewServiceFactory(nil, testConfig),
			},
			after: func(t *testing.T, deps *testDependencies, args *testArgs) error {
				return nil
			},
			expect: func(t *testing.T, result any, err error) {
				sf := NewServiceFactory(nil, testConfig)
				assert.NotNil(t, sf.logger, "Logger should be initialized")
				assert.NotNil(t, sf.validator, "Validator should be initialized")
			},
			expectErr: false,
		},
		{
			name: "AutoMigrate success",
			deps: &testDependencies{
				db: createTestDB(t),
			},
			before: func(t *testing.T, deps *testDependencies, args *testArgs) {
				args.sf.db = deps.db
			},
			after: func(t *testing.T, deps *testDependencies, args *testArgs) error {
				return args.sf.AutoMigrate()
			},
			expect: func(t *testing.T, result any, err error) {
				assert.NoError(t, err, "AutoMigrate should not return an error")
			},
			expectErr: false,
		},
		{
			name: "InitializeRepositories initializes repositories",
			deps: &testDependencies{
				db: createTestDB(t),
			},
			before: func(t *testing.T, deps *testDependencies, args *testArgs) {
				args.sf.db = deps.db
			},
			after: func(t *testing.T, deps *testDependencies, args *testArgs) error {
				args.sf.InitializeRepositories()
				return nil
			},
			expect: func(t *testing.T, result any, err error) {
				sf := NewServiceFactory(nil, testConfig)
				sf.db = createTestDB(t)
				sf.InitializeRepositories()
				assert.NotNil(t, sf.userRepo, "User repository should be initialized")
				assert.NotNil(t, sf.authRepo, "Auth repository should be initialized")
			},
			expectErr: false,
		},
		{
			name: "InitializeServices initializes services",
			after: func(t *testing.T, deps *testDependencies, args *testArgs) error {
				args.sf.InitializeServices()
				return nil
			},
			expect: func(t *testing.T, result any, err error) {
				sf := NewServiceFactory(nil, testConfig)
				sf.InitializeServices()
				assert.NotNil(t, sf.tokenSvc, "Token service should be initialized")
				assert.NotNil(t, sf.emailSvc, "Email service should be initialized")
			},
			expectErr: false,
		},
		{
			name: "GetAuthService returns non-nil service",
			deps: &testDependencies{
				db: createTestDB(t),
			},
			before: func(t *testing.T, deps *testDependencies, args *testArgs) {
				args.sf.db = deps.db
				args.sf.InitializeRepositories()
				args.sf.InitializeServices()
			},
			after: func(t *testing.T, deps *testDependencies, args *testArgs) error {
				return nil
			},
			expect: func(t *testing.T, result any, err error) {
				sf := NewServiceFactory(nil, testConfig)
				sf.db = createTestDB(t)
				sf.InitializeRepositories()
				sf.InitializeServices()
				svc := sf.GetAuthService()
				assert.NotNil(t, svc, "Auth service should not be nil")
			},
			expectErr: false,
		},
		{
			name: "GetAccountManagementService returns non-nil service",
			deps: &testDependencies{
				db: createTestDB(t),
			},
			before: func(t *testing.T, deps *testDependencies, args *testArgs) {
				args.sf.db = deps.db
				args.sf.InitializeRepositories()
				args.sf.InitializeServices()
			},
			after: func(t *testing.T, deps *testDependencies, args *testArgs) error {
				return nil
			},
			expect: func(t *testing.T, result any, err error) {
				sf := NewServiceFactory(nil, testConfig)
				sf.db = createTestDB(t)
				sf.InitializeRepositories()
				sf.InitializeServices()
				svc := sf.GetAccountManagementService()
				assert.NotNil(t, svc, "Account management service should not be nil")
			},
			expectErr: false,
		},
		{
			name: "GetTokenService returns initialized token service",
			before: func(t *testing.T, deps *testDependencies, args *testArgs) {
				args.sf.InitializeServices()
			},
			after: func(t *testing.T, deps *testDependencies, args *testArgs) error {
				return nil
			},
			expect: func(t *testing.T, result any, err error) {
				sf := NewServiceFactory(nil, testConfig)
				sf.InitializeServices()
				svc := sf.GetTokenService()
				assert.NotNil(t, svc, "Token service should not be nil")
			},
			expectErr: false,
		},
		{
			name: "GetEmailService returns initialized email service",
			before: func(t *testing.T, deps *testDependencies, args *testArgs) {
				args.sf.InitializeServices()
			},
			after: func(t *testing.T, deps *testDependencies, args *testArgs) error {
				return nil
			},
			expect: func(t *testing.T, result any, err error) {
				sf := NewServiceFactory(nil, testConfig)
				sf.InitializeServices()
				svc := sf.GetEmailService()
				assert.NotNil(t, svc, "Email service should not be nil")
			},
			expectErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Initialize test case
			if tc.deps == nil {
				tc.deps = &testDependencies{}
			}
			if tc.args == nil {
				tc.args = &testArgs{
					sf: NewServiceFactory(nil, testConfig),
				}
			}

			// Setup
			if tc.before != nil {
				tc.before(t, tc.deps, tc.args)
			}

			// Execute
			var err error
			if tc.after != nil {
				err = tc.after(t, tc.deps, tc.args)
			}

			// Assert expectations
			if tc.expect != nil {
				tc.expect(t, nil, err)
			}

			// Check error expectation
			if tc.expectErr {
				assert.Error(t, err)
			} else if !tc.expectErr && err != nil {
				assert.NoError(t, err, "Unexpected error: %v", err)
			}
		})
	}
}

// TestServiceFactory_ErrorCases tests error scenarios for the ServiceFactory
func TestServiceFactory_ErrorCases(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	type testDependencies struct {
		container testcontainers.Container
		db        *gorm.DB
	}

	type testArgs struct {
		sf *ServiceFactory
	}

	tests := []struct {
		name      string
		deps      *testDependencies
		args      *testArgs
		before    func(t *testing.T, deps *testDependencies, args *testArgs)
		after     func(t *testing.T, deps *testDependencies, args *testArgs) error
		expect    func(t *testing.T, result any, err error)
		expectErr bool
	}{
		{
			name: "AutoMigrate fails with invalid migration model",
			after: func(t *testing.T, deps *testDependencies, args *testArgs) error {
				// Create a struct with an unsupported type to force migration failure
				type InvalidModel struct {
					ID   uint `gorm:"primarykey"`
					Data func()
				}
				return args.sf.db.AutoMigrate(&InvalidModel{})
			},
			expect: func(t *testing.T, result any, err error) {
				assert.Error(t, err, "AutoMigrate should fail with unsupported type")
			},
			expectErr: true,
		},
		{
			name: "GetAuthService returns service with nil repositories when not initialized",
			after: func(t *testing.T, deps *testDependencies, args *testArgs) error {
				// Just verify the service can be retrieved, actual checks are in expect
				args.sf.GetAuthService()
				return nil
			},
			expect: func(t *testing.T, result any, err error) {
				sf := result.(*ServiceFactory)
				svc := sf.GetAuthService()
				assert.NotNil(t, svc, "Auth service should not be nil")
				svcValue := reflect.ValueOf(svc).Elem()
				userRepo := svcValue.FieldByName("userRepo")
				assert.True(t, userRepo.IsZero(), "User repository should be zero value")
			},
			expectErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Initialize test case
			if tc.deps == nil {
				tc.deps = &testDependencies{}
			}
			if tc.args == nil {
				// Create container and DB for tests that need it
				container, db, dbURL := createTestDBContainer(t)
				if container == nil || db == nil || dbURL == "" {
					t.Fatal("Failed to create test DB container")
				}

				t.Cleanup(func() {
					if err := container.Terminate(context.Background()); err != nil {
						t.Logf("Failed to terminate container: %v", err)
					}
				})

				tc.deps.container = container
				tc.deps.db = db
				tc.args = &testArgs{
					sf: NewServiceFactory(db, testConfig),
				}
			}

			// Setup
			if tc.before != nil {
				tc.before(t, tc.deps, tc.args)
			}

			// Execute
			var err error
			if tc.after != nil {
				err = tc.after(t, tc.deps, tc.args)
			}

			// Assert expectations
			if tc.expect != nil {
				tc.expect(t, tc.args.sf, err)
			}

			// Check error expectation
			if tc.expectErr {
				assert.Error(t, err)
			} else if !tc.expectErr && err != nil {
				assert.NoError(t, err, "Unexpected error: %v", err)
			}
		})
	}
}
