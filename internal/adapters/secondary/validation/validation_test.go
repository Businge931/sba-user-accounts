package validation

import (
	"testing"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/stretchr/testify/assert"
)

func TestValidator_ValidateEmail(t *testing.T) {
	tests := []struct {
		name         string
		dependencies func() *testDependencies
		args         testArgs
		before       func()
		after        func()
		expect       func(*testing.T, error)
	}{
		{
			name: "valid email",
			dependencies: func() *testDependencies {
				return setupTest()
			},
			args: testArgs{
				email: "test@example.com",
			},
			expect: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "empty email",
			dependencies: func() *testDependencies {
				return setupTest()
			},
			args: testArgs{
				email: "",
			},
			expect: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "cannot be blank")
			},
		},
		{
			name: "invalid email format - missing @",
			dependencies: func() *testDependencies {
				return setupTest()
			},
			args: testArgs{
				email: "testexample.com",
			},
			expect: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "must be a valid email")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := tc.dependencies()
			if tc.before != nil {
				tc.before()
			}

			err := deps.validator.ValidateEmail(tc.args.email)

			if tc.after != nil {
				tc.after()
			}

			tc.expect(t, err)
		})
	}
}

func TestValidator_ValidatePassword(t *testing.T) {
	tests := []struct {
		name         string
		dependencies func() *testDependencies
		args         testArgs
		before       func()
		after        func()
		expect       func(*testing.T, error)
	}{
		{
			name: "valid password",
			dependencies: func() *testDependencies {
				return setupTest()
			},
			args: testArgs{
				password: "Password123!",
			},
			expect: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "empty password",
			dependencies: func() *testDependencies {
				return setupTest()
			},
			args: testArgs{
				password: "",
			},
			expect: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "cannot be blank")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := tc.dependencies()
			if tc.before != nil {
				tc.before()
			}

			err := deps.validator.ValidatePassword(tc.args.password)

			if tc.after != nil {
				tc.after()
			}

			tc.expect(t, err)
		})
	}
}

func TestValidator_ValidateRegisterRequest(t *testing.T) {
	tests := []struct {
		name         string
		dependencies func() *testDependencies
		setup        func() domain.RegisterRequest
		before       func()
		after        func()
		expect       func(*testing.T, error)
	}{
		{
			name:         "valid register request",
			dependencies: func() *testDependencies { return setupTest() },
			setup: func() domain.RegisterRequest {
				return domain.RegisterRequest{
					Email:     "test@example.com",
					Password:  "ValidPass123!",
					FirstName: "John",
					LastName:  "Doe",
				}
			},
			expect: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:         "invalid email format",
			dependencies: func() *testDependencies { return setupTest() },
			setup: func() domain.RegisterRequest {
				req := validRegisterRequest()
				req.Email = "invalid-email"
				return req
			},
			expect: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "must be a valid email")
			},
		},
		{
			name:         "missing all required fields",
			dependencies: func() *testDependencies { return setupTest() },
			setup:        func() domain.RegisterRequest { return domain.RegisterRequest{} },
			expect: func(t *testing.T, err error) {
				assert.Error(t, err)
				// Check that we have validation errors
				errMsg := err.Error()
				assert.Contains(t, errMsg, "cannot be blank")
			},
		},
		{
			name:         "password too short",
			dependencies: func() *testDependencies { return setupTest() },
			setup: func() domain.RegisterRequest {
				req := validRegisterRequest()
				req.Password = "short"
				return req
			},
			expect: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "the length must be between 8 and 72")
			},
		},
		{
			name:         "invalid first name format",
			dependencies: func() *testDependencies { return setupTest() },
			setup: func() domain.RegisterRequest {
				req := validRegisterRequest()
				req.FirstName = "John123"
				return req
			},
			expect: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "must be in a valid format")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := tc.dependencies()
			req := tc.setup()

			if tc.before != nil {
				tc.before()
			}

			err := deps.validator.ValidateRegisterRequest(req)

			if tc.after != nil {
				tc.after()
			}

			tc.expect(t, err)
		})
	}
}

func TestValidator_ValidateLoginRequest(t *testing.T) {
	tests := []struct {
		name         string
		dependencies func() *testDependencies
		setup        func() domain.LoginRequest
		before       func()
		after        func()
		expect       func(*testing.T, error)
	}{
		{
			name:         "valid login request",
			dependencies: func() *testDependencies { return setupTest() },
			setup: func() domain.LoginRequest {
				return domain.LoginRequest{
					Email:    "test@example.com",
					Password: "password123",
				}
			},
			expect: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:         "missing email",
			dependencies: func() *testDependencies { return setupTest() },
			setup: func() domain.LoginRequest {
				req := validLoginRequest()
				req.Email = ""
				return req
			},
			expect: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "cannot be blank")
			},
		},
		{
			name:         "missing password",
			dependencies: func() *testDependencies { return setupTest() },
			setup: func() domain.LoginRequest {
				req := validLoginRequest()
				req.Password = ""
				return req
			},
			expect: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "cannot be blank")
			},
		},
		{
			name:         "invalid email format",
			dependencies: func() *testDependencies { return setupTest() },
			setup: func() domain.LoginRequest {
				req := validLoginRequest()
				req.Email = "not-an-email"
				return req
			},
			expect: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "must be a valid email")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := tc.dependencies()
			req := tc.setup()

			if tc.before != nil {
				tc.before()
			}

			err := deps.validator.ValidateLoginRequest(req)

			if tc.after != nil {
				tc.after()
			}

			tc.expect(t, err)
		})
	}
}

func TestValidator_ValidateName(t *testing.T) {
	tests := []struct {
		name         string
		dependencies func() *testDependencies
		setup        func() (string, string) // returns name and fieldName
		before       func()
		after        func()
		expect       func(*testing.T, error)
	}{
		{
			name:         "valid name",
			dependencies: func() *testDependencies { return setupTest() },
			setup: func() (string, string) {
				return "John", "first_name"
			},
			expect: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:         "empty name",
			dependencies: func() *testDependencies { return setupTest() },
			setup: func() (string, string) {
				return "", "last_name"
			},
			expect: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "is required")
			},
		},
		{
			name:         "name too short",
			dependencies: func() *testDependencies { return setupTest() },
			setup: func() (string, string) {
				return "A", "username"
			},
			expect: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "must be between 2 and 50")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := tc.dependencies()
			name, fieldName := tc.setup()

			if tc.before != nil {
				tc.before()
			}

			err := deps.validator.ValidateName(name, fieldName)

			if tc.after != nil {
				tc.after()
			}

			tc.expect(t, err)
		})
	}
}

// Helper functions for test data
func validRegisterRequest() domain.RegisterRequest {
	return domain.RegisterRequest{
		Email:     "test@example.com",
		Password:  "ValidPass123!",
		FirstName: "John",
		LastName:  "Doe",
	}
}

func validLoginRequest() domain.LoginRequest {
	return domain.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}
}

type testDependencies struct {
	validator *Validator
}

type testArgs struct {
	email     string
	password  string
	firstName string
	lastName  string
	field     string
}

func setupTest() *testDependencies {
	return &testDependencies{
		validator: NewValidator(),
	}
}
