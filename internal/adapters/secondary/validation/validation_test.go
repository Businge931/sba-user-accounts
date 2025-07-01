package validation

import (
	"testing"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/stretchr/testify/assert"
)

func TestValidator_ValidateEmail(t *testing.T) {
	tests := []emailTestCase{
		{
			baseTestCase: baseTestCase{
				name: "valid email",
			},
			args: testArgs{
				email: "test@example.com",
			},
			expect: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			baseTestCase: baseTestCase{
				name: "empty email",
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
			baseTestCase: baseTestCase{
				name: "invalid email format - missing @",
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
			tc.deps = setupTestDeps()
			if tc.before != nil {
				tc.before()
			}

			err := tc.deps.validator.ValidateEmail(tc.args.email)

			if tc.after != nil {
				tc.after()
			}

			tc.expect(t, err)
		})
	}
}

func TestValidator_ValidatePassword(t *testing.T) {
	tests := []passwordTestCase{
		{
			baseTestCase: baseTestCase{
				name: "valid password",
			},
			args: testArgs{
				password: "Password123!",
			},
			expect: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			baseTestCase: baseTestCase{
				name: "empty password",
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
			tc.deps = setupTestDeps()
			if tc.before != nil {
				tc.before()
			}

			err := tc.deps.validator.ValidatePassword(tc.args.password)

			if tc.after != nil {
				tc.after()
			}

			tc.expect(t, err)
		})
	}
}

func TestValidator_ValidateRegisterRequest(t *testing.T) {
	tests := []registerTestCase{
		{
			baseTestCase: baseTestCase{
				name: "valid register request",
			},
			setup: func() domain.RegisterRequest {
				return validRegisterRequest()
			},
			expect: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			baseTestCase: baseTestCase{
				name: "invalid email format",
			},
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
			baseTestCase: baseTestCase{
				name: "missing all required fields",
			},
			setup: func() domain.RegisterRequest { return domain.RegisterRequest{} },
			expect: func(t *testing.T, err error) {
				assert.Error(t, err)
				errMsg := err.Error()
				assert.Contains(t, errMsg, "cannot be blank")
			},
		},
		{
			baseTestCase: baseTestCase{
				name: "password too short",
			},
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
			baseTestCase: baseTestCase{
				name: "invalid first name format",
			},
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
			tc.deps = setupTestDeps()
			req := tc.setup()

			if tc.before != nil {
				tc.before()
			}

			err := tc.deps.validator.ValidateRegisterRequest(req)

			if tc.after != nil {
				tc.after()
			}

			tc.expect(t, err)
		})
	}
}

func TestValidator_ValidateLoginRequest(t *testing.T) {
	tests := []loginTestCase{
		{
			baseTestCase: baseTestCase{
				name: "valid login request",
			},
			setup: func() domain.LoginRequest {
				return validLoginRequest()
			},
			expect: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			baseTestCase: baseTestCase{
				name: "missing email",
			},
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
			baseTestCase: baseTestCase{
				name: "missing password",
			},
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
			baseTestCase: baseTestCase{
				name: "invalid email format",
			},
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
			tc.deps = setupTestDeps()
			req := tc.setup()

			if tc.before != nil {
				tc.before()
			}

			err := tc.deps.validator.ValidateLoginRequest(req)

			if tc.after != nil {
				tc.after()
			}

			tc.expect(t, err)
		})
	}
}

func TestValidator_ValidateName(t *testing.T) {
	tests := []nameTestCase{
		{
			baseTestCase: baseTestCase{
				name: "valid name",
			},
			setup: func() (string, string) {
				return "John", "first_name"
			},
			expect: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			baseTestCase: baseTestCase{
				name: "empty name",
			},
			setup: func() (string, string) {
				return "", "last_name"
			},
			expect: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "is required")
			},
		},
		{
			baseTestCase: baseTestCase{
				name: "name too short",
			},
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
			tc.deps = setupTestDeps()
			name, fieldName := tc.setup()

			if tc.before != nil {
				tc.before()
			}

			err := tc.deps.validator.ValidateName(name, fieldName)

			if tc.after != nil {
				tc.after()
			}

			tc.expect(t, err)
		})
	}
}

// Test dependencies and helpers
type testDeps struct {
	validator *Validator
}

type testArgs struct {
	email    string
	password string
}

func setupTestDeps() *testDeps {
	return &testDeps{
		validator: NewValidator(),
	}
}

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

// Test case structures
type baseTestCase struct {
	name   string
	deps   *testDeps
	before func()
	after  func()
}

type emailTestCase struct {
	baseTestCase
	args   testArgs
	expect func(*testing.T, error)
}

type passwordTestCase struct {
	baseTestCase
	args   testArgs
	expect func(*testing.T, error)
}

type registerTestCase struct {
	baseTestCase
	setup  func() domain.RegisterRequest
	expect func(*testing.T, error)
}

type loginTestCase struct {
	baseTestCase
	setup  func() domain.LoginRequest
	expect func(*testing.T, error)
}

type nameTestCase struct {
	baseTestCase
	setup  func() (string, string)
	expect func(*testing.T, error)
}
