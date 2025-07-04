package identity

import (
	"fmt"
	"testing"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/Businge931/sba-user-accounts/internal/core/services/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestIdentityProvider_LoginSvc(t *testing.T) {
	tests := []loginTestCase{
		{
			name: "successful login returns token",
			before: func(d *loginTestDependencies) {
				d.tokenSvc.On("GenerateToken", "123").
					Return("test.jwt.token", nil).
					Once()
				d.logger.On("Debugf", "User %s logged in successfully", mock.Anything).Maybe()
			},
			args: struct {
				req  domain.LoginRequest
				user *domain.User
			}{
				req: domain.LoginRequest{
					Email:    "test@example.com",
					Password: "correctpassword",
				},
				user: &domain.User{
					ID:             "123",
					Email:          "test@example.com",
					HashedPassword: testPasswordHash,
				},
			},
			after: func(t *testing.T, d *loginTestDependencies) {
				d.tokenSvc.AssertExpectations(t)
				d.logger.AssertExpectations(t)
			},
			want: "test.jwt.token",
		},
		{
			name: "returns error when user is nil",
			before: func(d *loginTestDependencies) {
				d.logger.On("Debugf", mock.Anything, mock.Anything).Maybe()
			},
			args: struct {
				req  domain.LoginRequest
				user *domain.User
			}{
				req: domain.LoginRequest{
					Email:    "nonexistent@example.com",
					Password: "anypassword",
				},
				user: nil,
			},
			after: func(t *testing.T, d *loginTestDependencies) {
				d.logger.AssertExpectations(t)
			},
			wantErr:  true,
			errorMsg: "user not found",
		},
		{
			name: "returns error when password is invalid",
			before: func(d *loginTestDependencies) {
				d.logger.On("Debugf", "Password comparison failed: %v", mock.Anything).Maybe()
			},
			args: struct {
				req  domain.LoginRequest
				user *domain.User
			}{
				req: domain.LoginRequest{
					Email:    "test@example.com",
					Password: "wrongpassword",
				},
				user: &domain.User{
					ID:             "123",
					Email:          "test@example.com",
					HashedPassword: testPasswordHash,
				},
			},
			after: func(t *testing.T, d *loginTestDependencies) {
				d.logger.AssertExpectations(t)
			},
			wantErr:  true,
			errorMsg: "invalid password",
		},
		{
			name: "returns error when token generation fails",
			before: func(d *loginTestDependencies) {
				d.tokenSvc.On("GenerateToken", "123").
					Return("", fmt.Errorf("token generation failed")).
					Once()
				d.logger.On("Debugf", "Token generation failed for user %s: %v", mock.Anything).Maybe()
				d.logger.On("Debugf", "Password comparison failed: %v", mock.Anything).Maybe()
			},
			args: struct {
				req  domain.LoginRequest
				user *domain.User
			}{
				req: domain.LoginRequest{
					Email:    "test@example.com",
					Password: "correctpassword",
				},
				user: &domain.User{
					ID:             "123",
					Email:          "test@example.com",
					HashedPassword: testPasswordHash, // Use the same test hash as other tests
				},
			},
			after: func(t *testing.T, d *loginTestDependencies) {
				d.tokenSvc.AssertExpectations(t)
				d.logger.AssertExpectations(t)
			},
			wantErr:  true,
			errorMsg: "failed to generate token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			svc, deps := setupLoginMocks(t)

			// Setup test-specific mocks
			if tt.before != nil {
				tt.before(deps)
			}

			// Execute the method under test
			token, err := svc.LoginSvc(tt.args.req, tt.args.user)

			// Verify the results
			if tt.wantErr {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, token)
			}

			// Verify mocks
			if tt.after != nil {
				tt.after(t, deps)
			}
		})
	}
}

// Generate a consistent bcrypt hash for testing
var testPasswordHash = mustHashPassword("correctpassword")

// Helper function to generate a bcrypt hash for testing
func mustHashPassword(password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		panic(fmt.Sprintf("failed to hash password: %v", err))
	}
	return string(hash)
}

func setupLoginMocks(*testing.T) (*identityProvider, *loginTestDependencies) {
	tokenSvc := new(mocks.MockTokenService)
	logger := new(mocks.MockLogger)

	// Create service with authRepo and userRepo set to nil since they're not used in LoginSvc
	svc := NewIdentityProvider(nil, nil, tokenSvc, logger).(*identityProvider)

	return svc, &loginTestDependencies{
		svc:      svc,
		tokenSvc: tokenSvc,
		logger:   logger,
	}
}
