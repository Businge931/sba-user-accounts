package identity

import (
	"errors"
	"testing"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/Businge931/sba-user-accounts/internal/core/services/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestIdentityProvider_RegisterSvc(t *testing.T) {
	tests := []registerTestCase{
		{
			name: "successful registration with password hashing and token generation",
			dependencies: struct {
				authRepoMocks func(*mocks.MockAuthRepository)
				userRepoMocks func(*mocks.MockUserRepository)
				tokenSvcMocks func(*mocks.MockTokenService)
				loggerMocks   func(*mocks.MockLogger)
			}{
				tokenSvcMocks: func(ts *mocks.MockTokenService) {
					ts.On("GenerateVerificationToken").Return("test-verification-token").Once()
				},
				authRepoMocks: func(ar *mocks.MockAuthRepository) {
					ar.On("StoreVerificationToken", mock.AnythingOfType("string"), "test-verification-token").
						Return(nil).Once()
				},
				loggerMocks: func(l *mocks.MockLogger) {
					l.On("Warnf", mock.Anything, mock.Anything).Maybe()
				},
			},
			args: struct{ req domain.RegisterRequest }{
				req: domain.RegisterRequest{
					Email:     "test@example.com",
					Password:  "ValidPass123",
					FirstName: "John",
					LastName:  "Doe",
				},
			},
			after: func(t *testing.T, deps *registerTestDependencies) {
				// Verify all expected calls were made
				deps.tokenSvc.AssertExpectations(t)
				deps.authRepo.AssertExpectations(t)
				deps.userRepo.AssertExpectations(t)
			},
			want: &domain.User{
				Email:     "test@example.com",
				FirstName: "John",
				LastName:  "Doe",
			},
		},
		{
			name: "handles token storage error gracefully",
			dependencies: struct {
				authRepoMocks func(*mocks.MockAuthRepository)
				userRepoMocks func(*mocks.MockUserRepository)
				tokenSvcMocks func(*mocks.MockTokenService)
				loggerMocks   func(*mocks.MockLogger)
			}{
				tokenSvcMocks: func(ts *mocks.MockTokenService) {
					ts.On("GenerateVerificationToken").Return("test-token").Once()
				},
				authRepoMocks: func(ar *mocks.MockAuthRepository) {
					ar.On("StoreVerificationToken", mock.AnythingOfType("string"), "test-token").
						Return(errors.New("token storage error")).Once()
				},
				userRepoMocks: func(ur *mocks.MockUserRepository) {
					ur.On("CreateUser", mock.AnythingOfType("*domain.User")).Return(nil).Once()
				},
				loggerMocks: func(l *mocks.MockLogger) {
					l.On("Warnf", "Failed to store verification token for user %s: %v", mock.Anything).Once()
					l.On("Warnf", mock.Anything, mock.Anything).Maybe()
				},
			},
			args: struct{ req domain.RegisterRequest }{
				req: domain.RegisterRequest{
					Email:     "test@example.com",
					Password:  "ValidPass123",
					FirstName: "John",
					LastName:  "Doe",
				},
			},
			want: &domain.User{
				Email:     "test@example.com",
				FirstName: "John",
				LastName:  "Doe",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			svc, deps := setupRegisterMocks(t)

			// Apply test-specific mocks
			if tt.dependencies.authRepoMocks != nil {
				tt.dependencies.authRepoMocks(deps.authRepo)
			}
			if tt.dependencies.userRepoMocks != nil {
				tt.dependencies.userRepoMocks(deps.userRepo)
			}
			if tt.dependencies.tokenSvcMocks != nil {
				tt.dependencies.tokenSvcMocks(deps.tokenSvc)
			}
			if tt.dependencies.loggerMocks != nil {
				tt.dependencies.loggerMocks(deps.logger)
			}

			// Execute before hook if exists
			if tt.before != nil {
				tt.before(t, deps)
			}

			// Execute the method under test
			user, err := svc.RegisterSvc(tt.args.req)

			// Verify the results
			if tt.wantErr {
				require.Error(t, err)
				if tt.err != nil {
					assert.Equal(t, tt.err, err)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, user)

				// Verify basic user fields
				assert.Equal(t, tt.want.Email, user.Email)
				assert.Equal(t, tt.want.FirstName, user.FirstName)
				assert.Equal(t, tt.want.LastName, user.LastName)

				// Verify password was hashed
				hashErr := bcrypt.CompareHashAndPassword(
					[]byte(user.HashedPassword),
					[]byte(tt.args.req.Password),
				)
				assert.NoError(t, hashErr, "password should be properly hashed")
			}

			// Execute after hook if exists (for assertions)
			if tt.after != nil {
				tt.after(t, deps)
			}
		})
	}
}
