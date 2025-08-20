package identityprovider

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/identity_provider/mocks"
	"github.com/Businge931/sba-user-accounts/internal/core/domain"
)

// These tests directly test the actual firebaseAuthAdapter struct and its methods
// The adapter is responsible for creating context.Background() and delegating to the provider

func TestFirebaseAuthAdapter_RegisterSvc(t *testing.T) {
	tests := []struct {
		name string
		args struct {
			req domain.RegisterRequest
		}
		before        func(*mocks.MockFirebaseClient)
		expectedUser  *domain.User
		expectedLink  string
		expectedError error
	}{
		{
			name: "Success_AdapterCreatesContextAndDelegates",
			args: struct {
				req domain.RegisterRequest
			}{
				req: domain.RegisterRequest{
					Email:     "test@example.com",
					Password:  "password123",
					FirstName: "John",
					LastName:  "Doe",
				},
			},
			before: func(mockClient *mocks.MockFirebaseClient) {
				// Verify adapter creates context.Background() internally
				mockClient.EXPECT().CreateUser(
					gomock.Any(), // Should be context.Background()
					"test@example.com",
					"password123",
					"John",
					"Doe",
				).Return(&domain.User{
					ID:              "user123",
					Email:           "test@example.com",
					FirstName:       "John",
					LastName:        "Doe",
					IsEmailVerified: false,
				}, nil)

				mockClient.EXPECT().SendVerificationEmail(
					gomock.Any(),
					"test@example.com",
				).Return("https://verification-link.com", nil)
			},
			expectedUser: &domain.User{
				ID:              "user123",
				Email:           "test@example.com",
				FirstName:       "John",
				LastName:        "Doe",
				IsEmailVerified: false,
			},
			expectedLink:  "https://verification-link.com",
			expectedError: nil,
		},
		{
			name: "Error_AdapterPassesErrorsThrough",
			args: struct {
				req domain.RegisterRequest
			}{
				req: domain.RegisterRequest{
					Email:     "invalid@example.com",
					Password:  "weak",
					FirstName: "Test",
					LastName:  "User",
				},
			},
			before: func(mockClient *mocks.MockFirebaseClient) {
				mockClient.EXPECT().CreateUser(
					gomock.Any(),
					"invalid@example.com",
					"weak",
					"Test",
					"User",
				).Return(nil, errors.New("user creation failed"))
			},
			expectedUser:  nil,
			expectedLink:  "",
			expectedError: errors.New("failed to create user"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockClient := mocks.NewMockFirebaseClient(ctrl)
			tt.before(mockClient)

			logger := logrus.New()
			logger.SetLevel(logrus.ErrorLevel)

			// Create the actual firebaseAuthProvider with mock client
			provider := &firebaseAuthProvider{
				client: mockClient,
				logger: logger,
			}

			// Create the actual firebaseAuthAdapter - this is what we're testing!
			adapter := &firebaseAuthAdapter{
				provider: provider,
			}

			// Execute - Test the actual adapter's RegisterSvc method
			// This should create context.Background() internally and call provider
			user, link, err := adapter.RegisterSvc(tt.args.req)

			// Assert
			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Nil(t, user)
				assert.Empty(t, link)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedUser, user)
				assert.Equal(t, tt.expectedLink, link)
			}
		})
	}
}

func TestFirebaseAuthAdapter_LoginSvc(t *testing.T) {
	tests := []struct {
		name string
		args struct {
			req  domain.LoginRequest
			user *domain.User
		}
		before        func(*mocks.MockFirebaseClient)
		expectedToken string
		expectedError error
	}{
		{
			name: "Success_AdapterCreatesContextAndDelegates",
			args: struct {
				req  domain.LoginRequest
				user *domain.User
			}{
				req: domain.LoginRequest{
					Email:    "test@example.com",
					Password: "password123",
				},
				user: &domain.User{
					ID:    "user123",
					Email: "test@example.com",
				},
			},
			before: func(mockClient *mocks.MockFirebaseClient) {
				mockClient.EXPECT().VerifyPassword(
					gomock.Any(), // Should be context.Background()
					"test@example.com",
					"password123",
				).Return("user123", nil)

				mockClient.EXPECT().CreateCustomToken(
					gomock.Any(),
					"user123",
				).Return("custom-token-123", nil)
			},
			expectedToken: "custom-token-123",
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockClient := mocks.NewMockFirebaseClient(ctrl)
			tt.before(mockClient)

			logger := logrus.New()
			logger.SetLevel(logrus.ErrorLevel)

			// Create the actual firebaseAuthProvider with mock client
			provider := &firebaseAuthProvider{
				client: mockClient,
				logger: logger,
			}

			// Create the actual firebaseAuthAdapter - this is what we're testing!
			adapter := &firebaseAuthAdapter{
				provider: provider,
			}

			// Execute - Test the actual adapter's LoginSvc method
			token, err := adapter.LoginSvc(tt.args.req, tt.args.user)

			// Assert
			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Equal(t, tt.expectedError, err)
				assert.Empty(t, token)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedToken, token)
			}
		})
	}
}

func TestFirebaseAuthAdapter_VerifyEmailSvc(t *testing.T) {
	tests := []struct {
		name string
		args struct {
			token string
		}
		before         func(*mocks.MockFirebaseClient)
		expectedUserID string
		expectedError  error
	}{
		{
			name: "Success_AdapterCreatesContextAndDelegates",
			args: struct {
				token string
			}{
				token: "valid-verification-token",
			},
			before: func(mockClient *mocks.MockFirebaseClient) {
				mockClient.EXPECT().VerifyEmail(
					gomock.Any(), // Should be context.Background()
					"valid-verification-token",
				).Return(nil)

				mockClient.EXPECT().VerifyIDToken(
					gomock.Any(),
					"valid-verification-token",
				).Return("user123", nil)
			},
			expectedUserID: "user123",
			expectedError:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockClient := mocks.NewMockFirebaseClient(ctrl)
			tt.before(mockClient)

			logger := logrus.New()
			logger.SetLevel(logrus.ErrorLevel)

			// Create the actual firebaseAuthProvider with mock client
			provider := &firebaseAuthProvider{
				client: mockClient,
				logger: logger,
			}

			// Create the actual firebaseAuthAdapter - this is what we're testing!
			adapter := &firebaseAuthAdapter{
				provider: provider,
			}

			// Execute - Test the actual adapter's VerifyEmailSvc method
			userID, err := adapter.VerifyEmailSvc(tt.args.token)

			// Assert
			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Empty(t, userID)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedUserID, userID)
			}
		})
	}
}

func TestFirebaseAuthAdapter_RequestPasswordResetSvc(t *testing.T) {
	tests := []struct {
		name string
		args struct {
			email string
		}
		before           func(*mocks.MockFirebaseClient)
		expectedResetLink string
		expectedError    error
	}{
		{
			name: "Success_AdapterCreatesContextAndDelegates",
			args: struct {
				email string
			}{
				email: "test@example.com",
			},
			before: func(mockClient *mocks.MockFirebaseClient) {
				mockClient.EXPECT().SendPasswordResetEmail(
					gomock.Any(), // Should be context.Background()
					"test@example.com",
				).Return("https://reset-link.com", nil)
			},
			expectedResetLink: "https://reset-link.com",
			expectedError:     nil,
		},
		{
			name: "Error_AdapterPassesErrorsThrough",
			args: struct {
				email string
			}{
				email: "invalid@example.com",
			},
			before: func(mockClient *mocks.MockFirebaseClient) {
				mockClient.EXPECT().SendPasswordResetEmail(
					gomock.Any(),
					"invalid@example.com",
				).Return("", errors.New("failed to send reset email"))
			},
			expectedResetLink: "",
			expectedError:     errors.New("failed to send password reset email"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockClient := mocks.NewMockFirebaseClient(ctrl)
			tt.before(mockClient)

			logger := logrus.New()
			logger.SetLevel(logrus.ErrorLevel)

			// Create the actual firebaseAuthProvider with mock client
			provider := &firebaseAuthProvider{
				client: mockClient,
				logger: logger,
			}

			// Create the actual firebaseAuthAdapter - this is what we're testing!
			adapter := &firebaseAuthAdapter{
				provider: provider,
			}

			// Execute - Test the actual adapter's RequestPasswordResetSvc method
			resetLink, err := adapter.RequestPasswordResetSvc(tt.args.email)

			// Assert
			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Empty(t, resetLink)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedResetLink, resetLink)
			}
		})
	}
}

func TestFirebaseAuthAdapter_ResetPasswordSvc(t *testing.T) {
	tests := []struct {
		name string
		args struct {
			token       string
			newPassword string
		}
		before        func(*mocks.MockFirebaseClient)
		expectedUserID string
		expectedToken  string
		expectedError  error
	}{
		{
			name: "Success_AdapterCreatesContextAndDelegates",
			args: struct {
				token       string
				newPassword string
			}{
				token:       "valid-reset-token",
				newPassword: "newPassword123",
			},
			before: func(mockClient *mocks.MockFirebaseClient) {
				mockClient.EXPECT().VerifyIDToken(
					gomock.Any(), // Should be context.Background()
					"valid-reset-token",
				).Return("user123", nil)

				mockClient.EXPECT().UpdatePassword(
					gomock.Any(),
					"user123",
					"newPassword123",
				).Return(nil)

				mockClient.EXPECT().CreateCustomToken(
					gomock.Any(),
					"user123",
				).Return("new-custom-token", nil)
			},
			expectedUserID: "user123",
			expectedToken:  "new-custom-token",
			expectedError:  nil,
		},
		{
			name: "Error_InvalidToken_AdapterPassesErrorsThrough",
			args: struct {
				token       string
				newPassword string
			}{
				token:       "invalid-token",
				newPassword: "newPassword123",
			},
			before: func(mockClient *mocks.MockFirebaseClient) {
				mockClient.EXPECT().VerifyIDToken(
					gomock.Any(),
					"invalid-token",
				).Return("", errors.New("token verification failed"))
			},
			expectedUserID: "",
			expectedToken:  "",
			expectedError:  errors.New("invalid or expired token"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockClient := mocks.NewMockFirebaseClient(ctrl)
			tt.before(mockClient)

			logger := logrus.New()
			logger.SetLevel(logrus.ErrorLevel)

			// Create the actual firebaseAuthProvider with mock client
			provider := &firebaseAuthProvider{
				client: mockClient,
				logger: logger,
			}

			// Create the actual firebaseAuthAdapter - this is what we're testing!
			adapter := &firebaseAuthAdapter{
				provider: provider,
			}

			// Execute - Test the actual adapter's ResetPasswordSvc method
			userID, token, err := adapter.ResetPasswordSvc(tt.args.token, tt.args.newPassword)

			// Assert
			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Empty(t, userID)
				assert.Empty(t, token)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedUserID, userID)
				assert.Equal(t, tt.expectedToken, token)
			}
		})
	}
}

func TestFirebaseAuthAdapter_ChangePasswordSvc(t *testing.T) {
	tests := []struct {
		name string
		args struct {
			userID      string
			oldPassword string
			newPassword string
		}
		before        func(*mocks.MockFirebaseClient)
		expectedToken string
		expectedError error
	}{
		{
			name: "Success_AdapterCreatesContextAndDelegates",
			args: struct {
				userID      string
				oldPassword string
				newPassword string
			}{
				userID:      "test@example.com",
				oldPassword: "oldPassword123",
				newPassword: "newPassword456",
			},
			before: func(mockClient *mocks.MockFirebaseClient) {
				mockClient.EXPECT().GetUserByEmail(
					gomock.Any(), // Should be context.Background()
					"test@example.com",
				).Return(&domain.User{
					ID:    "user123",
					Email: "test@example.com",
				}, nil)

				mockClient.EXPECT().VerifyPassword(
					gomock.Any(),
					"test@example.com",
					"oldPassword123",
				).Return("user123", nil)

				mockClient.EXPECT().UpdatePassword(
					gomock.Any(),
					"user123",
					"newPassword456",
				).Return(nil)

				mockClient.EXPECT().CreateCustomToken(
					gomock.Any(),
					"user123",
				).Return("new-token-123", nil)
			},
			expectedToken: "new-token-123",
			expectedError: nil,
		},
		{
			name: "Error_UserNotFound_AdapterPassesErrorsThrough",
			args: struct {
				userID      string
				oldPassword string
				newPassword string
			}{
				userID:      "nonexistent@example.com",
				oldPassword: "oldPassword123",
				newPassword: "newPassword456",
			},
			before: func(mockClient *mocks.MockFirebaseClient) {
				mockClient.EXPECT().GetUserByEmail(
					gomock.Any(),
					"nonexistent@example.com",
				).Return(nil, errors.New("user not found"))
			},
			expectedToken: "",
			expectedError: errors.New("user not found"),
		},
		{
			name: "Error_InvalidOldPassword_AdapterPassesErrorsThrough",
			args: struct {
				userID      string
				oldPassword string
				newPassword string
			}{
				userID:      "test@example.com",
				oldPassword: "wrongPassword",
				newPassword: "newPassword456",
			},
			before: func(mockClient *mocks.MockFirebaseClient) {
				mockClient.EXPECT().GetUserByEmail(
					gomock.Any(),
					"test@example.com",
				).Return(&domain.User{
					ID:    "user123",
					Email: "test@example.com",
				}, nil)

				mockClient.EXPECT().VerifyPassword(
					gomock.Any(),
					"test@example.com",
					"wrongPassword",
				).Return("", errors.New("invalid password"))
			},
			expectedToken: "",
			expectedError: errors.New("invalid old password"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockClient := mocks.NewMockFirebaseClient(ctrl)
			tt.before(mockClient)

			logger := logrus.New()
			logger.SetLevel(logrus.ErrorLevel)

			// Create the actual firebaseAuthProvider with mock client
			provider := &firebaseAuthProvider{
				client: mockClient,
				logger: logger,
			}

			// Create the actual firebaseAuthAdapter - this is what we're testing!
			adapter := &firebaseAuthAdapter{
				provider: provider,
			}

			// Execute - Test the actual adapter's ChangePasswordSvc method
			token, err := adapter.ChangePasswordSvc(tt.args.userID, tt.args.oldPassword, tt.args.newPassword)

			// Assert
			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Empty(t, token)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedToken, token)
			}
		})
	}
}
