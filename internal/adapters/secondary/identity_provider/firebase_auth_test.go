package identityprovider_test

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identityprovider "github.com/Businge931/sba-user-accounts/internal/adapters/secondary/identity_provider"
	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/identity_provider/mocks"
	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	dcerrors "github.com/Businge931/sba-user-accounts/internal/core/errors"
)

func TestFirebaseAuthProvider_RegisterSvc(t *testing.T) {
	tests := []struct {
		name string
		args struct {
			ctx context.Context
			req domain.RegisterRequest
		}
		before    func(*mocks.MockFirebaseClient)
		expectedUser  *domain.User
		expectedLink  string
		expectedError error
	}{
		{
			name: "Success_RegisterUser",
			args: struct {
				ctx context.Context
				req domain.RegisterRequest
			}{
				ctx: context.Background(),
				req: domain.RegisterRequest{
					Email:     "test@example.com",
					Password:  "password123",
					FirstName: "John",
					LastName:  "Doe",
				},
			},
			before: func(mockClient *mocks.MockFirebaseClient) {
				mockClient.EXPECT().CreateUser(
					gomock.Any(),
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
			name: "Success_RegisterUserWithVerificationEmailFailure",
			args: struct {
				ctx context.Context
				req domain.RegisterRequest
			}{
				ctx: context.Background(),
				req: domain.RegisterRequest{
					Email:     "test@example.com",
					Password:  "password123",
					FirstName: "Jane",
					LastName:  "Smith",
				},
			},
			before: func(mockClient *mocks.MockFirebaseClient) {
				mockClient.EXPECT().CreateUser(
					gomock.Any(),
					"test@example.com",
					"password123",
					"Jane",
					"Smith",
				).Return(&domain.User{
					ID:              "user456",
					Email:           "test@example.com",
					FirstName:       "Jane",
					LastName:        "Smith",
					IsEmailVerified: false,
				}, nil)

				mockClient.EXPECT().SendVerificationEmail(
					gomock.Any(),
					"test@example.com",
				).Return("", errors.New("email service error"))
			},
			expectedUser: &domain.User{
				ID:              "user456",
				Email:           "test@example.com",
				FirstName:       "Jane",
				LastName:        "Smith",
				IsEmailVerified: false,
			},
			expectedLink:  "", // Empty link due to email failure
			expectedError: nil,  // Should still succeed despite email failure
		},
		{
			name: "Error_CreateUserFails",
			args: struct {
				ctx context.Context
				req domain.RegisterRequest
			}{
				ctx: context.Background(),
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
			// Setup
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockClient := mocks.NewMockFirebaseClient(ctrl)
			tt.before(mockClient)

			logger := logrus.New()
			logger.SetLevel(logrus.ErrorLevel) // Reduce noise in tests
			provider := identityprovider.NewFirebaseAuthProviderForTesting(mockClient, logger)

			// Execute
			user, link, err := provider.RegisterSvc(tt.args.ctx, tt.args.req)

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

func TestFirebaseAuthProvider_LoginSvc(t *testing.T) {
	tests := []struct {
		name string
		args struct {
			ctx  context.Context
			req  domain.LoginRequest
			user *domain.User
		}
		before    func(*mocks.MockFirebaseClient)
		expectedToken string
		expectedError error
	}{
		{
			name: "Success_LoginUser",
			args: struct {
				ctx  context.Context
				req  domain.LoginRequest
				user *domain.User
			}{
				ctx: context.Background(),
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
					gomock.Any(),
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
		{
			name: "Error_NilUser",
			args: struct {
				ctx  context.Context
				req  domain.LoginRequest
				user *domain.User
			}{
				ctx: context.Background(),
				req: domain.LoginRequest{
					Email:    "test@example.com",
					Password: "password123",
				},
				user: nil,
			},
			before:    func(mockClient *mocks.MockFirebaseClient) {},
			expectedToken: "",
			expectedError: dcerrors.ErrInvalidAuth,
		},
		{
			name: "Error_PasswordVerificationFails",
			args: struct {
				ctx  context.Context
				req  domain.LoginRequest
				user *domain.User
			}{
				ctx: context.Background(),
				req: domain.LoginRequest{
					Email:    "test@example.com",
					Password: "wrongpassword",
				},
				user: &domain.User{
					ID:    "user123",
					Email: "test@example.com",
				},
			},
			before: func(mockClient *mocks.MockFirebaseClient) {
				mockClient.EXPECT().VerifyPassword(
					gomock.Any(),
					"test@example.com",
					"wrongpassword",
				).Return("", errors.New("invalid password"))
			},
			expectedToken: "",
			expectedError: dcerrors.ErrInvalidAuth,
		},
		{
			name: "Error_UserIDMismatch",
			args: struct {
				ctx  context.Context
				req  domain.LoginRequest
				user *domain.User
			}{
				ctx: context.Background(),
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
					gomock.Any(),
					"test@example.com",
					"password123",
				).Return("different-user-id", nil)
			},
			expectedToken: "",
			expectedError: dcerrors.ErrInternal,
		},
		{
			name: "Error_CustomTokenCreationFails",
			args: struct {
				ctx  context.Context
				req  domain.LoginRequest
				user *domain.User
			}{
				ctx: context.Background(),
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
					gomock.Any(),
					"test@example.com",
					"password123",
				).Return("user123", nil)

				mockClient.EXPECT().CreateCustomToken(
					gomock.Any(),
					"user123",
				).Return("", errors.New("token creation failed"))
			},
			expectedToken: "",
			expectedError: dcerrors.ErrInternal,
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
			provider := identityprovider.NewFirebaseAuthProviderForTesting(mockClient, logger)

			// Execute
			token, err := provider.LoginSvc(tt.args.ctx, tt.args.req, tt.args.user)

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

func TestFirebaseAuthProvider_VerifyEmailSvc(t *testing.T) {
	tests := []struct {
		name string
		args struct {
			ctx   context.Context
			token string
		}
		before     func(*mocks.MockFirebaseClient)
		expectedUserID string
		expectedError  error
	}{
		{
			name: "Success_VerifyEmail",
			args: struct {
				ctx   context.Context
				token string
			}{
				ctx:   context.Background(),
				token: "valid-verification-token",
			},
			before: func(mockClient *mocks.MockFirebaseClient) {
				mockClient.EXPECT().VerifyEmail(
					gomock.Any(),
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
		{
			name: "Error_VerifyEmailFails",
			args: struct {
				ctx   context.Context
				token string
			}{
				ctx:   context.Background(),
				token: "invalid-verification-token",
			},
			before: func(mockClient *mocks.MockFirebaseClient) {
				mockClient.EXPECT().VerifyEmail(
					gomock.Any(),
					"invalid-verification-token",
				).Return(errors.New("invalid token"))
			},
			expectedUserID: "",
			expectedError:  errors.New("invalid or expired verification token"),
		},
		{
			name: "Error_VerifyIDTokenFails",
			args: struct {
				ctx   context.Context
				token string
			}{
				ctx:   context.Background(),
				token: "valid-verification-but-invalid-id-token",
			},
			before: func(mockClient *mocks.MockFirebaseClient) {
				mockClient.EXPECT().VerifyEmail(
					gomock.Any(),
					"valid-verification-but-invalid-id-token",
				).Return(nil)

				mockClient.EXPECT().VerifyIDToken(
					gomock.Any(),
					"valid-verification-but-invalid-id-token",
				).Return("", errors.New("invalid ID token"))
			},
			expectedUserID: "",
			expectedError:  errors.New("invalid token"),
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
			provider := identityprovider.NewFirebaseAuthProviderForTesting(mockClient, logger)

			// Execute
			userID, err := provider.VerifyEmailSvc(tt.args.ctx, tt.args.token)

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

func TestFirebaseAuthProvider_RequestPasswordResetSvc(t *testing.T) {
	tests := []struct {
		name string
		args struct {
			ctx   context.Context
			email string
		}
		before    func(*mocks.MockFirebaseClient)
		expectedLink  string
		expectedError error
	}{
		{
			name: "Success_RequestPasswordReset",
			args: struct {
				ctx   context.Context
				email string
			}{
				ctx:   context.Background(),
				email: "test@example.com",
			},
			before: func(mockClient *mocks.MockFirebaseClient) {
				mockClient.EXPECT().SendPasswordResetEmail(
					gomock.Any(),
					"test@example.com",
				).Return("https://reset-link.com", nil)
			},
			expectedLink:  "https://reset-link.com",
			expectedError: nil,
		},
		{
			name: "Error_SendPasswordResetEmailFails",
			args: struct {
				ctx   context.Context
				email string
			}{
				ctx:   context.Background(),
				email: "nonexistent@example.com",
			},
			before: func(mockClient *mocks.MockFirebaseClient) {
				mockClient.EXPECT().SendPasswordResetEmail(
					gomock.Any(),
					"nonexistent@example.com",
				).Return("", errors.New("user not found"))
			},
			expectedLink:  "",
			expectedError: errors.New("failed to send password reset email"),
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
			provider := identityprovider.NewFirebaseAuthProviderForTesting(mockClient, logger)

			// Execute
			link, err := provider.RequestPasswordResetSvc(tt.args.ctx, tt.args.email)

			// Assert
			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Empty(t, link)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedLink, link)
			}
		})
	}
}

func TestFirebaseAuthProvider_ResetPasswordSvc(t *testing.T) {
	tests := []struct {
		name string
		args struct {
			ctx         context.Context
			token       string
			newPassword string
		}
		before     func(*mocks.MockFirebaseClient)
		expectedUserID string
		expectedToken  string
		expectedError  error
	}{
		{
			name: "Success_ResetPassword",
			args: struct {
				ctx         context.Context
				token       string
				newPassword string
			}{
				ctx:         context.Background(),
				token:       "valid-reset-token",
				newPassword: "newpassword123",
			},
			before: func(mockClient *mocks.MockFirebaseClient) {
				mockClient.EXPECT().VerifyIDToken(
					gomock.Any(),
					"valid-reset-token",
				).Return("user123", nil)

				mockClient.EXPECT().UpdatePassword(
					gomock.Any(),
					"user123",
					"newpassword123",
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
			name: "Error_InvalidToken",
			args: struct {
				ctx         context.Context
				token       string
				newPassword string
			}{
				ctx:         context.Background(),
				token:       "invalid-reset-token",
				newPassword: "newpassword123",
			},
			before: func(mockClient *mocks.MockFirebaseClient) {
				mockClient.EXPECT().VerifyIDToken(
					gomock.Any(),
					"invalid-reset-token",
				).Return("", errors.New("invalid token"))
			},
			expectedUserID: "",
			expectedToken:  "",
			expectedError:  errors.New("invalid or expired token"),
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
			provider := identityprovider.NewFirebaseAuthProviderForTesting(mockClient, logger)

			// Execute
			userID, token, err := provider.ResetPasswordSvc(tt.args.ctx, tt.args.token, tt.args.newPassword)

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

func TestFirebaseAuthProvider_ChangePasswordSvc(t *testing.T) {
	tests := []struct {
		name string
		args struct {
			ctx         context.Context
			userID      string
			oldPassword string
			newPassword string
		}
		before    func(*mocks.MockFirebaseClient)
		expectedToken string
		expectedError error
	}{
		{
			name: "Success_ChangePassword",
			args: struct {
				ctx         context.Context
				userID      string
				oldPassword string
				newPassword string
			}{
				ctx:         context.Background(),
				userID:      "test@example.com", // Using email as ID
				oldPassword: "oldpassword123",
				newPassword: "newpassword456",
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
					"oldpassword123",
				).Return("user123", nil)

				mockClient.EXPECT().UpdatePassword(
					gomock.Any(),
					"user123",
					"newpassword456",
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
			name: "Error_UserNotFound",
			args: struct {
				ctx         context.Context
				userID      string
				oldPassword string
				newPassword string
			}{
				ctx:         context.Background(),
				userID:      "nonexistent@example.com",
				oldPassword: "oldpassword123",
				newPassword: "newpassword456",
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
			provider := identityprovider.NewFirebaseAuthProviderForTesting(mockClient, logger)

			// Execute
			token, err := provider.ChangePasswordSvc(tt.args.ctx, tt.args.userID, tt.args.oldPassword, tt.args.newPassword)

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
