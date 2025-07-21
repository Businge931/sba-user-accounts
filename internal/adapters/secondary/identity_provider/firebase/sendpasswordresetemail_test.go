package firebase_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/identity_provider/firebase"
	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/identity_provider/firebase/mocks"
	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFirebaseClient_SendPasswordResetEmail(t *testing.T) {
	tests := []struct {
		name string
		deps struct {
			mockSDK    *mocks.MockFirebaseSDK
			mockAuth   *mocks.MockFirebaseAuth
			mockHTTP   *mocks.MockHTTPClient
			mockConfig *mocks.MockConfigProvider
		}
		args struct {
			ctx   context.Context
			email string
		}
		before func(deps struct {
			mockSDK    *mocks.MockFirebaseSDK
			mockAuth   *mocks.MockFirebaseAuth
			mockHTTP   *mocks.MockHTTPClient
			mockConfig *mocks.MockConfigProvider
		})
		expectedResult string
		expectedError  error
	}{
		{
			name: "Success_SendPasswordResetEmail",
			args: struct {
				ctx   context.Context
				email string
			}{
				ctx:   context.Background(),
				email: "user@example.com",
			},
			before: func(deps struct {
				mockSDK    *mocks.MockFirebaseSDK
				mockAuth   *mocks.MockFirebaseAuth
				mockHTTP   *mocks.MockHTTPClient
				mockConfig *mocks.MockConfigProvider
			}) {
				// Mock SDK.Auth() call
				deps.mockSDK.EXPECT().Auth(gomock.Any()).Return(deps.mockAuth, nil)

				// Mock successful password reset link generation
				deps.mockAuth.EXPECT().PasswordResetLink(gomock.Any(), "user@example.com").Return("https://example.com/reset?token=reset123", nil)
			},
			expectedResult: "https://example.com/reset?token=reset123",
			expectedError:  nil,
		},
		{
			name: "Success_SendPasswordResetEmailWithDifferentDomain",
			args: struct {
				ctx   context.Context
				email string
			}{
				ctx:   context.Background(),
				email: "admin@company.org",
			},
			before: func(deps struct {
				mockSDK    *mocks.MockFirebaseSDK
				mockAuth   *mocks.MockFirebaseAuth
				mockHTTP   *mocks.MockHTTPClient
				mockConfig *mocks.MockConfigProvider
			}) {
				// Mock SDK.Auth() call
				deps.mockSDK.EXPECT().Auth(gomock.Any()).Return(deps.mockAuth, nil)

				// Mock successful password reset link generation
				deps.mockAuth.EXPECT().PasswordResetLink(gomock.Any(), "admin@company.org").Return("https://myapp.firebase.com/reset?oobCode=resetXYZ789", nil)
			},
			expectedResult: "https://myapp.firebase.com/reset?oobCode=resetXYZ789",
			expectedError:  nil,
		},
		{
			name: "Error_SDKAuthFails",
			args: struct {
				ctx   context.Context
				email string
			}{
				ctx:   context.Background(),
				email: "user@example.com",
			},
			before: func(deps struct {
				mockSDK    *mocks.MockFirebaseSDK
				mockAuth   *mocks.MockFirebaseAuth
				mockHTTP   *mocks.MockHTTPClient
				mockConfig *mocks.MockConfigProvider
			}) {
				// Mock SDK.Auth() failure
				deps.mockSDK.EXPECT().Auth(gomock.Any()).Return(nil, errors.New("auth client error"))
			},
			expectedResult: "",
			expectedError:  errors.New("error getting auth client"),
		},
		{
			name: "Error_PasswordResetLinkFails",
			args: struct {
				ctx   context.Context
				email string
			}{
				ctx:   context.Background(),
				email: "nonexistent@example.com",
			},
			before: func(deps struct {
				mockSDK    *mocks.MockFirebaseSDK
				mockAuth   *mocks.MockFirebaseAuth
				mockHTTP   *mocks.MockHTTPClient
				mockConfig *mocks.MockConfigProvider
			}) {
				// Mock SDK.Auth() success
				deps.mockSDK.EXPECT().Auth(gomock.Any()).Return(deps.mockAuth, nil)
				// Mock password reset link generation failure
				deps.mockAuth.EXPECT().PasswordResetLink(gomock.Any(), "nonexistent@example.com").Return("", errors.New("user not found"))
			},
			expectedResult: "",
			expectedError:  errors.New("error generating password reset link"),
		},
		{
			name: "Error_InvalidEmailFormat",
			args: struct {
				ctx   context.Context
				email string
			}{
				ctx:   context.Background(),
				email: "invalid-email-format",
			},
			before: func(deps struct {
				mockSDK    *mocks.MockFirebaseSDK
				mockAuth   *mocks.MockFirebaseAuth
				mockHTTP   *mocks.MockHTTPClient
				mockConfig *mocks.MockConfigProvider
			}) {
				// Mock SDK.Auth() success
				deps.mockSDK.EXPECT().Auth(gomock.Any()).Return(deps.mockAuth, nil)
				// Mock password reset link generation failure for invalid email
				deps.mockAuth.EXPECT().PasswordResetLink(gomock.Any(), "invalid-email-format").Return("", errors.New("invalid email format"))
			},
			expectedResult: "",
			expectedError:  errors.New("error generating password reset link"),
		},
		{
			name: "Error_DisabledUser",
			args: struct {
				ctx   context.Context
				email string
			}{
				ctx:   context.Background(),
				email: "disabled@example.com",
			},
			before: func(deps struct {
				mockSDK    *mocks.MockFirebaseSDK
				mockAuth   *mocks.MockFirebaseAuth
				mockHTTP   *mocks.MockHTTPClient
				mockConfig *mocks.MockConfigProvider
			}) {
				// Mock SDK.Auth() success
				deps.mockSDK.EXPECT().Auth(gomock.Any()).Return(deps.mockAuth, nil)
				// Mock password reset link generation failure for disabled user
				deps.mockAuth.EXPECT().PasswordResetLink(gomock.Any(), "disabled@example.com").Return("", errors.New("user is disabled"))
			},
			expectedResult: "",
			expectedError:  errors.New("error generating password reset link"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Create mocks
			mockSDK := mocks.NewMockFirebaseSDK(ctrl)
			mockAuth := mocks.NewMockFirebaseAuth(ctrl)
			mockHTTP := mocks.NewMockHTTPClient(ctrl)
			mockConfig := mocks.NewMockConfigProvider(ctrl)

			// Set up dependencies
			tt.deps.mockSDK = mockSDK
			tt.deps.mockAuth = mockAuth
			tt.deps.mockHTTP = mockHTTP
			tt.deps.mockConfig = mockConfig

			// Execute before function
			if tt.before != nil {
				tt.before(tt.deps)
			}

			// Create client using test constructor
			logger := logrus.New()
			client := firebase.NewFirebaseClientForTesting(mockSDK, mockHTTP, mockConfig, logger)

			// Execute
			result, err := client.SendPasswordResetEmail(tt.args.ctx, tt.args.email)

			// Assert
			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Equal(t, tt.expectedResult, result)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedResult, result)
			}
		})
	}
}
