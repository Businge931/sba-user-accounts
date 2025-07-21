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

func TestFirebaseClient_CreateCustomToken(t *testing.T) {
	tests := []struct {
		name string
		deps struct {
			mockSDK    *mocks.MockFirebaseSDK
			mockAuth   *mocks.MockFirebaseAuth
			mockHTTP   *mocks.MockHTTPClient
			mockConfig *mocks.MockConfigProvider
		}
		args struct {
			ctx    context.Context
			userID string
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
			name: "Success_CreateCustomToken",
			args: struct {
				ctx    context.Context
				userID string
			}{
				ctx:    context.Background(),
				userID: "test-uid-123",
			},
			before: func(deps struct {
				mockSDK    *mocks.MockFirebaseSDK
				mockAuth   *mocks.MockFirebaseAuth
				mockHTTP   *mocks.MockHTTPClient
				mockConfig *mocks.MockConfigProvider
			}) {
				// Mock SDK.Auth() call
				deps.mockSDK.EXPECT().Auth(gomock.Any()).Return(deps.mockAuth, nil)

				// Mock successful custom token creation
				deps.mockAuth.EXPECT().CustomToken(gomock.Any(), "test-uid-123").Return("custom.jwt.token", nil)
			},
			expectedResult: "custom.jwt.token",
			expectedError:  nil,
		},
		{
			name: "Error_SDKAuthFails",
			args: struct {
				ctx    context.Context
				userID string
			}{
				ctx:    context.Background(),
				userID: "test-uid-456",
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
			name: "Error_CustomTokenCreationFails",
			args: struct {
				ctx    context.Context
				userID string
			}{
				ctx:    context.Background(),
				userID: "invalid-uid",
			},
			before: func(deps struct {
				mockSDK    *mocks.MockFirebaseSDK
				mockAuth   *mocks.MockFirebaseAuth
				mockHTTP   *mocks.MockHTTPClient
				mockConfig *mocks.MockConfigProvider
			}) {
				// Mock SDK.Auth() success
				deps.mockSDK.EXPECT().Auth(gomock.Any()).Return(deps.mockAuth, nil)
				// Mock custom token creation failure
				deps.mockAuth.EXPECT().CustomToken(gomock.Any(), "invalid-uid").Return("", errors.New("user not found"))
			},
			expectedResult: "",
			expectedError:  errors.New("error creating custom token"),
		},
		{
			name: "Error_EmptyUserID",
			args: struct {
				ctx    context.Context
				userID string
			}{
				ctx:    context.Background(),
				userID: "",
			},
			before: func(deps struct {
				mockSDK    *mocks.MockFirebaseSDK
				mockAuth   *mocks.MockFirebaseAuth
				mockHTTP   *mocks.MockHTTPClient
				mockConfig *mocks.MockConfigProvider
			}) {
				// Mock SDK.Auth() success
				deps.mockSDK.EXPECT().Auth(gomock.Any()).Return(deps.mockAuth, nil)
				// Mock custom token creation failure for empty UID
				deps.mockAuth.EXPECT().CustomToken(gomock.Any(), "").Return("", errors.New("uid cannot be empty"))
			},
			expectedResult: "",
			expectedError:  errors.New("error creating custom token"),
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
			result, err := client.CreateCustomToken(tt.args.ctx, tt.args.userID)

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
