package firebase_test

import (
	"context"
	"errors"
	"testing"

	"firebase.google.com/go/v4/auth"
	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/identity_provider/firebase"
	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/identity_provider/firebase/mocks"
	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFirebaseClient_VerifyEmail(t *testing.T) {
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
			token string
		}
		before func(deps struct {
			mockSDK    *mocks.MockFirebaseSDK
			mockAuth   *mocks.MockFirebaseAuth
			mockHTTP   *mocks.MockHTTPClient
			mockConfig *mocks.MockConfigProvider
		})
		expectedError error
	}{
		{
			name: "Success_VerifyEmail",
			args: struct {
				ctx   context.Context
				token string
			}{
				ctx:   context.Background(),
				token: "valid.verification.token",
			},
			before: func(deps struct {
				mockSDK    *mocks.MockFirebaseSDK
				mockAuth   *mocks.MockFirebaseAuth
				mockHTTP   *mocks.MockHTTPClient
				mockConfig *mocks.MockConfigProvider
			}) {
				// Mock SDK.Auth() call for token verification
				deps.mockSDK.EXPECT().Auth(gomock.Any()).Return(deps.mockAuth, nil)

				// Mock successful token verification
				mockToken := &auth.Token{
					UID: "test-uid-123",
					Claims: map[string]interface{}{
						"email": "user@example.com",
					},
				}
				deps.mockAuth.EXPECT().VerifyIDToken(gomock.Any(), "valid.verification.token").Return(mockToken, nil)

				// Mock successful user update to set email as verified
				mockUserRecord := &auth.UserRecord{
					UserInfo: &auth.UserInfo{
						UID:   "test-uid-123",
						Email: "user@example.com",
					},
					EmailVerified: true,
				}
				deps.mockAuth.EXPECT().UpdateUser(gomock.Any(), "test-uid-123", gomock.Any()).Return(mockUserRecord, nil)
			},
			expectedError: nil,
		},
		{
			name: "Error_SDKAuthFails",
			args: struct {
				ctx   context.Context
				token string
			}{
				ctx:   context.Background(),
				token: "some.token",
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
			expectedError: errors.New("error getting auth client"),
		},
		{
			name: "Error_InvalidToken",
			args: struct {
				ctx   context.Context
				token string
			}{
				ctx:   context.Background(),
				token: "invalid.verification.token",
			},
			before: func(deps struct {
				mockSDK    *mocks.MockFirebaseSDK
				mockAuth   *mocks.MockFirebaseAuth
				mockHTTP   *mocks.MockHTTPClient
				mockConfig *mocks.MockConfigProvider
			}) {
				// Mock SDK.Auth() success
				deps.mockSDK.EXPECT().Auth(gomock.Any()).Return(deps.mockAuth, nil)
				// Mock token verification failure
				deps.mockAuth.EXPECT().VerifyIDToken(gomock.Any(), "invalid.verification.token").Return(nil, errors.New("token verification failed"))
			},
			expectedError: errors.New("error verifying token"),
		},
		{
			name: "Error_ExpiredToken",
			args: struct {
				ctx   context.Context
				token string
			}{
				ctx:   context.Background(),
				token: "expired.verification.token",
			},
			before: func(deps struct {
				mockSDK    *mocks.MockFirebaseSDK
				mockAuth   *mocks.MockFirebaseAuth
				mockHTTP   *mocks.MockHTTPClient
				mockConfig *mocks.MockConfigProvider
			}) {
				// Mock SDK.Auth() success
				deps.mockSDK.EXPECT().Auth(gomock.Any()).Return(deps.mockAuth, nil)
				// Mock expired token error
				deps.mockAuth.EXPECT().VerifyIDToken(gomock.Any(), "expired.verification.token").Return(nil, errors.New("token has expired"))
			},
			expectedError: errors.New("error verifying token"),
		},
		{
			name: "Error_UpdateUserFails",
			args: struct {
				ctx   context.Context
				token string
			}{
				ctx:   context.Background(),
				token: "valid.token.but.update.fails",
			},
			before: func(deps struct {
				mockSDK    *mocks.MockFirebaseSDK
				mockAuth   *mocks.MockFirebaseAuth
				mockHTTP   *mocks.MockHTTPClient
				mockConfig *mocks.MockConfigProvider
			}) {
				// Mock SDK.Auth() success
				deps.mockSDK.EXPECT().Auth(gomock.Any()).Return(deps.mockAuth, nil)

				// Mock successful token verification
				mockToken := &auth.Token{
					UID: "test-uid-456",
					Claims: map[string]interface{}{
						"email": "user2@example.com",
					},
				}
				deps.mockAuth.EXPECT().VerifyIDToken(gomock.Any(), "valid.token.but.update.fails").Return(mockToken, nil)

				// Mock user update failure
				deps.mockAuth.EXPECT().UpdateUser(gomock.Any(), "test-uid-456", gomock.Any()).Return(nil, errors.New("user update failed"))
			},
			expectedError: errors.New("user update failed"),
		},
		{
			name: "Error_EmptyToken",
			args: struct {
				ctx   context.Context
				token string
			}{
				ctx:   context.Background(),
				token: "",
			},
			before: func(deps struct {
				mockSDK    *mocks.MockFirebaseSDK
				mockAuth   *mocks.MockFirebaseAuth
				mockHTTP   *mocks.MockHTTPClient
				mockConfig *mocks.MockConfigProvider
			}) {
				// Mock SDK.Auth() success
				deps.mockSDK.EXPECT().Auth(gomock.Any()).Return(deps.mockAuth, nil)
				// Mock token verification failure for empty token
				deps.mockAuth.EXPECT().VerifyIDToken(gomock.Any(), "").Return(nil, errors.New("token cannot be empty"))
			},
			expectedError: errors.New("error verifying token"),
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
			err := client.VerifyEmail(tt.args.ctx, tt.args.token)

			// Assert
			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
