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

func TestFirebaseClient_UpdateUser(t *testing.T) {
	tests := []struct {
		name string
		deps struct {
			mockSDK    *mocks.MockFirebaseSDK
			mockAuth   *mocks.MockFirebaseAuth
			mockHTTP   *mocks.MockHTTPClient
			mockConfig *mocks.MockConfigProvider
		}
		args struct {
			ctx     context.Context
			userID  string
			updates map[string]any
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
			name: "Success_UpdateUserEmail",
			args: struct {
				ctx     context.Context
				userID  string
				updates map[string]any
			}{
				ctx:    context.Background(),
				userID: "test-uid-123",
				updates: map[string]any{
					"email": "newemail@example.com",
				},
			},
			before: func(deps struct {
				mockSDK    *mocks.MockFirebaseSDK
				mockAuth   *mocks.MockFirebaseAuth
				mockHTTP   *mocks.MockHTTPClient
				mockConfig *mocks.MockConfigProvider
			}) {
				// Mock SDK.Auth() call
				deps.mockSDK.EXPECT().Auth(gomock.Any()).Return(deps.mockAuth, nil)

				// Mock successful user update
				mockUserRecord := &auth.UserRecord{
					UserInfo: &auth.UserInfo{
						UID:   "test-uid-123",
						Email: "newemail@example.com",
					},
				}
				deps.mockAuth.EXPECT().UpdateUser(gomock.Any(), "test-uid-123", gomock.Any()).Return(mockUserRecord, nil)
			},
			expectedError: nil,
		},
		{
			name: "Success_UpdateUserPassword",
			args: struct {
				ctx     context.Context
				userID  string
				updates map[string]any
			}{
				ctx:    context.Background(),
				userID: "test-uid-456",
				updates: map[string]any{
					"password": "newpassword123",
				},
			},
			before: func(deps struct {
				mockSDK    *mocks.MockFirebaseSDK
				mockAuth   *mocks.MockFirebaseAuth
				mockHTTP   *mocks.MockHTTPClient
				mockConfig *mocks.MockConfigProvider
			}) {
				// Mock SDK.Auth() call
				deps.mockSDK.EXPECT().Auth(gomock.Any()).Return(deps.mockAuth, nil)

				// Mock successful password update
				mockUserRecord := &auth.UserRecord{
					UserInfo: &auth.UserInfo{
						UID: "test-uid-456",
					},
				}
				deps.mockAuth.EXPECT().UpdateUser(gomock.Any(), "test-uid-456", gomock.Any()).Return(mockUserRecord, nil)
			},
			expectedError: nil,
		},
		{
			name: "Success_UpdateUserMultipleFields",
			args: struct {
				ctx     context.Context
				userID  string
				updates map[string]any
			}{
				ctx:    context.Background(),
				userID: "test-uid-789",
				updates: map[string]any{
					"email":         "updated@example.com",
					"displayName":   "Updated Name",
					"emailVerified": true,
					"disabled":      false,
				},
			},
			before: func(deps struct {
				mockSDK    *mocks.MockFirebaseSDK
				mockAuth   *mocks.MockFirebaseAuth
				mockHTTP   *mocks.MockHTTPClient
				mockConfig *mocks.MockConfigProvider
			}) {
				// Mock SDK.Auth() call
				deps.mockSDK.EXPECT().Auth(gomock.Any()).Return(deps.mockAuth, nil)

				// Mock successful multiple field update
				mockUserRecord := &auth.UserRecord{
					UserInfo: &auth.UserInfo{
						UID:         "test-uid-789",
						Email:       "updated@example.com",
						DisplayName: "Updated Name",
					},
					EmailVerified: true,
					Disabled:      false,
				}
				deps.mockAuth.EXPECT().UpdateUser(gomock.Any(), "test-uid-789", gomock.Any()).Return(mockUserRecord, nil)
			},
			expectedError: nil,
		},
		{
			name: "Error_SDKAuthFails",
			args: struct {
				ctx     context.Context
				userID  string
				updates map[string]any
			}{
				ctx:    context.Background(),
				userID: "test-uid-123",
				updates: map[string]any{
					"email": "test@example.com",
				},
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
			name: "Error_UpdateUserFails",
			args: struct {
				ctx     context.Context
				userID  string
				updates map[string]any
			}{
				ctx:    context.Background(),
				userID: "invalid-uid",
				updates: map[string]any{
					"email": "test@example.com",
				},
			},
			before: func(deps struct {
				mockSDK    *mocks.MockFirebaseSDK
				mockAuth   *mocks.MockFirebaseAuth
				mockHTTP   *mocks.MockHTTPClient
				mockConfig *mocks.MockConfigProvider
			}) {
				// Mock SDK.Auth() success
				deps.mockSDK.EXPECT().Auth(gomock.Any()).Return(deps.mockAuth, nil)
				// Mock UpdateUser failure
				deps.mockAuth.EXPECT().UpdateUser(gomock.Any(), "invalid-uid", gomock.Any()).Return(nil, errors.New("user not found"))
			},
			expectedError: errors.New("user not found"),
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
			err := client.UpdateUser(tt.args.ctx, tt.args.userID, tt.args.updates)

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
