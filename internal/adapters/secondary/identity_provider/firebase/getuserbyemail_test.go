package firebase_test

import (
	"context"
	"errors"
	"testing"

	"firebase.google.com/go/v4/auth"
	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/identity_provider/firebase"
	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/identity_provider/firebase/mocks"
	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)



func TestFirebaseClient_GetUserByEmail(t *testing.T) {
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
		expectedResult *domain.User
		expectedError  error
	}{
		{
			name: "Success_GetUserByEmail",
			args: struct {
				ctx   context.Context
				email string
			}{
				ctx:   context.Background(),
				email: "john.doe@example.com",
			},
			before: func(deps struct {
				mockSDK    *mocks.MockFirebaseSDK
				mockAuth   *mocks.MockFirebaseAuth
				mockHTTP   *mocks.MockHTTPClient
				mockConfig *mocks.MockConfigProvider
			}) {
				// Mock SDK.Auth() call
				deps.mockSDK.EXPECT().Auth(gomock.Any()).Return(deps.mockAuth, nil)

				// Mock successful user retrieval
				mockUserRecord := &auth.UserRecord{
					UserInfo: &auth.UserInfo{
						UID:         "test-uid-123",
						Email:       "john.doe@example.com",
						DisplayName: "John Doe",
					},
					EmailVerified: true,
				}
				deps.mockAuth.EXPECT().GetUserByEmail(gomock.Any(), "john.doe@example.com").Return(mockUserRecord, nil)
			},
			expectedResult: &domain.User{
				ID:              "test-uid-123",
				Email:           "john.doe@example.com",
				FirstName:       "John",
				LastName:        "Doe",
				IsEmailVerified: true,
			},
			expectedError: nil,
		},
		{
			name: "Success_GetUserByEmail_NoDisplayName",
			args: struct {
				ctx   context.Context
				email string
			}{
				ctx:   context.Background(),
				email: "jane.smith@example.com",
			},
			before: func(deps struct {
				mockSDK    *mocks.MockFirebaseSDK
				mockAuth   *mocks.MockFirebaseAuth
				mockHTTP   *mocks.MockHTTPClient
				mockConfig *mocks.MockConfigProvider
			}) {
				// Mock SDK.Auth() call
				deps.mockSDK.EXPECT().Auth(gomock.Any()).Return(deps.mockAuth, nil)

				// Mock successful user retrieval with no display name
				mockUserRecord := &auth.UserRecord{
					UserInfo: &auth.UserInfo{
						UID:         "test-uid-456",
						Email:       "jane.smith@example.com",
						DisplayName: "", // No display name
					},
					EmailVerified: false,
				}
				deps.mockAuth.EXPECT().GetUserByEmail(gomock.Any(), "jane.smith@example.com").Return(mockUserRecord, nil)
			},
			expectedResult: &domain.User{
				ID:              "test-uid-456",
				Email:           "jane.smith@example.com",
				FirstName:       "",
				LastName:        "",
				IsEmailVerified: false,
			},
			expectedError: nil,
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
			expectedResult: nil,
			expectedError:  errors.New("error getting auth client"),
		},
		{
			name: "Error_GetUserByEmailFails",
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
				// Mock GetUserByEmail failure
				deps.mockAuth.EXPECT().GetUserByEmail(gomock.Any(), "nonexistent@example.com").Return(nil, errors.New("user not found"))
			},
			expectedResult: nil,
			expectedError:  errors.New("error getting user by email"),
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
			result, err := client.GetUserByEmail(tt.args.ctx, tt.args.email)

			// Assert
			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedResult, result)
			}
		})
	}
}
