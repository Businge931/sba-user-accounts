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

func TestFirebaseClient_CreateUser(t *testing.T) {
	tests := []struct {
		name string
		deps struct {
			mockSDK    *mocks.MockFirebaseSDK
			mockAuth   *mocks.MockFirebaseAuth
			mockHTTP   *mocks.MockHTTPClient
			mockConfig *mocks.MockConfigProvider
		}
		args struct {
			ctx       context.Context
			email     string
			password  string
			firstName string
			lastName  string
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
			name: "Success_CreateUser",
			args: struct {
				ctx       context.Context
				email     string
				password  string
				firstName string
				lastName  string
			}{
				ctx:       context.Background(),
				email:     "test@example.com",
				password:  "password123",
				firstName: "John",
				lastName:  "Doe",
			},
			before: func(deps struct {
				mockSDK    *mocks.MockFirebaseSDK
				mockAuth   *mocks.MockFirebaseAuth
				mockHTTP   *mocks.MockHTTPClient
				mockConfig *mocks.MockConfigProvider
			}) {
				// Mock SDK.Auth() call
				deps.mockSDK.EXPECT().Auth(gomock.Any()).Return(deps.mockAuth, nil)
				
				// Mock AuthClient.CreateUser() call
				userRecord := &auth.UserRecord{
					UserInfo: &auth.UserInfo{
						UID:   "test-uid-123",
						Email: "test@example.com",
					},
					EmailVerified: false,
				}
				deps.mockAuth.EXPECT().CreateUser(gomock.Any(), gomock.Any()).Return(userRecord, nil)
			},
			expectedResult: &domain.User{
				ID:              "test-uid-123",
				Email:           "test@example.com",
				FirstName:       "John",
				LastName:        "Doe",
				IsEmailVerified: false,
			},
			expectedError: nil,
		},
		{
			name: "Error_SDKAuthFails",
			args: struct {
				ctx       context.Context
				email     string
				password  string
				firstName string
				lastName  string
			}{
				ctx:       context.Background(),
				email:     "test@example.com",
				password:  "password123",
				firstName: "John",
				lastName:  "Doe",
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
			expectedError:  errors.New("error getting auth client: auth client error"),
		},
		{
			name: "Error_CreateUserFails",
			args: struct {
				ctx       context.Context
				email     string
				password  string
				firstName string
				lastName  string
			}{
				ctx:       context.Background(),
				email:     "test@example.com",
				password:  "password123",
				firstName: "John",
				lastName:  "Doe",
			},
			before: func(deps struct {
				mockSDK    *mocks.MockFirebaseSDK
				mockAuth   *mocks.MockFirebaseAuth
				mockHTTP   *mocks.MockHTTPClient
				mockConfig *mocks.MockConfigProvider
			}) {
				// Mock SDK.Auth() success
				deps.mockSDK.EXPECT().Auth(gomock.Any()).Return(deps.mockAuth, nil)
				
				// Mock AuthClient.CreateUser() failure
				deps.mockAuth.EXPECT().CreateUser(gomock.Any(), gomock.Any()).Return(nil, errors.New("user creation failed"))
			},
			expectedResult: nil,
			expectedError:  errors.New("error creating user: user creation failed"),
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
			result, err := client.CreateUser(tt.args.ctx, tt.args.email, tt.args.password, tt.args.firstName, tt.args.lastName)

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