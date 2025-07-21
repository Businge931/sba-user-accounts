package firebase_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	"firebase.google.com/go/v4/auth"
	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/identity_provider/firebase"
	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/identity_provider/firebase/mocks"
	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFirebaseClient_VerifyPassword(t *testing.T) {
	tests := []struct {
		name string
		deps struct {
			mockSDK    *mocks.MockFirebaseSDK
			mockAuth   *mocks.MockFirebaseAuth
			mockHTTP   *mocks.MockHTTPClient
			mockConfig *mocks.MockConfigProvider
		}
		args struct {
			ctx      context.Context
			email    string
			password string
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
			name: "Success_VerifyPassword",
			args: struct {
				ctx      context.Context
				email    string
				password string
			}{
				ctx:      context.Background(),
				email:    "user@example.com",
				password: "validpassword",
			},
			before: func(deps struct {
				mockSDK    *mocks.MockFirebaseSDK
				mockAuth   *mocks.MockFirebaseAuth
				mockHTTP   *mocks.MockHTTPClient
				mockConfig *mocks.MockConfigProvider
			}) {
				// Mock SDK.Auth() call for VerifyPassword
				deps.mockSDK.EXPECT().Auth(gomock.Any()).Return(deps.mockAuth, nil)

				// Mock config.GetAPIKey() for signInWithEmailAndPassword
				deps.mockConfig.EXPECT().GetAPIKey().Return("test-api-key")

				// Mock HTTP client for sign-in request
				responseBody := map[string]interface{}{
					"idToken": "valid.jwt.token",
				}
				responseJSON, _ := json.Marshal(responseBody)
				
				mockResponse := &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(bytes.NewReader(responseJSON)),
				}
				deps.mockHTTP.EXPECT().Do(gomock.Any()).Return(mockResponse, nil)

				// Mock token verification
				mockToken := &auth.Token{
					UID: "test-uid-123",
				}
				deps.mockAuth.EXPECT().VerifyIDToken(gomock.Any(), "valid.jwt.token").Return(mockToken, nil)
			},
			expectedResult: "test-uid-123",
			expectedError:  nil,
		},
		{
			name: "Error_SDKAuthFails",
			args: struct {
				ctx      context.Context
				email    string
				password string
			}{
				ctx:      context.Background(),
				email:    "user@example.com",
				password: "password",
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
			name: "Error_SignInFails",
			args: struct {
				ctx      context.Context
				email    string
				password string
			}{
				ctx:      context.Background(),
				email:    "user@example.com",
				password: "wrongpassword",
			},
			before: func(deps struct {
				mockSDK    *mocks.MockFirebaseSDK
				mockAuth   *mocks.MockFirebaseAuth
				mockHTTP   *mocks.MockHTTPClient
				mockConfig *mocks.MockConfigProvider
			}) {
				// Mock SDK.Auth() success
				deps.mockSDK.EXPECT().Auth(gomock.Any()).Return(deps.mockAuth, nil)

				// Mock config.GetAPIKey() for signInWithEmailAndPassword
				deps.mockConfig.EXPECT().GetAPIKey().Return("test-api-key")

				// Mock HTTP client for failed sign-in request
				responseBody := map[string]interface{}{
					"error": map[string]interface{}{
						"message": "INVALID_PASSWORD",
					},
				}
				responseJSON, _ := json.Marshal(responseBody)
				
				mockResponse := &http.Response{
					StatusCode: 400,
					Body:       io.NopCloser(bytes.NewReader(responseJSON)),
				}
				deps.mockHTTP.EXPECT().Do(gomock.Any()).Return(mockResponse, nil)
			},
			expectedResult: "",
			expectedError:  errors.New("error signing in"),
		},
		{
			name: "Error_TokenVerificationFails",
			args: struct {
				ctx      context.Context
				email    string
				password string
			}{
				ctx:      context.Background(),
				email:    "user@example.com",
				password: "validpassword",
			},
			before: func(deps struct {
				mockSDK    *mocks.MockFirebaseSDK
				mockAuth   *mocks.MockFirebaseAuth
				mockHTTP   *mocks.MockHTTPClient
				mockConfig *mocks.MockConfigProvider
			}) {
				// Mock SDK.Auth() call for VerifyPassword
				deps.mockSDK.EXPECT().Auth(gomock.Any()).Return(deps.mockAuth, nil)

				// Mock config.GetAPIKey() for signInWithEmailAndPassword
				deps.mockConfig.EXPECT().GetAPIKey().Return("test-api-key")

				// Mock HTTP client for successful sign-in request
				responseBody := map[string]interface{}{
					"idToken": "invalid.jwt.token",
				}
				responseJSON, _ := json.Marshal(responseBody)
				
				mockResponse := &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(bytes.NewReader(responseJSON)),
				}
				deps.mockHTTP.EXPECT().Do(gomock.Any()).Return(mockResponse, nil)

				// Mock token verification failure
				deps.mockAuth.EXPECT().VerifyIDToken(gomock.Any(), "invalid.jwt.token").Return(nil, errors.New("invalid token"))
			},
			expectedResult: "",
			expectedError:  errors.New("error verifying ID token"),
		},
		{
			name: "Error_HTTPRequestFails",
			args: struct {
				ctx      context.Context
				email    string
				password string
			}{
				ctx:      context.Background(),
				email:    "user@example.com",
				password: "password",
			},
			before: func(deps struct {
				mockSDK    *mocks.MockFirebaseSDK
				mockAuth   *mocks.MockFirebaseAuth
				mockHTTP   *mocks.MockHTTPClient
				mockConfig *mocks.MockConfigProvider
			}) {
				// Mock SDK.Auth() success
				deps.mockSDK.EXPECT().Auth(gomock.Any()).Return(deps.mockAuth, nil)

				// Mock config.GetAPIKey() for signInWithEmailAndPassword
				deps.mockConfig.EXPECT().GetAPIKey().Return("test-api-key")

				// Mock HTTP client failure
				deps.mockHTTP.EXPECT().Do(gomock.Any()).Return(nil, errors.New("network error"))
			},
			expectedResult: "",
			expectedError:  errors.New("error signing in"),
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
			result, err := client.VerifyPassword(tt.args.ctx, tt.args.email, tt.args.password)

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
