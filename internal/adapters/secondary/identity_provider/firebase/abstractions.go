package firebase

import (
	"context"
	"net/http"
	"time"

	"firebase.google.com/go/v4/auth"
)

type (
	// FirebaseSDK abstracts the Firebase Admin SDK
	FirebaseSDK interface {
		Auth(ctx context.Context) (FirebaseAuth, error)
	}

	// FirebaseAuth abstracts Firebase Auth operations
	FirebaseAuth interface {
		CreateUser(ctx context.Context, user *auth.UserToCreate) (*auth.UserRecord, error)
		GetUserByEmail(ctx context.Context, email string) (*auth.UserRecord, error)
		UpdateUser(ctx context.Context, uid string, user *auth.UserToUpdate) (*auth.UserRecord, error)
		VerifyIDToken(ctx context.Context, idToken string) (*auth.Token, error)
		CustomToken(ctx context.Context, uid string) (string, error)
		EmailVerificationLink(ctx context.Context, email string) (string, error)
		PasswordResetLink(ctx context.Context, email string) (string, error)
	}

	// HTTPClient abstracts HTTP operations
	HTTPClient interface {
		Do(req *http.Request) (*http.Response, error)
	}

	// ConfigProvider abstracts configuration access
	ConfigProvider interface {
		GetAPIKey() string
		GetProjectID() string
		GetStorageBucket() string
		GetServiceAccountKeyPath() string
		GetHTTPTimeout() int
	}

// FirebaseConfig holds configuration for Firebase client
	FirebaseConfig struct {
		ServiceAccountKeyPath string
		ProjectID             string
		StorageBucket         string
		APIKey                string
		HTTPClientTimeout     time.Duration
	}
)