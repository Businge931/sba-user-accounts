package firebase

import (
	"context"
	"net/http"
	"time"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"google.golang.org/api/option"
)

// firebaseSDKImpl implements FirebaseSDK
type firebaseSDKImpl struct {
	app *firebase.App
}

func NewFirebaseSDK(ctx context.Context, config ConfigProvider) (FirebaseSDK, error) {
	opt := option.WithCredentialsFile(config.GetServiceAccountKeyPath())
	app, err := firebase.NewApp(ctx, &firebase.Config{
		ProjectID:     config.GetProjectID(),
		StorageBucket: config.GetStorageBucket(),
	}, opt)
	if err != nil {
		return nil, err
	}

	return &firebaseSDKImpl{app: app}, nil
}

func (f *firebaseSDKImpl) Auth(ctx context.Context) (FirebaseAuth, error) {
	authClient, err := f.app.Auth(ctx)
	if err != nil {
		return nil, err
	}
	return &firebaseAuthImpl{client: authClient}, nil
}

// firebaseAuthImpl implements FirebaseAuth
type firebaseAuthImpl struct {
	client *auth.Client
}

func (f *firebaseAuthImpl) CreateUser(ctx context.Context, user *auth.UserToCreate) (*auth.UserRecord, error) {
	return f.client.CreateUser(ctx, user)
}

func (f *firebaseAuthImpl) GetUserByEmail(ctx context.Context, email string) (*auth.UserRecord, error) {
	return f.client.GetUserByEmail(ctx, email)
}

func (f *firebaseAuthImpl) UpdateUser(ctx context.Context, uid string, user *auth.UserToUpdate) (*auth.UserRecord, error) {
	return f.client.UpdateUser(ctx, uid, user)
}

func (f *firebaseAuthImpl) VerifyIDToken(ctx context.Context, idToken string) (*auth.Token, error) {
	return f.client.VerifyIDToken(ctx, idToken)
}

func (f *firebaseAuthImpl) CustomToken(ctx context.Context, uid string) (string, error) {
	return f.client.CustomToken(ctx, uid)
}

func (f *firebaseAuthImpl) EmailVerificationLink(ctx context.Context, email string) (string, error) {
	return f.client.EmailVerificationLink(ctx, email)
}

func (f *firebaseAuthImpl) PasswordResetLink(ctx context.Context, email string) (string, error) {
	return f.client.PasswordResetLink(ctx, email)
}

// httpClientImpl implements HTTPClient
type httpClientImpl struct {
	client *http.Client
}

func NewHTTPClient(timeout time.Duration) HTTPClient {
	return &httpClientImpl{
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

func (h *httpClientImpl) Do(req *http.Request) (*http.Response, error) {
	return h.client.Do(req)
}

// configProviderImpl implements ConfigProvider
type configProviderImpl struct {
	config *FirebaseConfig
}

func NewConfigProvider(config *FirebaseConfig) ConfigProvider {
	return &configProviderImpl{config: config}
}

func (c *configProviderImpl) GetAPIKey() string {
	return c.config.APIKey
}

func (c *configProviderImpl) GetProjectID() string {
	return c.config.ProjectID
}

func (c *configProviderImpl) GetStorageBucket() string {
	return c.config.StorageBucket
}

func (c *configProviderImpl) GetServiceAccountKeyPath() string {
	return c.config.ServiceAccountKeyPath
}

func (c *configProviderImpl) GetHTTPTimeout() int {
	if c.config.HTTPClientTimeout == 0 {
		return 30 // default 30 seconds
	}
	return int(c.config.HTTPClientTimeout.Seconds())
}
