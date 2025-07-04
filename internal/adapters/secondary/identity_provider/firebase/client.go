package firebase

import (
	"context"

	log "github.com/sirupsen/logrus"

	firebase "firebase.google.com/go/v4"
	"github.com/Businge931/sba-user-accounts/internal/config"
	"google.golang.org/api/option"
)

// Client represents a Firebase client wrapper
type Client struct {
	App *firebase.App
}

// NewClient initializes a new Firebase Admin SDK client
func NewClient(ctx context.Context, cfg config.FirebaseConfig, credentialsFile string) (*Client, error) {
	// Initialize the Firebase Admin SDK with the service account key file
	opt := option.WithCredentialsFile(credentialsFile)

	app, err := firebase.NewApp(ctx, &firebase.Config{
		ProjectID:     cfg.ProjectID,
		StorageBucket: cfg.StorageBucket,
	}, opt)
	if err != nil {
		log.Fatalf("Failed to create Firebase app: %v", err)
	}

	return &Client{
		App: app,
	}, nil
}

// VerifyIDToken verifies a Firebase ID token
func (c *Client) VerifyIDToken(ctx context.Context, idToken string) (string, error) {
	client, err := c.App.Auth(ctx)
	if err != nil {
		log.Errorf("error getting Auth client: %v\n", err)
		return "", err
	}

	token, err := client.VerifyIDToken(ctx, idToken)
	if err != nil {
		log.Errorf("error verifying ID token: %v\n", err)
		return "", err
	}

	return token.UID, nil
}
