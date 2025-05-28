package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type UserRepositoryTestSuite struct {
	suite.Suite
	db         *sql.DB
	container  testcontainers.Container
	ctx        context.Context
	repo       *userRepository
	testUser   *domain.User
	testUserID string
}

func (s *UserRepositoryTestSuite) SetupSuite() {
	s.ctx = context.Background()

	// Start PostgreSQL container
	req := testcontainers.ContainerRequest{
		Image:        "postgres:13-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "testdb",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
	}

	var err error
	s.container, err = testcontainers.GenericContainer(s.ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(s.T(), err)

	// Get connection details
	host, err := s.container.Host(s.ctx)
	require.NoError(s.T(), err)
	port, err := s.container.MappedPort(s.ctx, "5432")
	require.NoError(s.T(), err)

	// Connect to the database
	connStr := "postgres://test:test@" + host + ":" + port.Port() + "/testdb?sslmode=disable"
	s.db, err = sql.Open("postgres", connStr)
	require.NoError(s.T(), err)

	// Create tables
	_, err = s.db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT NOT NULL UNIQUE,
			hashed_password TEXT NOT NULL,
			first_name TEXT NOT NULL,
			last_name TEXT NOT NULL,
			is_email_verified BOOLEAN NOT NULL,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		)
	`)
	require.NoError(s.T(), err)

	// Initialize repository
	s.repo = &userRepository{db: s.db}
	s.testUserID = uuid.NewString()
}

func (s *UserRepositoryTestSuite) SetupTest() {
	// Create a test user before each test
	now := time.Now()
	s.testUser = &domain.User{
		ID:              s.testUserID,
		Email:           "test@example.com",
		HashedPassword:  "hashedpassword123",
		FirstName:       "Test",
		LastName:        "User",
		IsEmailVerified: true,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	// Clean up any existing test data
	_, _ = s.db.Exec("DELETE FROM users")
}

func (s *UserRepositoryTestSuite) TearDownSuite() {
	if s.db != nil {
		s.db.Close()
	}
	if s.container != nil {
		s.container.Terminate(s.ctx)
	}
}

func TestUserRepository(t *testing.T) {
	suite.Run(t, new(UserRepositoryTestSuite))
}

func (s *UserRepositoryTestSuite) TestCreate() {
	tests := []struct {
		name        string
		user        *domain.User
		before      func()
		expectedErr bool
	}{
		{
			name: "success - create new user",
			user: s.testUser,
			before: func() {
				// No setup needed
			},
			expectedErr: false,
		},
		{
			name: "fail - duplicate email",
			user: s.testUser,
			before: func() {
				// Create a user with the same email first
				_, _ = s.db.Exec(`
					INSERT INTO users (id, email, hashed_password, first_name, last_name, is_email_verified, created_at, updated_at)
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
				`, "another-id", s.testUser.Email, "hash", "First", "Last", false, time.Now(), time.Now())
			},
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			if tt.before != nil {
				tt.before()
			}

			err := s.repo.Create(tt.user)

			if tt.expectedErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify the user was created
				var count int
				err = s.db.QueryRow("SELECT COUNT(*) FROM users WHERE id = $1", tt.user.ID).Scan(&count)
				assert.NoError(t, err)
				assert.Equal(t, 1, count)
			}
		})
	}
}

func (s *UserRepositoryTestSuite) TestGetByID() {
	// Insert test user
	err := s.repo.Create(s.testUser)
	require.NoError(s.T(), err)

	tests := []struct {
		name        string
		id          string
		expected    *domain.User
		expectedErr error
	}{
		{
			name:        "success - get existing user",
			id:          s.testUserID,
			expected:    s.testUser,
			expectedErr: nil,
		},
		{
			name:        "fail - non-existent user",
			id:          "non-existent-id",
			expected:    nil,
			expectedErr: errors.New("user not found"),
		},
	}

	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			user, err := s.repo.GetByID(tt.id)

			if tt.expectedErr != nil {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr.Error())
				assert.Nil(t, user)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected.ID, user.ID)
				assert.Equal(t, tt.expected.Email, user.Email)
				// Add more assertions as needed
			}
		})
	}
}

func (s *UserRepositoryTestSuite) TestGetByEmail() {
	// Insert test user
	err := s.repo.Create(s.testUser)
	require.NoError(s.T(), err)

	tests := []struct {
		name        string
		email       string
		expected    *domain.User
		expectedErr error
	}{
		{
			name:        "success - get existing user by email",
			email:       s.testUser.Email,
			expected:    s.testUser,
			expectedErr: nil,
		},
		{
			name:        "fail - non-existent email",
			email:       "nonexistent@example.com",
			expected:    nil,
			expectedErr: errors.New("user not found"),
		},
	}

	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			user, err := s.repo.GetByEmail(tt.email)

			if tt.expectedErr != nil {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr.Error())
				assert.Nil(t, user)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected.ID, user.ID)
				assert.Equal(t, tt.expected.Email, user.Email)
			}
		})
	}
}

func (s *UserRepositoryTestSuite) TestUpdate() {
	// Insert test user
	err := s.repo.Create(s.testUser)
	require.NoError(s.T(), err)

	updatedUser := *s.testUser
	updatedUser.FirstName = "Updated"
	updatedUser.LastName = "Name"
	updatedUser.UpdatedAt = time.Now()

	tests := []struct {
		name        string
		user        *domain.User
		before      func()
		expectedErr error
	}{
		{
			name: "success - update existing user",
			user: &updatedUser,
			before: func() {
				// No setup needed
			},
			expectedErr: nil,
		},
		{
			name: "fail - update non-existent user",
			user: &domain.User{
				ID:        "non-existent-id",
				Email:     "new@example.com",
				UpdatedAt: time.Now(),
			},
			expectedErr: errors.New("user not found"),
		},
	}

	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			if tt.before != nil {
				tt.before()
			}

			err := s.repo.Update(tt.user)

			if tt.expectedErr != nil {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr.Error())
			} else {
				assert.NoError(t, err)

				// Verify the update
				updated, err := s.repo.GetByID(tt.user.ID)
				assert.NoError(t, err)
				assert.Equal(t, tt.user.FirstName, updated.FirstName)
				assert.Equal(t, tt.user.LastName, updated.LastName)
			}
		})
	}
}

func (s *UserRepositoryTestSuite) TestDelete() {
	tests := []struct {
		name        string
		id          string
		before      func()
		expectedErr error
	}{
		{
			name: "success - delete existing user",
			id:   s.testUserID,
			before: func() {
				// Create a user to delete
				_ = s.repo.Create(s.testUser)
			},
			expectedErr: nil,
		},
		{
			name:        "fail - delete non-existent user",
			id:          "non-existent-id",
			before:      func() {},
			expectedErr: errors.New("user not found"),
		},
	}

	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			if tt.before != nil {
				tt.before()
			}

			err := s.repo.Delete(tt.id)

			if tt.expectedErr != nil {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr.Error())
			} else {
				assert.NoError(t, err)

				// Verify the user was deleted
				_, err := s.repo.GetByID(tt.id)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "user not found")
			}
		})
	}
}
