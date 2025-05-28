package postgres_test

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/Businge931/sba-user-accounts/internal/adapters/secondary/postgres"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TestDependencies struct {
	db   *sql.DB
	mock sqlmock.Sqlmock
}
type TestArgs struct {
	userID string
	token  string
}
type TestExpectations struct {
	result   string
	error    bool
	errorMsg string
}

func TestAuthRepository_StoreVerificationToken(t *testing.T) {
	testCases := []struct {
		name     string
		deps     TestDependencies
		args     TestArgs
		before   func(mock sqlmock.Sqlmock)
		expected TestExpectations
	}{
		{
			name: "StoreVerificationToken_Success",
			args: TestArgs{
				userID: "user123",
				token:  "verification-token-123",
			},
			before: func(mock sqlmock.Sqlmock) {
				// Setup expectations for table creation
				mock.ExpectExec("CREATE TABLE IF NOT EXISTS tokens").
					WillReturnResult(sqlmock.NewResult(0, 0))

				// Expect existing tokens to be deleted
				mock.ExpectExec("DELETE FROM tokens WHERE user_id = \\$1 AND token_type = \\$2").
					WithArgs("user123", postgres.VerificationToken).
					WillReturnResult(sqlmock.NewResult(0, 1))

				// Expect token insertion
				mock.ExpectExec("INSERT INTO tokens").
					WithArgs("user123", "verification-token-123").
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			expected: TestExpectations{
				error: false,
			},
		},
		{
			name: "StoreVerificationToken_TableCreationFails",
			args: TestArgs{
				userID: "user123",
				token:  "verification-token-123",
			},
			before: func(mock sqlmock.Sqlmock) {
				// Setup expectations for table creation failure
				mock.ExpectExec("CREATE TABLE IF NOT EXISTS tokens").
					WillReturnError(errors.New("database error"))
			},
			expected: TestExpectations{
				error:    true,
				errorMsg: "database error",
			},
		},
		{
			name: "StoreVerificationToken_DeleteFails",
			args: TestArgs{
				userID: "user123",
				token:  "verification-token-123",
			},
			before: func(mock sqlmock.Sqlmock) {
				// Setup expectations for table creation
				mock.ExpectExec("CREATE TABLE IF NOT EXISTS tokens").
					WillReturnResult(sqlmock.NewResult(0, 0))

				// Expect existing tokens deletion to fail
				mock.ExpectExec("DELETE FROM tokens WHERE user_id = \\$1 AND token_type = \\$2").
					WithArgs("user123", postgres.VerificationToken).
					WillReturnError(errors.New("delete failed"))
			},
			expected: TestExpectations{
				error:    true,
				errorMsg: "delete failed",
			},
		},
		{
			name: "StoreVerificationToken_InsertFails",
			args: TestArgs{
				userID: "user123",
				token:  "verification-token-123",
			},
			before: func(mock sqlmock.Sqlmock) {
				// Setup expectations for table creation
				mock.ExpectExec("CREATE TABLE IF NOT EXISTS tokens").
					WillReturnResult(sqlmock.NewResult(0, 0))

				// Expect existing tokens to be deleted
				mock.ExpectExec("DELETE FROM tokens WHERE user_id = \\$1 AND token_type = \\$2").
					WithArgs("user123", postgres.VerificationToken).
					WillReturnResult(sqlmock.NewResult(0, 1))

				// Expect token insertion to fail
				mock.ExpectExec("INSERT INTO tokens").
					WithArgs("user123", "verification-token-123").
					WillReturnError(errors.New("insert failed"))
			},
			expected: TestExpectations{
				error:    true,
				errorMsg: "insert failed",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			// Create test dependencies
			// deps := TestDependencies{
			// 	db:   db,
			// 	mock: mock,
			// }

			// Set up expectations
			if tc.before != nil {
				tc.before(mock)
			}

			// Create the repository
			repo := postgres.NewAuthRepository(db)

			// Execute
			err = repo.StoreVerificationToken(tc.args.userID, tc.args.token)

			// Verify
			if tc.expected.error {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expected.errorMsg)
			} else {
				assert.NoError(t, err)
			}

			// Verify all expectations were met
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestAuthRepository_GetUserIDByVerificationToken(t *testing.T) {
	testCases := []struct {
		name     string
		deps     TestDependencies
		args     TestArgs
		before   func(mock sqlmock.Sqlmock)
		expected TestExpectations
	}{
		{
			name: "GetUserIDByVerificationToken_Success",
			args: TestArgs{
				token: "verification-token-123",
			},
			before: func(mock sqlmock.Sqlmock) {
				// Setup for successful token lookup
				expiryTime := time.Now().Add(1 * time.Hour) // Token expires in the future

				rows := sqlmock.NewRows([]string{"user_id", "expiry_time"}).
					AddRow("user123", expiryTime)

				mock.ExpectQuery(`^SELECT user_id, expiry_time FROM tokens WHERE token_id = \$1 AND token_type = \$2$`).
					WithArgs("verification-token-123", postgres.VerificationToken).
					WillReturnRows(rows)
			},
			expected: TestExpectations{
				result: "user123",
				error:  false,
			},
		},
		{
			name: "GetUserIDByVerificationToken_NotFound",
			args: TestArgs{
				token: "non-existent-token",
			},
			before: func(mock sqlmock.Sqlmock) {
				// Setup for token not found
				mock.ExpectQuery(`^SELECT user_id, expiry_time FROM tokens WHERE token_id = \$1 AND token_type = \$2$`).
					WithArgs("non-existent-token", postgres.VerificationToken).
					WillReturnError(sql.ErrNoRows)
			},
			expected: TestExpectations{
				error:    true,
				errorMsg: "record not found",
			},
		},
		{
			name: "GetUserIDByVerificationToken_Expired",
			args: TestArgs{
				token: "expired-token",
			},
			before: func(mock sqlmock.Sqlmock) {
				// Setup for expired token
				expiryTime := time.Now().Add(-1 * time.Hour) // Token expired 1 hour ago

				rows := sqlmock.NewRows([]string{"user_id", "expiry_time"}).
					AddRow("user123", expiryTime)

				mock.ExpectQuery(`^SELECT user_id, expiry_time FROM tokens WHERE token_id = \$1 AND token_type = \$2$`).
					WithArgs("expired-token", postgres.VerificationToken).
					WillReturnRows(rows)
			},
			expected: TestExpectations{
				error:    true,
				errorMsg: "token has expired",
			},
		},
		{
			name: "GetUserIDByVerificationToken_DatabaseError",
			args: TestArgs{
				token: "token-123",
			},
			before: func(mock sqlmock.Sqlmock) {
				// Setup for database error
				mock.ExpectQuery("SELECT user_id, expiry_time FROM tokens").
					WithArgs("token-123", postgres.VerificationToken).
					WillReturnError(errors.New("database connection error"))
			},
			expected: TestExpectations{
				error:    true,
				errorMsg: "database connection error",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			// Create test dependencies
			// deps := TestDependencies{
			// 	db:   db,
			// 	mock: mock,
			// }

			// Set up expectations
			if tc.before != nil {
				tc.before(mock)
			}

			// Create the repository
			repo := postgres.NewAuthRepository(db)

			// Execute
			userID, err := repo.GetUserIDByVerificationToken(tc.args.token)

			// Verify
			if tc.expected.error {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expected.errorMsg)
				assert.Equal(t, "", userID)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected.result, userID)
			}

			// Verify all expectations were met
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestAuthRepository_StoreResetToken(t *testing.T) {
	testCases := []struct {
		name     string
		deps     TestDependencies
		args     TestArgs
		before   func(mock sqlmock.Sqlmock)
		expected TestExpectations
	}{
		{
			name: "StoreResetToken_Success",
			args: TestArgs{
				userID: "user123",
				token:  "reset-token-123",
			},
			before: func(mock sqlmock.Sqlmock) {
				// Setup expectations for table creation
				mock.ExpectExec("CREATE TABLE IF NOT EXISTS tokens").
					WillReturnResult(sqlmock.NewResult(0, 0))

				// Expect existing tokens to be deleted
				mock.ExpectExec("DELETE FROM tokens WHERE user_id = \\$1 AND token_type = \\$2").
					WithArgs("user123", postgres.ResetToken).
					WillReturnResult(sqlmock.NewResult(0, 1))

				// Expect token insertion
				mock.ExpectExec("INSERT INTO tokens").
					WithArgs("user123", "reset-token-123").
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			expected: TestExpectations{
				error: false,
			},
		},
		{
			name: "StoreResetToken_TableCreationFails",
			args: TestArgs{
				userID: "user123",
				token:  "reset-token-123",
			},
			before: func(mock sqlmock.Sqlmock) {
				// Setup expectations for table creation failure
				mock.ExpectExec("CREATE TABLE IF NOT EXISTS tokens").
					WillReturnError(errors.New("database error"))
			},
			expected: TestExpectations{
				error:    true,
				errorMsg: "database error",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			// Create test dependencies
			// deps := TestDependencies{
			// 	db:   db,
			// 	mock: mock,
			// }

			// Set up expectations
			if tc.before != nil {
				tc.before(mock)
			}

			// Create the repository
			repo := postgres.NewAuthRepository(db)

			// Execute
			err = repo.StoreResetToken(tc.args.userID, tc.args.token)

			// Verify
			if tc.expected.error {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expected.errorMsg)
			} else {
				assert.NoError(t, err)
			}

			// Verify all expectations were met
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestAuthRepository_GetUserIDByResetToken(t *testing.T) {
	testCases := []struct {
		name     string
		deps     TestDependencies
		args     TestArgs
		before   func(mock sqlmock.Sqlmock)
		expected TestExpectations
	}{
		{
			name: "GetUserIDByResetToken_Success",
			args: TestArgs{
				token: "reset-token-123",
			},
			before: func(mock sqlmock.Sqlmock) {
				// Setup for successful token lookup
				expiryTime := time.Now().Add(1 * time.Hour) // Token expires in the future

				rows := sqlmock.NewRows([]string{"user_id", "expiry_time"}).
					AddRow("user123", expiryTime)

				mock.ExpectQuery(`^SELECT user_id, expiry_time FROM tokens WHERE token_id = \$1 AND token_type = \$2$`).
					WithArgs("reset-token-123", postgres.ResetToken).
					WillReturnRows(rows)
			},
			expected: TestExpectations{
				result: "user123",
				error:  false,
			},
		},
		{
			name: "GetUserIDByResetToken_NotFound",
			args: TestArgs{
				token: "non-existent-token",
			},
			before: func(mock sqlmock.Sqlmock) {
				// Setup for token not found
				mock.ExpectQuery(`^SELECT user_id, expiry_time FROM tokens WHERE token_id = \$1 AND token_type = \$2$`).
					WithArgs("non-existent-token", postgres.ResetToken).
					WillReturnError(sql.ErrNoRows)
			},
			expected: TestExpectations{
				error:    true,
				errorMsg: "record not found",
			},
		},
		{
			name: "GetUserIDByResetToken_Expired",
			args: TestArgs{
				token: "expired-token",
			},
			before: func(mock sqlmock.Sqlmock) {
				// Setup for expired token
				expiryTime := time.Now().Add(-1 * time.Hour) // Token expired 1 hour ago

				rows := sqlmock.NewRows([]string{"user_id", "expiry_time"}).
					AddRow("user123", expiryTime)

				mock.ExpectQuery(`^SELECT user_id, expiry_time FROM tokens WHERE token_id = \$1 AND token_type = \$2$`).
					WithArgs("expired-token", postgres.ResetToken).
					WillReturnRows(rows)
			},
			expected: TestExpectations{
				error:    true,
				errorMsg: "token has expired",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			// Set up expectations
			if tc.before != nil {
				tc.before(mock)
			}

			// Create the repository
			repo := postgres.NewAuthRepository(db)

			// Execute
			userID, err := repo.GetUserIDByResetToken(tc.args.token)

			// Verify
			if tc.expected.error {
				assert.Error(t, err)
				if tc.expected.errorMsg != "" {
					assert.Contains(t, err.Error(), tc.expected.errorMsg)
				}
				assert.Equal(t, "", userID)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected.result, userID)
			}

			// Verify all expectations were met
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}
