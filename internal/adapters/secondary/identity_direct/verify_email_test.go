package identity

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestIdentityProvider_VerifyEmailSvc(t *testing.T) {
	tests := []verifyEmailTestCase{
		{
			name: "successful email verification",
			args: verifyEmailTestArgs{
				token: "valid-token",
			},
			expect: verifyEmailTestExpectations{
				result: "user-123",
			},
			before: func(t *testing.T, d *verifyEmailTestDependencies, args verifyEmailTestArgs) {
				d.authRepo.On("GetUserIDByVerificationToken", args.token).
					Return("user-123", nil).
					Once()
				d.logger.On("Infof", "Verifying email with token: %s", mock.MatchedBy(func(args []any) bool {
					return len(args) == 1 && args[0] == "valid-token"
				})).Once()
			},
			after: func(t *testing.T, d *verifyEmailTestDependencies) {
				d.authRepo.AssertExpectations(t)
				d.logger.AssertExpectations(t)
			},
		},
		{
			name: "returns error when token is empty",
			args: verifyEmailTestArgs{
				token: "",
			},
			expect: verifyEmailTestExpectations{
				wantErr: true,
				err:     errors.New("INVALID_INPUT: invalid or expired token: empty token"),
			},
			before: func(t *testing.T, d *verifyEmailTestDependencies, args verifyEmailTestArgs) {
				d.logger.On("Infof", "Verifying email with token: %s", mock.MatchedBy(func(args []any) bool {
					return len(args) == 1 && args[0] == ""
				})).Once()
				d.logger.On("Warnf", "Email verification failed: %v", mock.MatchedBy(func(args []any) bool {
					return len(args) == 1 && args[0].(error).Error() == "empty token"
				})).Once()
			},
			after: func(t *testing.T, d *verifyEmailTestDependencies) {
				d.logger.AssertExpectations(t)
			},
		},
		{
			name: "returns error when token is invalid",
			args: verifyEmailTestArgs{
				token: "invalid-token",
			},
			expect: verifyEmailTestExpectations{
				wantErr: true,
				err:     errors.New("INVALID_INPUT: invalid or expired token: token not found"),
			},
			before: func(t *testing.T, d *verifyEmailTestDependencies, args verifyEmailTestArgs) {
				d.authRepo.On("GetUserIDByVerificationToken", args.token).
					Return("", errors.New("token not found")).
					Once()
				d.logger.On("Infof", "Verifying email with token: %s", mock.MatchedBy(func(args []any) bool {
					return len(args) == 1 && args[0] == "invalid-token"
				})).Once()
				d.logger.On("Warnf", "Email verification failed: %v", mock.MatchedBy(func(args []any) bool {
					return len(args) == 1
				})).Once()
			},
			after: func(t *testing.T, d *verifyEmailTestDependencies) {
				d.authRepo.AssertExpectations(t)
				d.logger.AssertExpectations(t)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, deps := setupVerifyEmailTest(t)

			// before test case
			if tt.before != nil {
				tt.before(t, deps, tt.args)
			}

			// Execute the function under test
			got, err := svc.VerifyEmailSvc(tt.args.token)

			// Verify expectations
			if tt.expect.wantErr {
				require.Error(t, err)
				if tt.expect.err != nil {
					assert.EqualError(t, err, tt.expect.err.Error())
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expect.result, got)
			}

			// after test case
			if tt.after != nil {
				tt.after(t, deps)
			}
		})
	}
}
