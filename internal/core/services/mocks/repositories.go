package mocks

import (
	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/stretchr/testify/mock"
)

// MockUserRepository mocks the UserRepository interface for testing
type MockUserRepository struct {
	mock.Mock
}

// Create mocks the Create method
func (m *MockUserRepository) Create(user *domain.User) error {
	args := m.Called(user)
	return args.Error(0)
}

// GetByID mocks the GetByID method
func (m *MockUserRepository) GetByID(id string) (*domain.User, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

// GetByEmail mocks the GetByEmail method
func (m *MockUserRepository) GetByEmail(email string) (*domain.User, error) {
	args := m.Called(email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

// Update mocks the Update method
func (m *MockUserRepository) Update(user *domain.User) error {
	args := m.Called(user)
	return args.Error(0)
}

// Delete mocks the Delete method
func (m *MockUserRepository) Delete(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

// MockAuthRepository mocks the AuthRepository interface for testing
type MockAuthRepository struct {
	mock.Mock
}

// StoreVerificationToken mocks the StoreVerificationToken method
func (m *MockAuthRepository) StoreVerificationToken(userID, token string) error {
	args := m.Called(userID, token)
	return args.Error(0)
}

// GetUserIDByVerificationToken mocks the GetUserIDByVerificationToken method
func (m *MockAuthRepository) GetUserIDByVerificationToken(token string) (string, error) {
	args := m.Called(token)
	return args.String(0), args.Error(1)
}

// StoreResetToken mocks the StoreResetToken method
func (m *MockAuthRepository) StoreResetToken(userID, token string) error {
	args := m.Called(userID, token)
	return args.Error(0)
}

// GetUserIDByResetToken mocks the GetUserIDByResetToken method
func (m *MockAuthRepository) GetUserIDByResetToken(token string) (string, error) {
	args := m.Called(token)
	return args.String(0), args.Error(1)
}
