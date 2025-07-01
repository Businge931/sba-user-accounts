package mocks

import (
	"github.com/stretchr/testify/mock"
)

// MockLogger mocks the Logger interface for testing
type MockLogger struct {
	mock.Mock
}

// Debug mocks the Debug method
func (m *MockLogger) Debug(args ...interface{}) {
	m.Called(args)
}

// Debugf mocks the Debugf method
func (m *MockLogger) Debugf(format string, args ...interface{}) {
	m.Called(format, args)
}

// Info mocks the Info method
func (m *MockLogger) Info(args ...interface{}) {
	m.Called(args)
}

// Infof mocks the Infof method
func (m *MockLogger) Infof(format string, args ...interface{}) {
	m.Called(format, args)
}

// Warn mocks the Warn method
func (m *MockLogger) Warn(args ...interface{}) {
	m.Called(args)
}

// Warnf mocks the Warnf method
func (m *MockLogger) Warnf(format string, args ...interface{}) {
	m.Called(format, args)
}

// Error mocks the Error method
func (m *MockLogger) Error(args ...interface{}) {
	m.Called(args)
}

// Errorf mocks the Errorf method
func (m *MockLogger) Errorf(format string, args ...interface{}) {
	m.Called(format, args)
}

// Fatal mocks the Fatal method
func (m *MockLogger) Fatal(args ...interface{}) {
	m.Called(args)
}

// Fatalf mocks the Fatalf method
func (m *MockLogger) Fatalf(format string, args ...interface{}) {
	m.Called(format, args)
}

// MockValidator mocks the Validator functionality for testing
type MockValidator struct {
	mock.Mock
}

// ValidateEmail mocks the ValidateEmail method
func (m *MockValidator) ValidateEmail(email string) error {
	args := m.Called(email)
	return args.Error(0)
}

// ValidatePassword mocks the ValidatePassword method
func (m *MockValidator) ValidatePassword(password string) error {
	args := m.Called(password)
	return args.Error(0)
}

// ValidateName mocks the ValidateName method
func (m *MockValidator) ValidateName(name, fieldName string) error {
	args := m.Called(name, fieldName)
	return args.Error(0)
}
