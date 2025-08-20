package logging

import (
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/Businge931/sba-user-accounts/internal/core/ports"
)

// LogrusAdapter implements the Logger interface using logrus
type LogrusAdapter struct {
	logger *log.Logger
}

// NewLogrusAdapter creates a new logrus adapter
func NewLogrusAdapter() ports.Logger {
	logger := log.New()
	logger.SetFormatter(&log.JSONFormatter{})
	logger.SetOutput(os.Stdout)

	// Set log level from environment variable, default to info
	logLevel := log.InfoLevel
	switch os.Getenv("LOG_LEVEL") {
	case "debug":
		logLevel = log.DebugLevel
	case "info":
		logLevel = log.InfoLevel
	case "warn":
		logLevel = log.WarnLevel
	case "error":
		logLevel = log.ErrorLevel
	}
	logger.SetLevel(logLevel)

	return &LogrusAdapter{
		logger: logger,
	}
}

// Debug logs a debug message
func (l *LogrusAdapter) Debug(args ...interface{}) {
	l.logger.Debug(args...)
}

// Debugf logs a formatted debug message
func (l *LogrusAdapter) Debugf(format string, args ...interface{}) {
	l.logger.Debugf(format, args...)
}

// Info logs an info message
func (l *LogrusAdapter) Info(args ...interface{}) {
	l.logger.Info(args...)
}

// Infof logs a formatted info message
func (l *LogrusAdapter) Infof(format string, args ...interface{}) {
	l.logger.Infof(format, args...)
}

// Warn logs a warning message
func (l *LogrusAdapter) Warn(args ...interface{}) {
	l.logger.Warn(args...)
}

// Warnf logs a formatted warning message
func (l *LogrusAdapter) Warnf(format string, args ...interface{}) {
	l.logger.Warnf(format, args...)
}

// Error logs an error message
func (l *LogrusAdapter) Error(args ...interface{}) {
	l.logger.Error(args...)
}

// Errorf logs a formatted error message
func (l *LogrusAdapter) Errorf(format string, args ...interface{}) {
	l.logger.Errorf(format, args...)
}

// Fatal logs a fatal message and exits
func (l *LogrusAdapter) Fatal(args ...interface{}) {
	l.logger.Fatal(args...)
}

// Fatalf logs a formatted fatal message and exits
func (l *LogrusAdapter) Fatalf(format string, args ...interface{}) {
	l.logger.Fatalf(format, args...)
}
