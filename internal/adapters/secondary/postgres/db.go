package postgres

import (
	"database/sql"
	"fmt"

	"github.com/Businge931/sba-user-accounts/internal/config"
)

// DBFactory handles creating and managing database connections
type DBFactory struct {
	config config.DBConfig
}

// NewDBFactory creates a new database factory
func NewDBFactory(config config.DBConfig) *DBFactory {
	return &DBFactory{
		config: config,
	}
}

// Connect creates a new database connection
func (f *DBFactory) Connect() (*sql.DB, error) {
	dbURL := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		f.config.Host, f.config.Port, f.config.User, f.config.Password, f.config.Name)

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %v", err)
	}

	return db, nil
}
