package postgres

import (
	"fmt"

	"github.com/Businge931/sba-user-accounts/internal/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
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

// Connect creates a new database connection using GORM
func (f *DBFactory) Connect() (*gorm.DB, error) {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		f.config.Host, f.config.Port, f.config.User, f.config.Password, f.config.Name)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database instance: %v", err)
	}

	// Test the connection
	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %v", err)
	}

	return db, nil
}

// AutoMigrate runs auto migration for given models
func (f *DBFactory) AutoMigrate(db *gorm.DB, models ...interface{}) error {
	return db.AutoMigrate(models...)
}
