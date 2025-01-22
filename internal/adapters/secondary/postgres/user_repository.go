package postgres

import (
	"database/sql"
	"errors"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/Businge931/sba-user-accounts/internal/core/ports"
)

type userRepository struct {
	db *sql.DB
}

// NewUserRepository creates a new PostgreSQL user repository
func NewUserRepository(db *sql.DB) ports.UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) Create(user *domain.User) error {
	query := `
		INSERT INTO users (id, email, hashed_password, first_name, last_name, is_email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := r.db.Exec(
		query,
		user.ID,
		user.Email,
		user.HashedPassword,
		user.FirstName,
		user.LastName,
		user.IsEmailVerified,
		user.CreatedAt,
		user.UpdatedAt,
	)
	return err
}

func (r *userRepository) GetByID(id string) (*domain.User, error) {
	user := &domain.User{}
	query := `
		SELECT id, email, hashed_password, first_name, last_name, is_email_verified, created_at, updated_at
		FROM users WHERE id = $1
	`
	err := r.db.QueryRow(query, id).Scan(
		&user.ID,
		&user.Email,
		&user.HashedPassword,
		&user.FirstName,
		&user.LastName,
		&user.IsEmailVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, errors.New("user not found")
	}
	return user, err
}

func (r *userRepository) GetByEmail(email string) (*domain.User, error) {
	user := &domain.User{}
	query := `
		SELECT id, email, hashed_password, first_name, last_name, is_email_verified, created_at, updated_at
		FROM users WHERE email = $1
	`
	err := r.db.QueryRow(query, email).Scan(
		&user.ID,
		&user.Email,
		&user.HashedPassword,
		&user.FirstName,
		&user.LastName,
		&user.IsEmailVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, errors.New("user not found")
	}
	return user, err
}

func (r *userRepository) Update(user *domain.User) error {
	query := `
		UPDATE users
		SET email = $1, hashed_password = $2, first_name = $3, last_name = $4,
			is_email_verified = $5, updated_at = $6
		WHERE id = $7
	`
	result, err := r.db.Exec(
		query,
		user.Email,
		user.HashedPassword,
		user.FirstName,
		user.LastName,
		user.IsEmailVerified,
		user.UpdatedAt,
		user.ID,
	)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return errors.New("user not found")
	}
	return nil
}

func (r *userRepository) Delete(id string) error {
	query := "DELETE FROM users WHERE id = $1"
	result, err := r.db.Exec(query, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return errors.New("user not found")
	}
	return nil
}
