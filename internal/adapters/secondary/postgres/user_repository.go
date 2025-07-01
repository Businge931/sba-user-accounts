package postgres

import (
	"errors"

	"gorm.io/gorm"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	apperrors "github.com/Businge931/sba-user-accounts/internal/core/errors"
	"github.com/Businge931/sba-user-accounts/internal/core/ports"
)

type userRepository struct {
	db *gorm.DB
}

// NewUserRepository creates a new PostgreSQL user repository
func NewUserRepository(db *gorm.DB) ports.UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) Create(user *domain.User) error {
	result := r.db.Create(user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrDuplicatedKey) {
			return apperrors.ErrEmailAlreadyExists
		}
		return result.Error
	}
	return nil
}

func (r *userRepository) GetByID(id string) (*domain.User, error) {
	var user domain.User
	result := r.db.First(&user, "id = ?", id)

	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, apperrors.ErrUserNotFound
	}

	if result.Error != nil {
		return nil, result.Error
	}

	return &user, nil
}

func (r *userRepository) GetByEmail(email string) (*domain.User, error) {
	var user domain.User
	result := r.db.First(&user, "email = ?", email)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrUserNotFound
		}
		// For other database errors, return as internal server error
		return nil, apperrors.NewInternalError("failed to get user by email", result.Error)
	}

	return &user, nil
}

func (r *userRepository) Update(user *domain.User) error {
	result := r.db.Save(user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrDuplicatedKey) {
			return apperrors.ErrEmailAlreadyExists
		}
		return result.Error
	}

	if result.RowsAffected == 0 {
		return apperrors.ErrUserNotFound
	}

	return nil
}

func (r *userRepository) Delete(id string) error {
	result := r.db.Delete(&domain.User{}, "id = ?", id)
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return apperrors.ErrUserNotFound
	}

	return nil
}
