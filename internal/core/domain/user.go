package domain

import (
	"regexp"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

type RegisterRequest struct {
	Email     string `validate:"required,email"`
	Password  string `validate:"required,min=8,max=72"`
	FirstName string `validate:"required,min=2,max=50"`
	LastName  string `validate:"required,min=2,max=50"`
}

func (r RegisterRequest) Validate() error {
	return validation.ValidateStruct(&r,
		validation.Field(&r.Email, validation.Required, validation.Length(5, 255), is.EmailFormat),
		validation.Field(&r.Password, validation.Required, validation.Length(8, 72)),
		validation.Field(&r.FirstName, validation.Required, validation.Length(2, 50), validation.Match(regexp.MustCompile(`^[\p{L} -]+$`))),
		validation.Field(&r.LastName, validation.Required, validation.Length(2, 50), validation.Match(regexp.MustCompile(`^[\p{L} -]+$`))),
	)
}

type LoginRequest struct {
	Email    string `validate:"required,email"`
	Password string `validate:"required"`
}

func (l LoginRequest) Validate() error {
	return validation.ValidateStruct(&l,
		validation.Field(&l.Email, validation.Required, validation.Length(5, 255), is.EmailFormat),
		validation.Field(&l.Password, validation.Required),
	)
}

type User struct {
	ID              string    `gorm:"primaryKey;type:uuid;default:gen_random_uuid()" json:"id"`
	Email           string    `gorm:"uniqueIndex;not null" json:"email"`
	HashedPassword  string    `gorm:"not null" json:"-"`
	FirstName       string    `gorm:"not null" json:"first_name"`
	LastName        string    `gorm:"not null" json:"last_name"`
	IsEmailVerified bool      `gorm:"default:false" json:"is_email_verified"`
	CreatedAt       time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt       time.Time `gorm:"autoUpdateTime" json:"-"`
}

func NewUser(email, firstName, lastName string) *User {
	now := time.Now()
	return &User{
		Email:           email,
		FirstName:       firstName,
		LastName:        lastName,
		IsEmailVerified: false,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
}
