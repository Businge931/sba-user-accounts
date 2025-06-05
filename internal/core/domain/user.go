package domain

import (
	"time"
)

type RegisterRequest struct {
	Email     string
	Password  string
	FirstName string
	LastName  string
}

type LoginRequest struct {
	Email    string
	Password string
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
