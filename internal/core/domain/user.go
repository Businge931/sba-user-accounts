package domain

import (
	"time"
)

// User represents the user entity
type User struct {
	ID              string    `json:"id"`
	Email           string    `json:"email"`
	HashedPassword  string    `json:"-"`
	FirstName       string    `json:"first_name"`
	LastName        string    `json:"last_name"`
	IsEmailVerified bool      `json:"is_email_verified"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"-"`
}

// NewUser creates a new user instance
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
