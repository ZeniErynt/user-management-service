package domain

import (
	"context"
	"errors"
	"strings"
	"time"
)

const (
	MinNameLength     = 3
	MaxNameLength     = 100
	MaxEmailLength    = 255
	MinPasswordLength = 8
	MaxPasswordLength = 72
)

var (
	ErrInvalidName           = errors.New("name must be between 3 and 100 characters")
	ErrInvalidEmail          = errors.New("invalid email format or exceeds 255 characters")
	ErrInvalidPasswordLength = errors.New("password must be between 8 and 72 characters")
	ErrEmailAlreadyExists    = errors.New("email is already registered")
	ErrInvalidCredentials    = errors.New("invalid email or password")
	ErrUserNotFound          = errors.New("user not found")
	ErrUserAlreadyDeleted    = errors.New("user account has been deleted")
	ErrPasswordMismatch      = errors.New("old password does not match")
	ErrSamePassword          = errors.New("new password cannot be the same as the old password")
)

type UserRepository interface {
	FindByID(ctx context.Context, id uint64) (*User, error)
	FindByEmail(ctx context.Context, email string) (*User, error)
	ExistsByEmail(ctx context.Context, email string) (bool, error)
	Save(ctx context.Context, user *User) error
	Update(ctx context.Context, user *User) error
}

type User struct {
	id        uint64
	name      string
	email     string
	password  string
	createdAt *time.Time
	updatedAt *time.Time
	deletedAt *time.Time
}

func NewUser(name, email, plainPassword string) (*User, error) {
	return &User{name: name, email: email, password: plainPassword}, nil
}

func (u *User) ValidateName() error {
	if u.name == "" {
		return ErrInvalidName
	}

	if len(u.name) < MinNameLength {
		return ErrInvalidName
	}

	if len(u.name) > MaxNameLength {
		return ErrInvalidName
	}

	u.name = strings.TrimSpace(u.name)
	return nil
}

func (u *User) ValidateEmail() error {
	if u.email == "" {
		return ErrInvalidEmail
	}

	if len(u.email) > MaxEmailLength {
		return ErrInvalidEmail
	}

	normalizedEmail := strings.ToLower(
		strings.TrimSpace(u.email),
	)
	u.email = normalizedEmail

	return nil
}

func (u *User) ValidatePassword() error {
	if u.password == "" {
		return ErrInvalidPasswordLength
	}

	if len(u.password) < MinPasswordLength {
		return ErrInvalidPasswordLength
	}

	if len(u.password) > MaxPasswordLength {
		return ErrInvalidPasswordLength
	}

	return nil
}

func (u *User) SetCreatedAt() {
	now := time.Now().UTC()
	u.createdAt = &now
}

func (u *User) SetUpdatedAt() {
	now := time.Now().UTC()
	u.createdAt = &now
}

func (u *User) SetDeletedAt() {
	now := time.Now().UTC()
	u.deletedAt = &now
}

func (u *User) IsDeleted() error {
	if u.deletedAt != nil {
		return ErrUserAlreadyDeleted
	}
	return nil
}
