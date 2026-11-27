package domain

import (
	"context"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func validateAndNormalizeName(name string) (string, error) {
	normalized := strings.TrimSpace(name)
	if normalized == "" {
		return "", ErrInvalidName
	}
	if len(normalized) < MinNameLength || len(normalized) > MaxNameLength {
		return "", ErrInvalidName
	}
	return normalized, nil
}

func validateAndNormalizeEmail(email string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(email))
	if normalized == "" || len(normalized) > MaxEmailLength {
		return "", ErrInvalidEmail
	}
	return normalized, nil
}

func validatePasswordLength(plain string) error {
	if len(plain) < MinPasswordLength || len(plain) > MaxPasswordLength {
		return ErrInvalidPasswordLength
	}
	return nil
}

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
	createdAt time.Time
	updatedAt *time.Time
	deletedAt *time.Time
}

func NewUser(name, email, plainPassword string) (*User, error) {
	normalizedName, err := validateAndNormalizeName(name)
	if err != nil {
		return nil, err
	}

	normalizedEmail, err := validateAndNormalizeEmail(email)
	if err != nil {
		return nil, err
	}

	if err := validatePasswordLength(plainPassword); err != nil {
		return nil, err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(plainPassword), bcrypt.DefaultCost,
	)
	if err != nil {
		return nil, err
	}

	return &User{
		name:     normalizedName,
		email:    normalizedEmail,
		password: string(hashedPassword),
	}, nil
}

func (u *User) CheckPassword(plainPassword string) error {
	err := bcrypt.CompareHashAndPassword(
		[]byte(u.password), []byte(plainPassword),
	)
	if err != nil {
		return err
	}
	return nil
}

func (u *User) ChangePassword(oldPlain, newPlain string) error {
	if u.deletedAt != nil {
		return ErrUserAlreadyDeleted
	}

	if err := u.CheckPassword(oldPlain); err != nil {
		return ErrPasswordMismatch
	}

	if err := validatePasswordLength(newPlain); err != nil {
		return err
	}

	if err := u.CheckPassword(newPlain); err == nil {
		return ErrSamePassword
	}

	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(newPlain), bcrypt.DefaultCost,
	)
	if err != nil {
		return err
	}

	u.password = string(hashedPassword)
	now := time.Now().UTC()
	u.updatedAt = &now

	return nil
}
