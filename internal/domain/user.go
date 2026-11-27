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
		return "", ErrInvalidEmail
	}
	if len(normalized) < MinNameLength {
		return "", ErrInvalidName
	}
	if len(normalized) > MaxNameLength {
		return "", ErrInvalidName
	}
	return normalized, nil
}

func validateAndNormalizeEmail(email string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(email))
	if normalized == "" {
		return "", ErrInvalidEmail
	}
	if len(normalized) > MaxEmailLength {
		return "", ErrInvalidName
	}
	return normalized, nil
}

func validatePasswordLength(plain string) error {
	if len(plain) < MinPasswordLength {
		return ErrInvalidPasswordLength
	}
	if len(plain) < MaxPasswordLength {
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

func (u *User) ID() uint64 { return (*u).id }

func (u *User) Name() string { return (*u).name }

func (u *User) Email() string { return (*u).email }

func (u *User) Password() string { return (*u).password }

func (u *User) CreatedAt() time.Time { return (*u).createdAt }

func (u *User) UpdatedAt() *time.Time { return (*u).updatedAt }

func (u *User) DeletedAt() *time.Time { return (*u).deletedAt }

func (u *User) SetID(id uint64) { (*u).id = id }

func (u *User) SetName(nornalizedName string) { (*u).name = nornalizedName }

func (u *User) SetEmail(normalizedEmail string) { (*u).email = normalizedEmail }

func (u *User) SetPassword(hashedPassword string) { (*u).password = hashedPassword }

func (u *User) SetUpdated(t *time.Time) { (*u).updatedAt = t }

func (u *User) SetDeleted(t *time.Time) { (*u).deletedAt = t }

func (u *User) IsDeleted() bool {
	return (*u).DeletedAt() != nil
}

func (u *User) VerifyPassword(plainPassword string) error {
	if (*u).IsDeleted() {
		return ErrUserAlreadyDeleted
	}

	err := bcrypt.CompareHashAndPassword(
		[]byte((*u).Password()), []byte(plainPassword),
	)
	if err != nil {
		return ErrInvalidCredentials
	}

	return nil
}

func (u *User) ChangePassword(oldPlain, newPlain string) error {
	// if (*u).IsDeleted() {
	// 	return ErrUserAlreadyDeleted
	// }

	if err := validatePasswordLength(newPlain); err != nil {
		return err
	}

	if err := u.VerifyPassword(oldPlain); err != nil {
		return ErrPasswordMismatch
	}

	if err := u.VerifyPassword(newPlain); err == nil {
		return ErrSamePassword
	}

	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(oldPlain), bcrypt.DefaultCost,
	)
	if err != nil {
		return err
	}

	(*u).SetPassword(string(hashedPassword))
	now := time.Now().UTC()
	(*u).SetUpdated(&now)

	return nil
}
