package verification

import (
	"context"
	"errors"
)

var (
	// ErrCodeNotFound represents a verification code not found error.
	ErrCodeNotFound = errors.New("verification code not found")
	// ErrCodeTypeIsEmpty represents a verification code type is empty error.
	ErrCodeTypeIsEmpty = errors.New("verification code type is empty")
	// ErrCodeIncorrect represents a verification code incorrect error.
	ErrCodeIncorrect = errors.New("verification code is incorrect")
)

type Code struct {
	// user id
	UserID int64
	// type of the verification code
	Type string
	// sequence of this verification
	Sequence string
	// code size
	CodeLength int32
	// code
	Code string
	// content
	Content string
	// context arguments
	Args []any
	// content format function
	Format func(content string, args ...any) string
}

// MobileCode represents a mobile verification code.
type MobileCode struct {
	Code
	// mobile
	Mobile string
	// country code
	CountryCode string
}

// EmailCode represents an email verification code.
type EmailCode struct {
	Code
	// email
	Email string
}

// EcdsaCode represents an ecdsa verification code.
type EcdsaCode struct {
	Code
	// chain
	Chain string
	// The chain address
	Address string
}

// MobileCodeSender represents a mobile verification code sender.
type MobileCodeSender interface {
	// Send the mobile verification code via SMS.
	Send(ctx context.Context, code *MobileCode) error
}
