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

var (
	// ErrNilMobileCode represents a nil mobile code error.
	ErrNilMobileCode = errors.New("mobile code is nil")
	// ErrMobileCodeCountryCodeIsEmpty represents an empty country code error.
	ErrMobileCodeCountryCodeIsEmpty = errors.New("mobile code country code is empty")
	// ErrMobileCodeMobileIsEmpty represents an empty mobile number error.
	ErrMobileCodeMobileIsEmpty = errors.New("mobile code mobile is empty")
	// ErrMobileCodeCodeIsEmpty represents an empty code error.
	ErrMobileCodeCodeIsEmpty = errors.New("mobile code code is empty")
	// ErrMobileCodeTypeIsEmpty represents an empty code type error.
	ErrMobileCodeTypeIsEmpty = errors.New("mobile code type is empty")
	// ErrUnsupportedCountryCode represents an unsupported country code error.
	ErrUnsupportedCountryCode = errors.New("unsupported country code")
)

const (
	// ChinaCountryCode is the country code for China.
	ChinaCountryCode = "86"
)

type CodeType string

type Code struct {
	// user id
	UserID int64
	// type of the verification code
	Type CodeType
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
