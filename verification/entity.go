package verification

import (
	"context"
	"fmt"
)

type CodeType string

// ChinaCountryCode is the country code for mainland China.
const ChinaCountryCode = "86"

type Code struct {
	UserID     int64    `json:"user_id"`
	Type       CodeType `json:"type"`
	Sequence   string   `json:"sequence"`
	CodeLength int32    `json:"code_length"`
	Code       string   `json:"code"`
	Content    string   `json:"content"`
}

// VerificationCode returns the code string.
func (c Code) VerificationCode() string { return c.Code }

// GetSequence returns the sequence identifier.
func (c Code) GetSequence() string { return c.Sequence }

// GetType returns the code type.
func (c Code) GetType() CodeType { return c.Type }

// MobileCode represents a mobile verification code.
type MobileCode struct {
	Code
	Mobile      string `json:"mobile"`
	CountryCode string `json:"country_code"`
}

func (c MobileCode) Medium() string          { return "MOBILE" }
func (c MobileCode) CacheKeyParts() []string { return []string{c.Sequence, c.Mobile, c.CountryCode} }
func (c MobileCode) LimitKeyParts() []string { return []string{c.Mobile, c.CountryCode} }

// Format returns a formatted string using the given format and args.
// Typically used to format SMS template parameters, e.g. Format(`{"code":"%s"}`, code).
func (c MobileCode) Format(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}

// Validate checks that all required fields are populated.
func (c *MobileCode) Validate() error {
	if c == nil {
		return ErrNilMobileCode
	}
	if c.Mobile == "" {
		return ErrMobileCodeMobileIsEmpty
	}
	if c.CountryCode == "" {
		return ErrMobileCodeCountryCodeIsEmpty
	}
	if c.Code.Code == "" {
		return ErrMobileCodeCodeIsEmpty
	}
	if c.Type == "" {
		return ErrMobileCodeTypeIsEmpty
	}
	return nil
}

// EmailCode represents an email verification code.
type EmailCode struct {
	Code
	Email string `json:"email"`
}

func (c EmailCode) Medium() string          { return "EMAIL" }
func (c EmailCode) CacheKeyParts() []string { return []string{c.Sequence, c.Email} }
func (c EmailCode) LimitKeyParts() []string { return []string{c.Email} }

// Validate checks that all required fields are populated.
func (c *EmailCode) Validate() error {
	if c == nil {
		return ErrNilEmailCode
	}
	if c.Email == "" {
		return ErrEmailCodeEmailIsEmpty
	}
	if c.Code.Code == "" {
		return ErrEmailCodeCodeIsEmpty
	}
	if c.Type == "" {
		return ErrEmailCodeTypeIsEmpty
	}
	return nil
}

// EcdsaCode represents an ecdsa verification code.
type EcdsaCode struct {
	Code
	Chain   string `json:"chain"`
	Address string `json:"address"`
}

func (c EcdsaCode) Medium() string          { return "ECDSA" }
func (c EcdsaCode) CacheKeyParts() []string { return []string{c.Sequence, c.Chain, c.Address} }
func (c EcdsaCode) LimitKeyParts() []string { return []string{c.Chain, c.Address} }

// MobileCodeSender represents a mobile verification code sender.
type MobileCodeSender interface {
	// Send the mobile verification code via SMS.
	Send(ctx context.Context, code *MobileCode) error
}

// EmailCodeSender represents an email verification code sender.
type EmailCodeSender interface {
	// Send the email verification code via email.
	Send(ctx context.Context, code *EmailCode) error
}

// TemplateProvider provides template lookup by CodeType.
// Implementations can back this with a static map, database, config file, etc.
type TemplateProvider[T any] interface {
	GetTemplate(typ CodeType) (*T, error)
}
