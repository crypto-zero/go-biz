package verification

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// hashCode returns the hex-encoded SHA-256 hash of a verification code string.
func hashCode(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}

// timeNow is a package-level function variable for time.Now.
// Override in tests to make EcdsaCode generation deterministic.
var timeNow = time.Now

type CodeType string

// ChinaCountryCode is the country code for mainland China.
const ChinaCountryCode = "86"

type Code struct {
	UserID     int64    `json:"user_id"`
	Type       CodeType `json:"type"`
	Sequence   string   `json:"sequence"`
	CodeLength int32    `json:"code_length"`
	Value      string   `json:"value"`
}

// GetValue returns the verification code string.
func (c Code) GetValue() string { return c.Value }

// hashValue replaces the plaintext code with its SHA-256 hash (in-place).
func (c *Code) hashValue() { c.Value = hashCode(c.Value) }

// GetSequence returns the sequence identifier.
func (c Code) GetSequence() string { return c.Sequence }

// GetType returns the code type.
func (c Code) GetType() CodeType { return c.Type }

// validate checks that common base fields are populated.
func (c Code) validate() error {
	if c.Value == "" {
		return ErrCodeIsEmpty
	}
	if c.Type == "" {
		return ErrCodeTypeIsEmpty
	}
	return nil
}

// MobileCode represents a mobile verification code.
type MobileCode struct {
	Code
	Mobile      string `json:"mobile"`
	CountryCode string `json:"country_code"`
}

func (c MobileCode) Medium() string          { return "MOBILE" }
func (c MobileCode) CacheKeyParts() []string { return []string{c.Sequence, c.Mobile, c.CountryCode} }
func (c MobileCode) LimitKeyParts() []string { return []string{c.Mobile, c.CountryCode} }

// NewMobileCode creates a MobileCode from a base Code.
// Returns an error if required fields are missing.
func NewMobileCode(base Code, mobile, countryCode string) (*MobileCode, error) {
	mc := &MobileCode{Code: base, Mobile: mobile, CountryCode: countryCode}
	if err := mc.Validate(); err != nil {
		return nil, err
	}
	return mc, nil
}

// Validate checks that all required fields are populated.
func (c MobileCode) Validate() error {
	if c.Mobile == "" {
		return ErrMobileCodeMobileIsEmpty
	}
	if c.CountryCode == "" {
		return ErrMobileCodeCountryCodeIsEmpty
	}
	return c.Code.validate()
}

// EmailCode represents an email verification code.
type EmailCode struct {
	Code
	Email string `json:"email"`
}

func (c EmailCode) Medium() string          { return "EMAIL" }
func (c EmailCode) CacheKeyParts() []string { return []string{c.Sequence, c.Email} }
func (c EmailCode) LimitKeyParts() []string { return []string{c.Email} }

// NewEmailCode creates an EmailCode from a base Code.
// Returns an error if required fields are missing.
func NewEmailCode(base Code, email string) (*EmailCode, error) {
	ec := &EmailCode{Code: base, Email: email}
	if err := ec.Validate(); err != nil {
		return nil, err
	}
	return ec, nil
}

// Validate checks that all required fields are populated.
func (c EmailCode) Validate() error {
	if c.Email == "" {
		return ErrEmailCodeEmailIsEmpty
	}
	return c.Code.validate()
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

// NewEcdsaCode creates an EcdsaCode from a base Code.
// Appends a timestamp to the code for ECDSA challenge uniqueness.
// Returns an error if required fields are missing.
func NewEcdsaCode(base Code, chain, address string) (*EcdsaCode, error) {
	base.Value = fmt.Sprintf("%s-%d", base.Value, timeNow().UnixNano())
	ec := &EcdsaCode{Code: base, Chain: chain, Address: address}
	if err := ec.Validate(); err != nil {
		return nil, err
	}
	return ec, nil
}

// Validate checks that all required fields are populated.
func (c EcdsaCode) Validate() error {
	if c.Chain == "" {
		return ErrEcdsaCodeChainIsEmpty
	}
	if c.Address == "" {
		return ErrEcdsaCodeAddressIsEmpty
	}
	return c.Code.validate()
}

// VerificationCode is a type-set constraint for all verification code types.
type VerificationCode interface {
	MobileCode | EmailCode | EcdsaCode
}

// CodeConstraint is the unified generic constraint for OTPService.
// It combines the type-set restriction with all required method behaviors.
type CodeConstraint interface {
	VerificationCode
	GetValue() string        // returns the raw code string for comparison
	Medium() string          // e.g. "MOBILE", "EMAIL", "ECDSA"
	CacheKeyParts() []string // e.g. [sequence, mobile, countryCode]
	LimitKeyParts() []string // e.g. [mobile, countryCode]  (no sequence)
	GetSequence() string
	GetType() CodeType
	Validate() error // validates all required fields
}

// CodeSender sends a verification code.
type CodeSender[T VerificationCode] interface {
	Send(ctx context.Context, code *T) error
}

// EmailTemplate represents an email template with subject and body format.
type EmailTemplate struct {
	// Subject is the email subject line.
	Subject string `json:"subject"`
	// BodyFormat is the email body format string.
	// Use {{code}} as the placeholder for the verification code.
	BodyFormat string `json:"body_format"`
	// ContentType specifies the MIME type: "text/plain" or "text/html".
	// Defaults to "text/plain" if empty.
	ContentType string `json:"content_type"`
}

// SMSTemplate represents an SMS template with code and sign.
type SMSTemplate struct {
	TaskID       string `json:"task_id"`       // Optional: used for global SMS
	Code         string `json:"code"`          // Template code
	SignName     string `json:"sign_name"`     // Sign name
	ParamsFormat string `json:"params_format"` // JSON format string, e.g., `{"code":"%s"}`
}

// Template is a type constraint for all template types.
type Template interface {
	EmailTemplate | SMSTemplate
}

// TemplateProvider provides template lookup by CodeType.
type TemplateProvider[T Template] interface {
	GetTemplate(typ CodeType) (*T, error)
}
