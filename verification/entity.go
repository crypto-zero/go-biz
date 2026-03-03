package verification

import (
	"context"
	"fmt"
	"time"
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

// NewMobileCode creates a MobileCode from a base Code.
func NewMobileCode(base Code, mobile, countryCode string) *MobileCode {
	return &MobileCode{Code: base, Mobile: mobile, CountryCode: countryCode}
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

// NewEmailCode creates an EmailCode from a base Code.
func NewEmailCode(base Code, email string) *EmailCode {
	return &EmailCode{Code: base, Email: email}
}

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

// NewEcdsaCode creates an EcdsaCode from a base Code.
// Appends a timestamp to the code for ECDSA challenge uniqueness.
func NewEcdsaCode(base Code, chain, address string) *EcdsaCode {
	base.Code = fmt.Sprintf("%s-%d", base.Code, time.Now().UnixNano())
	base.Content = fmt.Sprintf("Your verification code is: %s.", base.Code)
	return &EcdsaCode{Code: base, Chain: chain, Address: address}
}

// Verifiable is satisfied by any code type that can return its verification code string.
type Verifiable interface {
	VerificationCode() string
}

// Codeable extends Verifiable with key-building metadata.
// Satisfied by MobileCode, EmailCode, EcdsaCode via their methods.
type Codeable interface {
	Verifiable
	Medium() string          // e.g. "MOBILE", "EMAIL", "ECDSA"
	CacheKeyParts() []string // e.g. [sequence, mobile, countryCode]
	LimitKeyParts() []string // e.g. [mobile, countryCode]  (no sequence)
	GetSequence() string
	GetType() CodeType
}

// VerificationCode is a type constraint for all verification code types.
type VerificationCode interface {
	MobileCode | EmailCode | EcdsaCode
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
