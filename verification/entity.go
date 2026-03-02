package verification

import "context"

type CodeType string

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

// EmailCode represents an email verification code.
type EmailCode struct {
	Code
	Email string `json:"email"`
}

func (c EmailCode) Medium() string          { return "EMAIL" }
func (c EmailCode) CacheKeyParts() []string { return []string{c.Sequence, c.Email} }
func (c EmailCode) LimitKeyParts() []string { return []string{c.Email} }

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
