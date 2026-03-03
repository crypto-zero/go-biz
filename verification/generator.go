package verification

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/crypto-zero/go-kit/text"
)

// CodeGenerator generates verification codes for all channels.
type CodeGenerator interface {
	NewMobileCode(ctx context.Context, typ CodeType, userID int64, mobile, countryCode string) (*MobileCode, error)
	NewEmailCode(ctx context.Context, typ CodeType, userID int64, email string) (*EmailCode, error)
	NewEcdsaCode(ctx context.Context, typ CodeType, userID int64, chain, address string) (*EcdsaCode, error)
}

// codeGenerator is the standard CodeGenerator implementation.
// Use NewCodeGenerator or NewTestCodeGenerator to create.
type codeGenerator struct {
	codeLength int
	staticCode string // if non-empty, always return this code (for testing)
}

var _ CodeGenerator = (*codeGenerator)(nil)

// NewCodeGenerator creates a generator that produces random numeric codes of the given length.
func NewCodeGenerator(codeLength int) CodeGenerator {
	if codeLength <= 0 {
		codeLength = 6
	}
	return &codeGenerator{codeLength: codeLength}
}

// DefaultCodeGenerator is a convenience CodeGenerator that produces 6-digit random codes.
var DefaultCodeGenerator = NewCodeGenerator(6)

// NewTestCodeGenerator creates a generator that always produces the given fixed code.
// Intended for testing only — do not use in production.
func NewTestCodeGenerator(code string) CodeGenerator {
	return &codeGenerator{codeLength: len(code), staticCode: code}
}

func (g *codeGenerator) newSequence() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (g *codeGenerator) newCode() (string, int32) {
	if g.staticCode != "" {
		return g.staticCode, int32(g.codeLength)
	}
	return text.RandStringWithCharset(g.codeLength, "0123456789"), int32(g.codeLength)
}

func (g *codeGenerator) newBaseCode(typ CodeType, userID int64) (Code, error) {
	if typ == "" {
		return Code{}, ErrCodeTypeIsEmpty
	}
	seq := g.newSequence()
	code, clen := g.newCode()
	return Code{
		UserID:     userID,
		Type:       CodeType(strings.ToUpper(string(typ))),
		Sequence:   seq,
		CodeLength: clen,
		Code:       code,
		Content:    fmt.Sprintf("Your verification code is: %s.", code),
	}, nil
}

func (g *codeGenerator) NewMobileCode(
	_ context.Context, typ CodeType, userID int64, mobile, countryCode string,
) (*MobileCode, error) {
	base, err := g.newBaseCode(typ, userID)
	if err != nil {
		return nil, err
	}
	return NewMobileCode(base, mobile, countryCode), nil
}

func (g *codeGenerator) NewEmailCode(
	_ context.Context, typ CodeType, userID int64, email string,
) (*EmailCode, error) {
	base, err := g.newBaseCode(typ, userID)
	if err != nil {
		return nil, err
	}
	return NewEmailCode(base, email), nil
}

func (g *codeGenerator) NewEcdsaCode(
	_ context.Context, typ CodeType, userID int64, chain, address string,
) (*EcdsaCode, error) {
	base, err := g.newBaseCode(typ, userID)
	if err != nil {
		return nil, err
	}
	return NewEcdsaCode(base, chain, address), nil
}
