package verification

import (
	"context"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/crypto-zero/go-kit/text"
)

// CodeFactory generates sequences and verification codes.
type CodeFactory interface {
	// NewSequence generates a new unique sequence id for the code.
	NewSequence() string
	// NewCode generates a new numeric code.
	NewCode() (string, int32)
}

var (
	_ CodeFactory = (*basicCodeFactory)(nil)
	_ CodeFactory = (*defaultNumberCodeFactory)(nil)
	_ CodeFactory = (*staticCodeFactory)(nil)
)

// basicCodeFactory is the default factory implementation.
// It provides the standard sequence and code strategies.
// Sequence uses time + rand; numeric code uses go-kit text helper.
type basicCodeFactory struct{}

func (basicCodeFactory) NewSequence() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), rand.Int64())
}

func (basicCodeFactory) NewNumericCode(n int) (string, int32) {
	if n <= 0 {
		n = 4
	}
	return text.RandStringWithCharset(n, "0123456789"), int32(n)
}

func (b basicCodeFactory) NewCode() (string, int32) {
	return b.NewNumericCode(6) // default 6-digit code
}

type defaultNumberCodeFactory struct {
	basicCodeFactory
	size int // code size, e.g., 4 or 6
}

func (f defaultNumberCodeFactory) NewCode() (string, int32) {
	return f.NewNumericCode(f.size)
}

// NewDefaultNumberCodeFactory returns a CodeFactory that generates numeric codes
// of a specified length (default 6 digits).
func NewDefaultNumberCodeFactory(size int) CodeFactory {
	return defaultNumberCodeFactory{size: size}
}

// staticCodeFactory is a factory that always returns the same code.
type staticCodeFactory struct {
	basicCodeFactory
}

// NewCode implements CodeFactory interface.
func (staticCodeFactory) NewCode() (string, int32) {
	return "666666", 6 // fixed code for testing
}

// CodeGenerator represents a verification code generator.
type CodeGenerator interface {
	// NewMobileCode generates a new mobile verification code.
	NewMobileCode(ctx context.Context, typ string, userID int64, mobile, countryCode string) (*MobileCode, error)
	// NewEmailCode generates a new email verification code.
	NewEmailCode(ctx context.Context, typ string, userID int64, email string) (*EmailCode, error)
	// NewEcdsaCode generates a new ecdsa verification code.
	NewEcdsaCode(ctx context.Context, typ string, userID int64, chain, address string) (*EcdsaCode, error)
}

// defaultCodeGenerator uses the factory test code (fixed 666666).
// It implements CodeGenerator.

type defaultCodeGenerator struct{ CodeFactory }

// Compile-time assertions: generators implement CodeGenerator.
var _ CodeGenerator = (*defaultCodeGenerator)(nil)

func (g *defaultCodeGenerator) NewMobileCode(
	_ context.Context, typ string, userID int64, mobile, countryCode string,
) (*MobileCode, error) {
	if typ == "" {
		return nil, ErrCodeTypeIsEmpty
	}
	seq := g.NewSequence()
	code, clen := g.NewCode()
	return &MobileCode{
		Code: Code{
			UserID:     userID,
			Type:       strings.ToUpper(typ),
			Sequence:   seq,
			CodeLength: clen,
			Code:       code,
			Content:    "Your verification code is: %s.",
			Args:       []any{code},
			Format:     fmt.Sprintf,
		},
		Mobile:      mobile,
		CountryCode: countryCode,
	}, nil
}

func (g *defaultCodeGenerator) NewEmailCode(
	_ context.Context, typ string, userID int64, email string,
) (*EmailCode, error) {
	if typ == "" {
		return nil, ErrCodeTypeIsEmpty
	}
	seq := g.NewSequence()
	code, clen := g.NewCode()
	return &EmailCode{
		Code: Code{
			UserID:     userID,
			Type:       strings.ToUpper(typ),
			Sequence:   seq,
			CodeLength: clen,
			Code:       code,
			Content:    "Your verification code is: %s.",
			Args:       []any{code},
			Format:     fmt.Sprintf,
		},
		Email: email,
	}, nil
}

func (g *defaultCodeGenerator) NewEcdsaCode(
	_ context.Context, typ string, userID int64, chain, publicKeyHex string,
) (*EcdsaCode, error) {
	if typ == "" {
		return nil, ErrCodeTypeIsEmpty
	}
	seq := g.NewSequence()
	code, clen := g.NewCode()
	code = fmt.Sprintf("%s-%d", code, time.Now().UnixNano())
	return &EcdsaCode{
		Code: Code{
			UserID:     userID,
			Type:       strings.ToUpper(typ),
			Sequence:   seq,
			CodeLength: clen,
			Code:       code,
			Content:    "Your verification code is: %s.",
			Args:       []any{code},
			Format:     fmt.Sprintf,
		},
		Chain:   chain,
		Address: publicKeyHex,
	}, nil
}

// DefaultCodeGenerator returns the fixed test code ("666666").
var DefaultCodeGenerator CodeGenerator = &defaultCodeGenerator{CodeFactory: staticCodeFactory{}}

// FourDigitCodeGenerator returns random 4-digit numeric codes.
var FourDigitCodeGenerator CodeGenerator = &defaultCodeGenerator{CodeFactory: NewDefaultNumberCodeFactory(4)}
