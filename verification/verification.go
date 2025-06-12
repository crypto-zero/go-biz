package verification

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	// ErrCodeNotFound represents a verification code not found error.
	ErrCodeNotFound = errors.New("verification code not found")
	// ErrCodeTypeIsEmpty represents a verification code type is empty error.
	ErrCodeTypeIsEmpty = errors.New("verification code type is empty")
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

// CodeGenerator represents a verification code generator.
type CodeGenerator interface {
	// NewMobileCode generates a new mobile verification code.
	NewMobileCode(ctx context.Context, typ string, userID int64, mobile,
		countryCode string) (*MobileCode, error)
	// NewEmailCode generates a new email verification code.
	NewEmailCode(ctx context.Context, typ string, userID int64, email string,
	) (*EmailCode, error)
	// NewEcdsaCode generates a new ecdsa verification code.
	NewEcdsaCode(ctx context.Context, typ string, userID int64, chain,
		address string) (*EcdsaCode, error)
}

// CodeCacheKeyPrefix represents a verification code cache key prefix.
type CodeCacheKeyPrefix string

// CodeCache represents a verification code cache.
type CodeCache interface {
	// SetMobileCode sets the mobile verification code.
	SetMobileCode(ctx context.Context, code *MobileCode,
		expire time.Duration) error
	// SetEmailCode sets the email verification code.
	SetEmailCode(ctx context.Context, code *EmailCode,
		expire time.Duration) error
	// SetEcdsaCode sets the ecdsa verification code.
	SetEcdsaCode(ctx context.Context, code *EcdsaCode,
		expire time.Duration) error
	// GetMobileCode gets the mobile verification code.
	GetMobileCode(ctx context.Context, typ, sequence, mobile, countryCode string) (
		*MobileCode, error)
	// GetEmailCode gets the email verification code.
	GetEmailCode(ctx context.Context, typ, sequence, email string) (
		*EmailCode, error)
	// GetEcdsaCode gets the ecdsa verification code.
	GetEcdsaCode(ctx context.Context, typ, sequence, chain, address string) (
		*EcdsaCode, error)
}

// EmailCodeSender represents an email verification code sender.
type EmailCodeSender interface {
	// Send the email verification code.
	Send(ctx context.Context, code *EmailCode) error
}

// StaticCodeGenerator represents a static verification code generator.
type StaticCodeGenerator struct{}

func (s StaticCodeGenerator) NewSequence() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), rand.Int64())
}

func (s StaticCodeGenerator) NewCode() (code string, length int32) {
	return "666666", 6 // nolint // always return 666666 for testing
}

func (s StaticCodeGenerator) NewMobileCode(_ context.Context,
	typ string, userID int64, mobile, countryCode string,
) (*MobileCode, error) {
	if typ == "" {
		return nil, ErrCodeTypeIsEmpty
	}
	sequence := s.NewSequence()
	code, codeLength := s.NewCode()
	return &MobileCode{
		Code: Code{
			UserID:     userID,
			Type:       strings.ToUpper(typ),
			Sequence:   sequence,
			CodeLength: codeLength,
			Code:       code,
			Content:    "Your verification code is: %s.",
			Args:       []any{code},
			Format:     fmt.Sprintf,
		},
		Mobile:      mobile,
		CountryCode: countryCode,
	}, nil
}

func (s StaticCodeGenerator) NewEmailCode(_ context.Context,
	typ string, userID int64, email string,
) (*EmailCode, error) {
	if typ == "" {
		return nil, ErrCodeTypeIsEmpty
	}
	sequence := s.NewSequence()
	code, codeLength := s.NewCode()
	return &EmailCode{
		Code: Code{
			UserID:     userID,
			Type:       strings.ToUpper(typ),
			Sequence:   sequence,
			CodeLength: codeLength,
			Code:       code,
			Content:    "Your verification code is: %s.",
			Args:       []any{code},
			Format:     fmt.Sprintf,
		},
		Email: email,
	}, nil
}

func (s StaticCodeGenerator) NewEcdsaCode(_ context.Context,
	typ string, userID int64, chain, publicKeyHex string,
) (*EcdsaCode, error) {
	if typ == "" {
		return nil, ErrCodeTypeIsEmpty
	}
	sequence := s.NewSequence()
	code, codeLength := s.NewCode()
	code = fmt.Sprintf("%s-%d", code, time.Now().UnixNano())
	return &EcdsaCode{
		Code: Code{
			UserID:     userID,
			Type:       strings.ToUpper(typ),
			Sequence:   sequence,
			CodeLength: codeLength,
			Code:       code,
			Content:    "Your verification code is: %s.",
			Args:       []any{code},
			Format:     fmt.Sprintf,
		},
		Chain:   chain,
		Address: publicKeyHex,
	}, nil
}

// NewStaticCodeGenerator creates a new static verification code generator.
func NewStaticCodeGenerator() CodeGenerator {
	return &StaticCodeGenerator{}
}

// MockEmailCodeSender represents a mock email verification code sender.
type MockEmailCodeSender struct{}

func (m MockEmailCodeSender) Send(_ context.Context, _ *EmailCode) error {
	return nil
}

// NewMockEmailCodeSender creates a new mock email verification code sender.
func NewMockEmailCodeSender() EmailCodeSender {
	return &MockEmailCodeSender{}
}

// CodeCacheImpl is a struct that implements CodeCache interface
type CodeCacheImpl struct {
	prefix CodeCacheKeyPrefix
	client redis.UniversalClient
}

func (v CodeCacheImpl) MobileCodeKey(typ, sequence, mobile, countryCode string) string {
	typ = strings.ToUpper(typ)
	return fmt.Sprintf("%s:VERIFICATION_CODE:MOBILE:%s:%s:%s:%s", v.prefix, typ,
		sequence, mobile, countryCode)
}

func (v CodeCacheImpl) EmailCodeKey(typ, sequence, email string) string {
	typ = strings.ToUpper(typ)
	return fmt.Sprintf("%s:VERIFICATION_CODE:EMAIL:%s:%s:%s", v.prefix, typ, sequence,
		email)
}

func (v CodeCacheImpl) EcdsaCodeKey(typ, sequence, chain,
	address string,
) string {
	typ = strings.ToUpper(typ)
	return fmt.Sprintf("%s:VERIFICATION_CODE:ECDSA:%s:%s:%s:%s", v.prefix, typ, sequence, chain, address)
}

func (v CodeCacheImpl) SetMobileCode(ctx context.Context, code *MobileCode, expire time.Duration) (err error) {
	var buffer bytes.Buffer
	encode := gob.NewEncoder(&buffer)
	if err = encode.Encode(code); err != nil {
		return fmt.Errorf("failed to encode mobile verification code: %w", err)
	}
	key := v.MobileCodeKey(code.Type, code.Sequence, code.Mobile, code.CountryCode)
	if err = v.client.Set(ctx, key, buffer.Bytes(), expire).Err(); err != nil {
		return fmt.Errorf("failed to set mobile verification code: %w", err)
	}
	return nil
}

func (v CodeCacheImpl) SetEmailCode(ctx context.Context, code *EmailCode, expire time.Duration) error {
	var buffer bytes.Buffer
	encode := gob.NewEncoder(&buffer)
	if err := encode.Encode(code); err != nil {
		return fmt.Errorf("failed to encode email verification code: %w", err)
	}
	key := v.EmailCodeKey(code.Type, code.Sequence, code.Email)
	if err := v.client.Set(ctx, key, buffer.Bytes(), expire).Err(); err != nil {
		return fmt.Errorf("failed to set email verification code: %w", err)
	}
	return nil
}

func (v CodeCacheImpl) SetEcdsaCode(ctx context.Context, code *EcdsaCode, expire time.Duration) error {
	var buffer bytes.Buffer
	encode := gob.NewEncoder(&buffer)
	if err := encode.Encode(code); err != nil {
		return fmt.Errorf("failed to encode ecdsa verification code: %w", err)
	}
	key := v.EcdsaCodeKey(code.Type, code.Sequence, code.Chain, code.Address)
	if err := v.client.Set(ctx, key, buffer.Bytes(), expire).Err(); err != nil {
		return fmt.Errorf("failed to set ecdsa verification code: %w", err)
	}
	return nil
}

func (v CodeCacheImpl) GetMobileCode(ctx context.Context,
	typ, sequence, mobile, countryCode string,
) (*MobileCode, error) {
	key := v.MobileCodeKey(typ, sequence, mobile, countryCode)
	data, err := v.client.GetDel(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get mobile verification code: %w", err)
	}
	var code MobileCode
	decode := gob.NewDecoder(bytes.NewReader(data))
	if err = decode.Decode(&code); err != nil {
		return nil, fmt.Errorf("failed to decode mobile verification code: %w", err)
	}
	return &code, nil
}

func (v CodeCacheImpl) GetEmailCode(ctx context.Context, typ, sequence, email string,
) (*EmailCode, error) {
	key := v.EmailCodeKey(typ, sequence, email)
	data, err := v.client.GetDel(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get email verification code: %w", err)
	}
	var code EmailCode
	decode := gob.NewDecoder(bytes.NewReader(data))
	if err = decode.Decode(&code); err != nil {
		return nil, fmt.Errorf("failed to decode email verification code: %w", err)
	}
	return &code, nil
}

func (v CodeCacheImpl) GetEcdsaCode(ctx context.Context, typ, sequence, chain, address string,
) (*EcdsaCode, error) {
	key := v.EcdsaCodeKey(typ, sequence, chain, address)
	data, err := v.client.GetDel(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get ecdsa verification code: %w", err)
	}
	var code EcdsaCode
	decode := gob.NewDecoder(bytes.NewReader(data))
	if err = decode.Decode(&code); err != nil {
		return nil, fmt.Errorf("failed to decode ecdsa verification code: %w", err)
	}
	return &code, nil
}

// NewCodeCacheImpl is a function that returns a new CodeCacheImpl
func NewCodeCacheImpl(prefix CodeCacheKeyPrefix, client redis.UniversalClient) CodeCache {
	return &CodeCacheImpl{
		prefix: prefix,
		client: client,
	}
}
