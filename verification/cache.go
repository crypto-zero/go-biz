package verification

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// CodeCacheKeyPrefix represents a verification code cache key prefix.
type CodeCacheKeyPrefix string

// CodeCache represents a verification code cache.
type CodeCache interface {
	// SetMobileCode sets the mobile verification code.
	SetMobileCode(ctx context.Context, code *MobileCode, expire time.Duration) error
	// SetEmailCode sets the email verification code.
	SetEmailCode(ctx context.Context, code *EmailCode, expire time.Duration) error
	// SetEcdsaCode sets the ecdsa verification code.
	SetEcdsaCode(ctx context.Context, code *EcdsaCode, expire time.Duration) error
	// GetMobileCode gets the mobile verification code.
	GetMobileCode(ctx context.Context, typ CodeType, sequence, mobile, countryCode string) (
		*MobileCode, error,
	)
	// PeekMobileCode gets the mobile verification code without deleting it.
	PeekMobileCode(ctx context.Context, typ CodeType, sequence, mobile, countryCode string) (*MobileCode, error)
	// DeleteMobileCode deletes the stored mobile verification code.
	DeleteMobileCode(ctx context.Context, typ CodeType, sequence, mobile, countryCode string) error
	// GetEmailCode gets the email verification code.
	GetEmailCode(ctx context.Context, typ CodeType, sequence, email string) (*EmailCode, error)
	// PeekEmailCode gets the email verification code without deleting it.
	PeekEmailCode(ctx context.Context, typ CodeType, sequence, email string) (*EmailCode, error)
	// DeleteEmailCode deletes the stored email verification code.
	DeleteEmailCode(ctx context.Context, typ CodeType, sequence, email string) error
	// GetEcdsaCode gets the ecdsa verification code.
	GetEcdsaCode(ctx context.Context, typ CodeType, sequence, chain, address string) (*EcdsaCode, error)
	// PeekEcdsaCode gets the ecdsa verification code without deleting it.
	PeekEcdsaCode(ctx context.Context, typ CodeType, sequence, chain, address string) (*EcdsaCode, error)
	// DeleteEcdsaCode deletes the stored ecdsa verification code.
	DeleteEcdsaCode(ctx context.Context, typ CodeType, sequence, chain, address string) error
}

// ============================================================================
// Cache (Redis gob serialization)
// ============================================================================

// CodeCacheImpl is a struct that implements CodeCache interface
type CodeCacheImpl struct {
	prefix CodeCacheKeyPrefix
	client redis.UniversalClient
}

// Compile-time assertion: CodeCacheImpl implements CodeCache.
var _ CodeCache = (*CodeCacheImpl)(nil)

// NewCodeCacheImpl is a function that returns a new CodeCacheImpl
func NewCodeCacheImpl(prefix CodeCacheKeyPrefix, client redis.UniversalClient) CodeCache {
	return &CodeCacheImpl{
		prefix: prefix,
		client: client,
	}
}

func (v CodeCacheImpl) MobileCodeKey(typ CodeType, sequence, mobile, countryCode string) string {
	return fmt.Sprintf(
		"%s:VERIFICATION_CODE:MOBILE:%s:%s:%s:%s", v.prefix, strings.ToUpper(string(typ)),
		sequence, mobile, countryCode,
	)
}

func (v CodeCacheImpl) EmailCodeKey(typ CodeType, sequence, email string) string {
	return fmt.Sprintf(
		"%s:VERIFICATION_CODE:EMAIL:%s:%s:%s", v.prefix, strings.ToUpper(string(typ)), sequence,
		email,
	)
}

func (v CodeCacheImpl) EcdsaCodeKey(typ CodeType, sequence, chain, address string,
) string {
	return fmt.Sprintf(
		"%s:VERIFICATION_CODE:ECDSA:%s:%s:%s:%s",
		v.prefix, strings.ToUpper(string(typ)), sequence, chain, address,
	)
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

func (v CodeCacheImpl) GetMobileCode(ctx context.Context, typ CodeType, sequence, mobile, countryCode string,
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

func (v CodeCacheImpl) GetEmailCode(ctx context.Context, typ CodeType, sequence, email string,
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

func (v CodeCacheImpl) GetEcdsaCode(ctx context.Context, typ CodeType, sequence, chain, address string,
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

func (v CodeCacheImpl) PeekMobileCode(ctx context.Context, typ CodeType, sequence, mobile, countryCode string) (
	*MobileCode, error,
) {
	key := v.MobileCodeKey(typ, sequence, mobile, countryCode)
	data, err := v.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to peek mobile verification code: %w", err)
	}

	var code MobileCode
	decode := gob.NewDecoder(bytes.NewReader(data))
	if err = decode.Decode(&code); err != nil {
		return nil, fmt.Errorf("failed to decode mobile verification code: %w", err)
	}
	return &code, nil
}

func (v CodeCacheImpl) DeleteMobileCode(ctx context.Context, typ CodeType, sequence, mobile, countryCode string) error {
	key := v.MobileCodeKey(typ, sequence, mobile, countryCode)
	if err := v.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete mobile verification code: %w", err)
	}
	return nil
}

func (v CodeCacheImpl) PeekEmailCode(ctx context.Context, typ CodeType, sequence, email string) (*EmailCode, error) {
	key := v.EmailCodeKey(typ, sequence, email)
	data, err := v.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to peek email verification code: %w", err)
	}

	var code EmailCode
	decode := gob.NewDecoder(bytes.NewReader(data))
	if err = decode.Decode(&code); err != nil {
		return nil, fmt.Errorf("failed to decode email verification code: %w", err)
	}
	return &code, nil
}

func (v CodeCacheImpl) DeleteEmailCode(ctx context.Context, typ CodeType, sequence, email string) error {
	key := v.EmailCodeKey(typ, sequence, email)
	if err := v.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete email verification code: %w", err)
	}
	return nil
}

func (v CodeCacheImpl) PeekEcdsaCode(ctx context.Context, typ CodeType, sequence, chain, address string) (*EcdsaCode, error) {
	key := v.EcdsaCodeKey(typ, sequence, chain, address)
	data, err := v.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to peek ecdsa verification code: %w", err)
	}

	var code EcdsaCode
	decode := gob.NewDecoder(bytes.NewReader(data))
	if err = decode.Decode(&code); err != nil {
		return nil, fmt.Errorf("failed to decode ecdsa verification code: %w", err)
	}
	return &code, nil
}

func (v CodeCacheImpl) DeleteEcdsaCode(ctx context.Context, typ CodeType, sequence, chain, address string) error {
	key := v.EcdsaCodeKey(typ, sequence, chain, address)
	if err := v.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete ecdsa verification code: %w", err)
	}
	return nil
}
