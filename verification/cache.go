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

const expectedResultLen = 4

// fixedWindowScript is a Lua script for fixed-window rate limiting.
// It performs an atomic INCR and sets PEXPIRE on the first increment.
// Returns a table: {allowed(0/1), current_count, limit, ttl_ms}
var fixedWindowScript = redis.NewScript(`
-- Fixed-window counter with atomic initialization
-- Returns: {allowed(0/1), current_count, limit, ttl_ms}

local key        = KEYS[1]
local limit      = tonumber(ARGV[1])
local window_ms  = tonumber(ARGV[2])

-- 1) Atomically initialize key with expiration if not exists
--    If key exists, SET NX fails but doesn't affect the existing value
redis.call('SET', key, 0, 'PX', window_ms, 'NX')

-- 2) Increment counter (works whether SET succeeded or not)
local current = redis.call('INCR', key)

-- 3) Get remaining TTL
local ttl = redis.call('PTTL', key)
if ttl == -1 then  -- Defensive: ensure expiration is always set
  redis.call('PEXPIRE', key, window_ms)
  ttl = window_ms
end

-- 4) Decide if allowed
local allowed = 0
if current <= limit then
  allowed = 1
end

return {allowed, current, limit, ttl}
`)

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

// LimitDecision captures a single limiter evaluation result.
type LimitDecision struct {
	Allowed bool          // whether the action is allowed
	Count   int64         // current count in the window
	Limit   int64         // configured limit
	ResetIn time.Duration // time until the window resets
}

type CodeLimiterCache interface {
	// AllowSendMobile applies a fixed-window limit for mobile verification attempts.
	AllowSendMobile(ctx context.Context, typ CodeType, mobile, countryCode string, limit int64, window time.Duration) (*LimitDecision, error)
	// AllowSendEmail applies a fixed-window limit for email verification attempts.
	AllowSendEmail(ctx context.Context, typ CodeType, email string, limit int64, window time.Duration) (*LimitDecision, error)
	// AllowSendEcdsa applies a fixed-window limit for ecdsa verification attempts.
	AllowSendEcdsa(ctx context.Context, typ CodeType, chain, address string, limit int64, window time.Duration) (*LimitDecision, error)

	// GetMobileCodeIncorrectCount get the current count of mobile verification attempts.
	GetMobileCodeIncorrectCount(ctx context.Context, typ CodeType, sequence, mobile, countryCode string) (int64, error)
	// GetEmailCodeIncorrectCount get the current count of email verification attempts.
	GetEmailCodeIncorrectCount(ctx context.Context, typ CodeType, sequence, email string) (int64, error)
	// GetEcdsaCodeIncorrectCount get the current count of ecdsa verification attempts.
	GetEcdsaCodeIncorrectCount(ctx context.Context, typ CodeType, sequence, chain, address string) (int64, error)

	// IncrementMobileCodeIncorrect increment a verification incorrect and returns lock status
	IncrementMobileCodeIncorrect(ctx context.Context, typ CodeType, sequence, mobile, countryCode string, maxAttempts int64, window time.Duration) (*LimitDecision, error)
	// IncrementEmailCodeIncorrect increment a verification incorrect and returns lock status
	IncrementEmailCodeIncorrect(ctx context.Context, typ CodeType, sequence, email string, maxAttempts int64, window time.Duration) (*LimitDecision, error)
	// IncrementEcdsaCodeIncorrect increment a verification incorrect and returns lock status
	IncrementEcdsaCodeIncorrect(ctx context.Context, typ CodeType, sequence, chain, address string, maxAttempts int64, window time.Duration) (*LimitDecision, error)

	// DeleteMobileCodeIncorrect deletes the incorrect count (call on successful verification)
	DeleteMobileCodeIncorrect(ctx context.Context, typ CodeType, sequence, mobile, countryCode string) error
	// DeleteEmailCodeIncorrect deletes the incorrect count (call on successful verification)
	DeleteEmailCodeIncorrect(ctx context.Context, typ CodeType, sequence, email string) error
	// DeleteEcdsaCodeIncorrect deletes the incorrect count (call on successful verification)
	DeleteEcdsaCodeIncorrect(ctx context.Context, typ CodeType, sequence, chain, address string) error
}

// NewCodeLimiterCacheImpl creates a new instance of CodeLimiterCacheImpl.
func NewCodeLimiterCacheImpl(prefix CodeCacheKeyPrefix, client redis.UniversalClient) CodeLimiterCache {
	return &CodeLimiterCacheImpl{
		prefix: prefix,
		client: client,
	}
}

// CodeLimiterCacheImpl is a struct that implements CodeLimiterCache interface
type CodeLimiterCacheImpl struct {
	prefix CodeCacheKeyPrefix
	client redis.UniversalClient
}

// Compile-time assertion: CodeLimiterCacheImpl implements CodeLimiterCache.
var _ CodeLimiterCache = (*CodeLimiterCacheImpl)(nil)

func (v *CodeLimiterCacheImpl) evalFixedWindow(ctx context.Context, key string, limit int64, window time.Duration,
) (*LimitDecision, error) {

	if window <= 0 {
		return nil, fmt.Errorf("invalid window duration: %d", window)
	}

	if limit <= 0 {
		return nil, fmt.Errorf("invalid limit: %d", limit)
	}

	res, err := fixedWindowScript.Run(ctx, v.client, []string{key}, limit, window.Milliseconds()).Int64Slice()
	if err != nil {
		return nil, fmt.Errorf("limiter eval failed: %w", err)
	}
	if len(res) != expectedResultLen {
		return nil, fmt.Errorf("limiter eval unexpected result length: got %d, want %d", len(res),
			expectedResultLen)
	}
	return &LimitDecision{
		Allowed: res[0] == 1,
		Count:   res[1],
		Limit:   res[2],
		ResetIn: time.Duration(res[3]) * time.Millisecond,
	}, nil
}

func (v *CodeLimiterCacheImpl) buildKey(category, medium string, parts ...string) string {
	allParts := append([]string{string(v.prefix), category, medium}, parts...)
	return strings.Join(allParts, ":")
}

// mobileIncorrectKey constructs the Redis key for mobile verification incorrect tracking.
func (v *CodeLimiterCacheImpl) mobileIncorrectKey(typ CodeType, sequence, mobile, countryCode string) string {
	return v.buildKey("VERIFICATION_FAILURE", "MOBILE", strings.ToUpper(string(typ)), sequence, mobile, countryCode)
}

// emailIncorrectKey constructs the Redis key for email verification incorrect tracking.
func (v *CodeLimiterCacheImpl) emailIncorrectKey(typ CodeType, sequence, email string) string {
	return v.buildKey("VERIFICATION_FAILURE", "EMAIL", strings.ToUpper(string(typ)), sequence, email)
}

// ecdsaIncorrectKey constructs the Redis key for ecdsa verification incorrect tracking.
func (v *CodeLimiterCacheImpl) ecdsaIncorrectKey(typ CodeType, sequence, chain, address string) string {
	return v.buildKey("VERIFICATION_FAILURE", "ECDSA", strings.ToUpper(string(typ)), sequence, chain, address)
}

// mobileLimitKey constructs the Redis key for mobile verification limits.
func (v *CodeLimiterCacheImpl) mobileLimitKey(typ CodeType, mobile, countryCode string) string {
	return v.buildKey("VERIFICATION_SEND_LIMIT", "MOBILE", strings.ToUpper(string(typ)), mobile, countryCode)
}

// emailLimitKey constructs the Redis key for email verification limits.
func (v *CodeLimiterCacheImpl) emailLimitKey(typ CodeType, email string) string {
	return v.buildKey("VERIFICATION_SEND_LIMIT", "EMAIL", strings.ToUpper(string(typ)), email)
}

// ecdsaLimitKey constructs the Redis key for ecdsa verification limits.
func (v *CodeLimiterCacheImpl) ecdsaLimitKey(typ CodeType, chain, address string) string {
	return v.buildKey("VERIFICATION_SEND_LIMIT", "ECDSA", strings.ToUpper(string(typ)), chain, address)
}

// AllowSendMobile applies a fixed-window limit for mobile verification attempts.
func (v *CodeLimiterCacheImpl) AllowSendMobile(ctx context.Context, typ CodeType, mobile, countryCode string,
	limit int64, window time.Duration) (*LimitDecision, error) {
	return v.evalFixedWindow(ctx, v.mobileLimitKey(typ, mobile, countryCode), limit, window)
}

// AllowSendEmail applies a fixed-window limit for email verification attempts.
func (v *CodeLimiterCacheImpl) AllowSendEmail(ctx context.Context, typ CodeType, email string,
	limit int64, window time.Duration) (*LimitDecision, error) {
	return v.evalFixedWindow(ctx, v.emailLimitKey(typ, email), limit, window)
}

// AllowSendEcdsa applies a fixed-window limit for ecdsa verification attempts.
func (v *CodeLimiterCacheImpl) AllowSendEcdsa(ctx context.Context, typ CodeType, chain, address string,
	limit int64, window time.Duration) (*LimitDecision, error) {
	return v.evalFixedWindow(ctx, v.ecdsaLimitKey(typ, chain, address), limit, window)
}

// GetMobileCodeIncorrectCount gets the current count of mobile verification attempts.
func (v *CodeLimiterCacheImpl) GetMobileCodeIncorrectCount(ctx context.Context, typ CodeType, sequence, mobile, countryCode string) (int64, error) {
	cnt, err := v.client.Get(ctx, v.mobileIncorrectKey(typ, sequence, mobile, countryCode)).Int64()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("failed to get mobile verification incorrect count: %w", err)
	}
	return cnt, nil
}

// GetEmailCodeIncorrectCount gets the current count of email verification attempts.
func (v *CodeLimiterCacheImpl) GetEmailCodeIncorrectCount(ctx context.Context, typ CodeType, sequence, email string) (int64, error) {
	cnt, err := v.client.Get(ctx, v.emailIncorrectKey(typ, sequence, email)).Int64()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("failed to get email verification incorrect count: %w", err)
	}
	return cnt, nil
}

// GetEcdsaCodeIncorrectCount gets the current count of ecdsa verification attempts.
func (v *CodeLimiterCacheImpl) GetEcdsaCodeIncorrectCount(ctx context.Context, typ CodeType, sequence, chain, address string) (int64, error) {
	cnt, err := v.client.Get(ctx, v.ecdsaIncorrectKey(typ, sequence, chain, address)).Int64()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("failed to get ecdsa verification incorrect count: %w", err)
	}
	return cnt, nil
}

// IncrementMobileCodeIncorrect set a verification incorrect and returns lock status.
func (v *CodeLimiterCacheImpl) IncrementMobileCodeIncorrect(ctx context.Context, typ CodeType, sequence, mobile, countryCode string,
	maxAttempts int64, lockDuration time.Duration) (*LimitDecision, error) {
	return v.evalFixedWindow(ctx, v.mobileIncorrectKey(typ, sequence, mobile, countryCode), maxAttempts, lockDuration)
}

// IncrementEmailCodeIncorrect set a verification incorrect and returns lock status.
func (v *CodeLimiterCacheImpl) IncrementEmailCodeIncorrect(ctx context.Context, typ CodeType, sequence, email string,
	maxAttempts int64, lockDuration time.Duration) (*LimitDecision, error) {
	return v.evalFixedWindow(ctx, v.emailIncorrectKey(typ, sequence, email), maxAttempts, lockDuration)
}

// IncrementEcdsaCodeIncorrect set a verification incorrect and returns lock status.
func (v *CodeLimiterCacheImpl) IncrementEcdsaCodeIncorrect(ctx context.Context, typ CodeType, sequence, chain, address string,
	maxAttempts int64, lockDuration time.Duration) (*LimitDecision, error) {
	return v.evalFixedWindow(ctx, v.ecdsaIncorrectKey(typ, sequence, chain, address), maxAttempts, lockDuration)
}

// DeleteMobileCodeIncorrect clears the incorrect count.
func (v *CodeLimiterCacheImpl) DeleteMobileCodeIncorrect(ctx context.Context, typ CodeType, sequence, mobile, countryCode string) error {
	key := v.mobileIncorrectKey(typ, sequence, mobile, countryCode)
	if err := v.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to clear mobile verification incorrect: %w", err)
	}
	return nil
}

// DeleteEmailCodeIncorrect clears the incorrect count.
func (v *CodeLimiterCacheImpl) DeleteEmailCodeIncorrect(ctx context.Context, typ CodeType, sequence, email string) error {
	if err := v.client.Del(ctx, v.emailIncorrectKey(typ, sequence, email)).Err(); err != nil {
		return fmt.Errorf("failed to clear email verification incorrect: %w", err)
	}
	return nil
}

// DeleteEcdsaCodeIncorrect clears the incorrect count.
func (v *CodeLimiterCacheImpl) DeleteEcdsaCodeIncorrect(ctx context.Context, typ CodeType, sequence, chain,
	address string) error {
	if err := v.client.Del(ctx, v.ecdsaIncorrectKey(typ, sequence, chain, address)).Err(); err != nil {
		return fmt.Errorf("failed to clear ecdsa verification incorrect: %w", err)
	}
	return nil
}
