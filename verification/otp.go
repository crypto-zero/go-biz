package verification

import (
	"context"
	"crypto/subtle"
	"time"

	"github.com/redis/go-redis/v9"
)

// OTPConfig groups the policy/configuration for a single-channel OTPService.
type OTPConfig struct {
	Prefix             CodeCacheKeyPrefix
	TTL                time.Duration // code expiration time
	MaxSendAttempts    int64         // max sends per window per identifier
	SendWindow         time.Duration // send rate-limit window
	MaxVerifyIncorrect int64         // max wrong attempts before lockout
	VerifyWindow       time.Duration // verify rate-limit window
	SendLimitErr       error         // returned when send limit is exceeded
	VerifyLimitErr     error         // returned when verify limit is exceeded
}

// DefaultOTPConfig returns an OTPConfig with sensible, secure defaults.
func DefaultOTPConfig(prefix CodeCacheKeyPrefix) OTPConfig {
	return OTPConfig{
		Prefix:             prefix,
		TTL:                5 * time.Minute,
		MaxSendAttempts:    1,
		SendWindow:         1 * time.Minute,
		MaxVerifyIncorrect: 5,
		VerifyWindow:       1 * time.Hour,
		SendLimitErr:       ErrSendFailed, // Caller should override with specific error if desired
		VerifyLimitErr:     ErrCodeIncorrect,
	}
}

// OTPService[T] manages OTP send/verify for a single verification code type.
type OTPService[T CodeConstraint] struct {
	store         CodeStore[T]
	keys          *CacheKeyBuilder
	sender        CodeSender[T]
	sendLimiter   RateLimiter
	verifyLimiter RateLimiter
	cfg           OTPConfig
}

// NewOTPService creates an OTPService for a specific code type T.
//
// sender is the external delivery implementation (e.g., SMS/email sender).
// Pass nil for channels that don't require external delivery (e.g., ECDSA).
func NewOTPService[T CodeConstraint](
	cfg OTPConfig, client redis.UniversalClient,
	sender CodeSender[T],
) *OTPService[T] {
	return &OTPService[T]{
		store:         NewRedisCodeStore[T](client),
		keys:          NewCacheKeyBuilder(cfg.Prefix),
		sender:        sender,
		sendLimiter:   NewRedisRateLimiter(client),
		verifyLimiter: NewRedisRateLimiter(client),
		cfg:           cfg,
	}
}

// Send stores the code, applies rate limiting, and optionally delivers it externally.
// The caller is responsible for creating the code via CodeGenerator.
// Returns the sequence identifier for later verification.
func (s *OTPService[T]) Send(ctx context.Context, code *T) (string, error) {
	var sf func() error
	if s.sender != nil {
		sf = func() error { return s.sender.Send(ctx, code) }
	}
	return s.sendCode(ctx, code, sf)
}

// Verify checks the input code against the stored code.
// keyParts should match the CacheKeyParts of the original code (e.g., sequence, mobile, countryCode).
func (s *OTPService[T]) Verify(ctx context.Context, typ CodeType, input string, keyParts ...string) error {
	var zero T
	medium := zero.Medium()
	codeKey := s.keys.CodeKey(medium, typ, keyParts...)
	incorrectKey := s.keys.IncorrectKey(medium, typ, keyParts...)
	return s.verifyCode(ctx, codeKey, incorrectKey, input)
}

// verifyCode performs the standard OTP verification flow for any code type.
//
// The flow is designed to be race-safe:
//  1. Peek the stored code (non-destructive read).
//  2. If correct → delete code, clear incorrect counter, return nil.
//  3. If wrong  → atomically increment incorrect counter (Lua script).
//  4. If the atomic increment shows the limit is exceeded → delete code, return limitExceededErr.
//  5. Otherwise → return ErrCodeIncorrect.
//
// This avoids the TOCTOU race between read and increment
// that could allow concurrent requests to bypass the limit.
func (s *OTPService[T]) verifyCode(ctx context.Context, codeKey, incorrectKey, input string) error {
	// 1. Peek the stored code.
	stored, err := s.store.Peek(ctx, codeKey)
	if err != nil {
		return err // ErrCodeNotFound if already deleted by a previous limit-exceeded cleanup
	}

	// 2. Correct code → success path (constant-time compare to prevent timing attacks).
	if subtle.ConstantTimeCompare([]byte((*stored).VerificationCode()), []byte(input)) == 1 {
		if err = s.store.Delete(ctx, codeKey); err != nil {
			return err
		}
		_ = s.verifyLimiter.Delete(ctx, incorrectKey)
		return nil
	}

	// 3. Wrong code → atomically increment the incorrect counter.
	decision, err := s.verifyLimiter.Allow(ctx, incorrectKey, s.cfg.MaxVerifyIncorrect, s.cfg.VerifyWindow)
	if err != nil {
		return ErrCodeIncorrect
	}

	// 4. If this attempt caused the limit to be exceeded → clean up.
	if decision != nil && !decision.Allowed {
		_ = s.store.Delete(ctx, codeKey)
		_ = s.verifyLimiter.Delete(ctx, incorrectKey)
		return &RateLimitError{Err: s.cfg.VerifyLimitErr, RetryIn: decision.ResetIn}
	}

	return ErrCodeIncorrect
}

// sendCode performs the common OTP send flow: rate-limit check → store code → optional send.
// sendFn is called after storing (e.g. to send SMS/email); on failure the code is rolled back.
// Pass nil for sendFn if no external delivery is needed (e.g. ECDSA challenge).
func (s *OTPService[T]) sendCode(ctx context.Context, code *T, sendFn func() error) (string, error) {
	c := *code // dereference to call interface methods on value
	limitKey := s.keys.LimitKey(c.Medium(), c.GetType(), c.LimitKeyParts()...)
	allow, err := s.sendLimiter.Allow(ctx, limitKey, s.cfg.MaxSendAttempts, s.cfg.SendWindow)
	if err != nil {
		return "", err
	}
	if !allow.Allowed {
		return "", &RateLimitError{Err: s.cfg.SendLimitErr, RetryIn: allow.ResetIn}
	}
	codeKey := s.keys.CodeKey(c.Medium(), c.GetType(), c.CacheKeyParts()...)
	if err = s.store.Set(ctx, codeKey, code, s.cfg.TTL); err != nil {
		return "", err
	}
	if sendFn != nil {
		if err = sendFn(); err != nil {
			_ = s.store.Delete(ctx, codeKey)
			_ = s.sendLimiter.Rollback(ctx, limitKey)
			return "", err
		}
	}
	return c.GetSequence(), nil
}
