package verification

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// OTPConfig groups the policy/configuration for a single-channel OTPService.
type OTPConfig struct {
	Prefix CodeCacheKeyPrefix
	TTL    time.Duration     // code expiration time
	Send   RateLimiterConfig // send rate-limit policy
	Verify RateLimiterConfig // verify rate-limit policy
}

// DefaultOTPConfig returns an OTPConfig with sensible, secure defaults.
func DefaultOTPConfig(prefix CodeCacheKeyPrefix) OTPConfig {
	return OTPConfig{
		Prefix: prefix,
		TTL:    5 * time.Minute,
		Send: RateLimiterConfig{
			Limit:    1,
			Window:   1 * time.Minute,
			LimitErr: ErrSendFailed,
		},
		Verify: RateLimiterConfig{
			Limit:    5,
			Window:   5 * time.Minute,
			LimitErr: ErrCodeIncorrect,
		},
	}
}

// OTPService[T] manages OTP send/verify for a single verification code type.
type OTPService[T CodeConstraint] struct {
	store         *CodeStore[T]
	keys          *CacheKeyBuilder
	sender        CodeSender[T]
	sendLimiter   *RateLimiter
	verifyLimiter *RateLimiter
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
		store:         NewCodeStore[T](client),
		keys:          NewCacheKeyBuilder(cfg.Prefix),
		sender:        sender,
		sendLimiter:   NewRateLimiter(client, cfg.Send),
		verifyLimiter: NewRateLimiter(client, cfg.Verify),
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
// probe should be a zero-value-like instance with identity fields populated
// (e.g., Sequence, Mobile, CountryCode for MobileCode) — the Code field is ignored.
// This design ensures the same CacheKeyParts()/Medium()/GetType() logic used in Send
// is also used here, eliminating key-construction mismatches.
func (s *OTPService[T]) Verify(ctx context.Context, input string, probe *T) error {
	c := *probe
	medium := c.Medium()
	codeKey := s.keys.CodeKey(medium, c.GetType(), c.CacheKeyParts()...)
	incorrectKey := s.keys.IncorrectKey(medium, c.GetType(), c.CacheKeyParts()...)
	return s.verifyCode(ctx, codeKey, incorrectKey, input)
}

// verifyCode performs the standard OTP verification flow for any code type.
//
// The flow is designed to be race-safe:
//  1. Peek the stored code (non-destructive read).
//  2. If correct → atomically delete code (prevents concurrent double-consumption),
//     clear incorrect counter, return nil.
//  3. If wrong  → atomically increment incorrect counter via limiter.
//     The limiter returns *RateLimitError when exceeded → clean up and propagate.
//  4. Otherwise → return ErrCodeIncorrect.
func (s *OTPService[T]) verifyCode(ctx context.Context, codeKey, incorrectKey, input string) error {
	// 1. Peek the stored code.
	stored, err := s.store.Peek(ctx, codeKey)
	if err != nil {
		return err
	}

	// 2. Correct code → success path (constant-time compare to prevent timing attacks).
	//    The stored code is a SHA-256 hash; hash the user input before comparing.
	if subtle.ConstantTimeCompare([]byte((*stored).GetDigest()), []byte(hashCode(input))) == 1 {
		deleted, err := s.store.Delete(ctx, codeKey)
		// If another concurrent request successfully deleted the code before us,
		// we must not return success, otherwise an OTP is consumed twice.
		if err == nil && !deleted {
			return ErrCodeNotFound
		}
		_ = s.verifyLimiter.Reset(ctx, incorrectKey)
		return nil
	}

	// 3. Wrong code → the limiter handles increment + limit check internally.
	//    *RateLimitError → limit exceeded; infrastructure error → propagate directly.
	if err := s.verifyLimiter.Allow(ctx, incorrectKey); err != nil {
		var rlErr *RateLimitError
		if errors.As(err, &rlErr) {
			_, _ = s.store.Delete(ctx, codeKey)
			_ = s.verifyLimiter.Reset(ctx, incorrectKey)
		}
		return err
	}

	return ErrCodeIncorrect
}

// sendCode performs the common OTP send flow: rate-limit check → store code → optional send.
// sendFn is called after storing (e.g. to send SMS/email); on failure the code is rolled back.
// Pass nil for sendFn if no external delivery is needed (e.g. ECDSA challenge).
//
// Design note: each code's CacheKeyParts includes the unique Sequence, so consecutive
// sends for the same user/identifier produce independent Redis keys. This means a
// rollback (store.Delete + sendLimiter.Undo) on send failure only affects the
// current attempt and never removes a previously sent, still-valid code.
func (s *OTPService[T]) sendCode(ctx context.Context, code *T, sendFn func() error) (string, error) {
	c := *code // dereference to call interface methods on value
	limitKey := s.keys.LimitKey(c.Medium(), c.GetType(), c.LimitKeyParts()...)
	if err := s.sendLimiter.Allow(ctx, limitKey); err != nil {
		return "", err
	}
	codeKey := s.keys.CodeKey(c.Medium(), c.GetType(), c.CacheKeyParts()...)
	if err := s.store.Set(ctx, codeKey, code, s.cfg.TTL); err != nil {
		return "", err
	}
	if sendFn != nil {
		if err := sendFn(); err != nil {
			_, _ = s.store.Delete(ctx, codeKey)
			_ = s.sendLimiter.Undo(ctx, limitKey)
			return "", err
		}
	}
	return c.GetSequence(), nil
}
