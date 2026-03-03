package verification

import (
	"context"
	"crypto/subtle"
	"time"
)

// verifyCode performs the standard OTP verification flow for any code type.
//
// The flow is designed to be race-safe:
//  1. Peek the stored code (non-destructive read).
//  2. If correct → delete code, clear incorrect counter, return nil.
//  3. If wrong  → atomically increment incorrect counter (Lua script).
//  4. If the atomic increment shows the limit is exceeded → delete code, return limitExceededErr.
//  5. Otherwise → return ErrCodeIncorrect.
//
// This avoids the TOCTOU race between GetIncorrectCount and IncrementIncorrect
// that could allow concurrent requests to bypass the limit.
func verifyCode[T interface {
	VerificationCode
	Verifiable
}](
	ctx context.Context,
	store CodeStore[T],
	limiter CodeLimiter,
	codeKey, incorrectKey string,
	input string,
	maxIncorrect int64,
	verifyWindow time.Duration,
	limitExceededErr error,
) error {
	// 1. Peek the stored code.
	stored, err := store.Peek(ctx, codeKey)
	if err != nil {
		return err // ErrCodeNotFound if already deleted by a previous limit-exceeded cleanup
	}

	// 2. Correct code → success path (constant-time compare to prevent timing attacks).
	if subtle.ConstantTimeCompare([]byte((*stored).VerificationCode()), []byte(input)) == 1 {
		if err = store.Delete(ctx, codeKey); err != nil {
			return err
		}
		_ = limiter.DeleteIncorrect(ctx, incorrectKey)
		return nil
	}

	// 3. Wrong code → atomically increment the incorrect counter.
	decision, err := limiter.IncrementIncorrect(ctx, incorrectKey, maxIncorrect, verifyWindow)
	if err != nil {
		return ErrCodeIncorrect
	}

	// 4. If this attempt caused the limit to be exceeded → clean up.
	if decision != nil && !decision.Allowed {
		_ = store.Delete(ctx, codeKey)
		_ = limiter.DeleteIncorrect(ctx, incorrectKey)
		return limitExceededErr
	}

	return ErrCodeIncorrect
}

// sendCode performs the common OTP send flow: rate-limit check → store code → optional send.
// sendFn is called after storing (e.g. to send SMS/email); on failure the code is rolled back.
// Pass nil for sendFn if no external delivery is needed (e.g. ECDSA challenge).
func sendCode[T interface {
	VerificationCode
	Codeable
}](
	ctx context.Context,
	store CodeStore[T],
	limiter CodeLimiter,
	keys *CacheKeyBuilder,
	code *T,
	ttl time.Duration,
	maxSend int64,
	sendWindow time.Duration,
	limitErr error,
	sendFn func() error,
) (string, error) {
	c := *code // dereference to call interface methods on value
	limitKey := keys.LimitKey(c.Medium(), c.GetType(), c.LimitKeyParts()...)
	allow, err := limiter.AllowSend(ctx, limitKey, maxSend, sendWindow)
	if err != nil {
		return "", err
	}
	if !allow.Allowed {
		return "", limitErr
	}
	codeKey := keys.CodeKey(c.Medium(), c.GetType(), c.CacheKeyParts()...)
	if err = store.Set(ctx, codeKey, code, ttl); err != nil {
		return "", err
	}
	if sendFn != nil {
		if err = sendFn(); err != nil {
			_ = store.Delete(ctx, codeKey)
			_ = limiter.RollbackSend(ctx, limitKey)
			return "", err
		}
	}
	return c.GetSequence(), nil
}
