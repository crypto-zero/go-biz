package verification

import (
	"context"
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

// OTPService[T] manages OTP send/verify for a single verification code type.
type OTPService[T interface {
	VerificationCode
	Codeable
}] struct {
	store                CodeStore[T]
	limiter              CodeLimiter
	keys                 *CacheKeyBuilder
	sender               CodeSender[T]
	ttl                  time.Duration
	maxSendAttempts      int64
	sendWindowDuration   time.Duration
	maxVerifyIncorrect   int64
	verifyWindowDuration time.Duration
	sendLimitErr         error
	verifyLimitErr       error
}

// NewOTPService creates an OTPService for a specific code type T.
//
// sendFn is the external delivery function (e.g., SMS/email sender).
// Pass nil for channels that don't require external delivery (e.g., ECDSA).
func NewOTPService[T interface {
	VerificationCode
	Codeable
}](
	cfg OTPConfig, client redis.UniversalClient,
	sender CodeSender[T],
) *OTPService[T] {
	return &OTPService[T]{
		store:                NewRedisCodeStore[T](client),
		limiter:              NewRedisCodeLimiter(client),
		keys:                 NewCacheKeyBuilder(cfg.Prefix),
		sender:               sender,
		ttl:                  cfg.TTL,
		maxSendAttempts:      cfg.MaxSendAttempts,
		sendWindowDuration:   cfg.SendWindow,
		maxVerifyIncorrect:   cfg.MaxVerifyIncorrect,
		verifyWindowDuration: cfg.VerifyWindow,
		sendLimitErr:         cfg.SendLimitErr,
		verifyLimitErr:       cfg.VerifyLimitErr,
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
	return sendCode(ctx, s.store, s.limiter, s.keys, code,
		s.ttl, s.maxSendAttempts, s.sendWindowDuration, s.sendLimitErr, sf)
}

// Verify checks the input code against the stored code.
// keyParts should match the CacheKeyParts of the original code (e.g., sequence, mobile, countryCode).
func (s *OTPService[T]) Verify(ctx context.Context, typ CodeType, input string, keyParts ...string) error {
	var zero T
	medium := zero.Medium()
	codeKey := s.keys.CodeKey(medium, typ, keyParts...)
	incorrectKey := s.keys.IncorrectKey(medium, typ, keyParts...)
	return verifyCode(ctx, s.store, s.limiter, codeKey, incorrectKey,
		input, s.maxVerifyIncorrect, s.verifyWindowDuration, s.verifyLimitErr)
}
