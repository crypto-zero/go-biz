package verification

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// OTPService provides methods to send and verify OTP codes.
type OTPService interface {
	SendMobileOTP(ctx context.Context, typ CodeType, userID int64, mobile, countryCode string) (string, error)
	VerifyMobileOTP(ctx context.Context, typ CodeType, sequence, mobile, countryCode, input string) error
	SendEmailOTP(ctx context.Context, typ CodeType, userID int64, email string) (string, error)
	VerifyEmailOTP(ctx context.Context, typ CodeType, sequence, email, input string) error
	SendEcdsaOTP(ctx context.Context, typ CodeType, userID int64, chain, address string) (string, error)
	VerifyEcdsaOTP(ctx context.Context, typ CodeType, sequence, chain, address, input string) error
}

// OTPServiceImpl encapsulates sending and verifying OTP codes.
type OTPServiceImpl struct {
	mobileStore CodeStore[MobileCode]
	emailStore  CodeStore[EmailCode]
	ecdsaStore  CodeStore[EcdsaCode]
	limiter     CodeLimiter
	keys        *CacheKeyBuilder
	smsSender   MobileCodeSender
	emailSender EmailCodeSender
	generator   CodeGenerator
	// Policy
	ttl                  time.Duration
	maxSendAttempts      int64
	sendWindowDuration   time.Duration
	maxVerifyIncorrect   int64
	verifyWindowDuration time.Duration
}

var _ OTPService = (*OTPServiceImpl)(nil)

// OTPConfig groups the policy/configuration for OTPService.
type OTPConfig struct {
	Prefix             CodeCacheKeyPrefix
	TTL                time.Duration // code expiration time
	MaxSendAttempts    int64         // max sends per window per identifier
	SendWindow         time.Duration // send rate-limit window
	MaxVerifyIncorrect int64         // max wrong attempts before lockout
	VerifyWindow       time.Duration // verify rate-limit window
}

// NewOTPService creates an OTPService.
//
// Use NewCodeGenerator(codeLength) for production, or NewTestCodeGenerator(code) for testing.
func NewOTPService(
	cfg OTPConfig, client redis.UniversalClient,
	smsSender MobileCodeSender, emailSender EmailCodeSender,
	gen CodeGenerator,
) OTPService {
	return &OTPServiceImpl{
		mobileStore:          NewRedisCodeStore[MobileCode](client),
		emailStore:           NewRedisCodeStore[EmailCode](client),
		ecdsaStore:           NewRedisCodeStore[EcdsaCode](client),
		limiter:              NewRedisCodeLimiter(client),
		keys:                 NewCacheKeyBuilder(cfg.Prefix),
		smsSender:            smsSender,
		emailSender:          emailSender,
		generator:            gen,
		ttl:                  cfg.TTL,
		maxSendAttempts:      cfg.MaxSendAttempts,
		sendWindowDuration:   cfg.SendWindow,
		maxVerifyIncorrect:   cfg.MaxVerifyIncorrect,
		verifyWindowDuration: cfg.VerifyWindow,
	}
}

// ============================================================================
// Send methods — all delegate to the generic sendCode[T] function
// ============================================================================

func (s *OTPServiceImpl) SendMobileOTP(ctx context.Context, typ CodeType, userID int64, mobile, countryCode string) (string, error) {
	mc, err := s.generator.NewMobileCode(ctx, typ, userID, mobile, countryCode)
	if err != nil {
		return "", err
	}
	return sendCode(ctx, s.mobileStore, s.limiter, s.keys, mc,
		s.ttl, s.maxSendAttempts, s.sendWindowDuration, ErrMobileSendLimitExceeded,
		func() error { return s.smsSender.Send(ctx, mc) })
}

func (s *OTPServiceImpl) SendEmailOTP(ctx context.Context, typ CodeType, userID int64, email string) (string, error) {
	ec, err := s.generator.NewEmailCode(ctx, typ, userID, email)
	if err != nil {
		return "", err
	}
	return sendCode(ctx, s.emailStore, s.limiter, s.keys, ec,
		s.ttl, s.maxSendAttempts, s.sendWindowDuration, ErrEmailSendLimitExceeded,
		func() error { return s.emailSender.Send(ctx, ec) })
}

func (s *OTPServiceImpl) SendEcdsaOTP(ctx context.Context, typ CodeType, userID int64, chain, address string) (string, error) {
	ec, err := s.generator.NewEcdsaCode(ctx, typ, userID, chain, address)
	if err != nil {
		return "", err
	}
	return sendCode(ctx, s.ecdsaStore, s.limiter, s.keys, ec,
		s.ttl, s.maxSendAttempts, s.sendWindowDuration, ErrEcdsaSendLimitExceeded, nil)
}

// ============================================================================
// Verify methods — all delegate to the generic verifyCode[T] function
// ============================================================================

func (s *OTPServiceImpl) VerifyMobileOTP(ctx context.Context, typ CodeType, sequence, mobile, countryCode, input string) error {
	return verifyCode(ctx, s.mobileStore, s.limiter,
		s.keys.CodeKey("MOBILE", typ, sequence, mobile, countryCode),
		s.keys.IncorrectKey("MOBILE", typ, sequence, mobile, countryCode),
		input, s.maxVerifyIncorrect, s.verifyWindowDuration, ErrMobileVerifyLimitExceeded)
}

func (s *OTPServiceImpl) VerifyEmailOTP(ctx context.Context, typ CodeType, sequence, email, input string) error {
	return verifyCode(ctx, s.emailStore, s.limiter,
		s.keys.CodeKey("EMAIL", typ, sequence, email),
		s.keys.IncorrectKey("EMAIL", typ, sequence, email),
		input, s.maxVerifyIncorrect, s.verifyWindowDuration, ErrEmailVerifyLimitExceeded)
}

func (s *OTPServiceImpl) VerifyEcdsaOTP(ctx context.Context, typ CodeType, sequence, chain, address, input string) error {
	return verifyCode(ctx, s.ecdsaStore, s.limiter,
		s.keys.CodeKey("ECDSA", typ, sequence, chain, address),
		s.keys.IncorrectKey("ECDSA", typ, sequence, chain, address),
		input, s.maxVerifyIncorrect, s.verifyWindowDuration, ErrEcdsaVerifyLimitExceeded)
}
