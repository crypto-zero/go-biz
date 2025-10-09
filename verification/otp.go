package verification

import (
	"context"
	"time"
)

// OTPService provides methods to send and verify OTP codes.
type OTPService interface {
	// SendMobileOTP sends a mobile OTP code and returns the sequence.
	SendMobileOTP(ctx context.Context, typ CodeType, userID int64, mobile, countryCode string) (string, error)
	// VerifyMobileOTP verifies the mobile OTP code.
	VerifyMobileOTP(ctx context.Context, typ CodeType, sequence, mobile, countryCode, input string) error
}

// OTPServiceImpl encapsulates sending and verifying OTP codes.
type OTPServiceImpl struct {
	cache        CodeCache
	smsSender    MobileCodeSender
	generator    CodeGenerator
	limiterCache CodeLimiterCache
	// Policy
	ttl                  time.Duration // e.g., 5 * time.Minute
	maxSendAttempts      int64         // max send attempts within sendWindowDuration
	sendWindowDuration   time.Duration // e.g., 1 hour
	maxVerifyIncorrect   int64         // max verify attempts within verifyWindowDuration
	verifyWindowDuration time.Duration // e.g., 1 hour
}

// NewOTPService returns a configured OTPServiceImpl.
// It keeps internal fields unexported while providing a simple constructor
// for external packages to initialize the service.
func NewOTPService(
	cache CodeCache, limiterCache CodeLimiterCache, sender MobileCodeSender,
	gen CodeGenerator, sendWindowDuration, verifyWindowDuration, ttl time.Duration,
	maxSendAttempts, maxVerifyIncorrect int64,
) *OTPServiceImpl {
	return &OTPServiceImpl{
		cache:                cache,
		smsSender:            sender,
		generator:            gen,
		limiterCache:         limiterCache,
		ttl:                  ttl,
		maxSendAttempts:      maxSendAttempts,      // max send attempts within sendWindowDuration
		sendWindowDuration:   sendWindowDuration,   // e.g., 1 hour
		maxVerifyIncorrect:   maxVerifyIncorrect,   // max verify attempts within verifyWindowDuration
		verifyWindowDuration: verifyWindowDuration, // e.g., 1 hour
	}
}

// NewStaticOTPService returns a service that generates the fixed test code ("666666").
func NewStaticOTPService(cache CodeCache, limiterCache CodeLimiterCache, sender MobileCodeSender,
	sendWindowDuration, verifyWindowDuration, ttl time.Duration,
	sendAttempts, verifyAttempts int64) *OTPServiceImpl {
	return NewOTPService(cache, limiterCache, sender, DefaultCodeGenerator, sendWindowDuration, verifyWindowDuration,
		ttl, sendAttempts, verifyAttempts)
}

// NewFourDigitOPTService returns a service that generates a random code, defaulting to 4 digits.
// It uses the FourDigitCodeGenerator.
func NewFourDigitOPTService(cache CodeCache, sender MobileCodeSender,
	limiterCache CodeLimiterCache,
	sendWindowDuration, verifyWindowDuration, ttl time.Duration,
	sendAttempts, verifyAttempts int64) *OTPServiceImpl {
	return NewOTPService(cache, limiterCache, sender, FourDigitCodeGenerator, sendWindowDuration, verifyWindowDuration,
		ttl, sendAttempts, verifyAttempts)
}

// SendMobileOTP generates a code, stores it, sends SMS, and returns the sequence.
func (s *OTPServiceImpl) SendMobileOTP(
	ctx context.Context, typ CodeType, userID int64, mobile, countryCode string,
) (string, error) {
	// Rate limiting check
	allowMobile, err := s.limiterCache.AllowSendMobile(ctx, typ, mobile, countryCode,
		s.maxSendAttempts, s.sendWindowDuration)
	if err != nil {
		return "", err
	}
	if !allowMobile.Allowed {
		return "", ErrMobileSendLimitExceeded
	}

	mc, err := s.generator.NewMobileCode(ctx, typ, userID, mobile, countryCode)
	if err != nil {
		return "", err
	}
	if err = s.cache.SetMobileCode(ctx, mc, s.ttl); err != nil {
		return "", err
	}
	if err = s.smsSender.Send(ctx, mc); err != nil {
		_ = s.cache.DeleteMobileCode(ctx, typ, mc.Sequence, mobile, countryCode)
		return "", err
	}
	return mc.Sequence, nil
}

// VerifyMobileOTP verifies the mobile OTP code.
func (s *OTPServiceImpl) VerifyMobileOTP(
	ctx context.Context, typ CodeType, sequence, mobile, countryCode, input string,
) error {
	// Rate limiting check
	cnt, err := s.limiterCache.GetMobileCodeIncorrectCount(ctx, typ, sequence, mobile, countryCode)
	if err != nil {
		return err
	}
	if cnt >= s.maxVerifyIncorrect {
		// Exceeded max attempts, delete the code to prevent further tries
		// and clear the incorrect count
		_ = s.cache.DeleteMobileCode(ctx, typ, sequence, mobile, countryCode)
		_ = s.limiterCache.DeleteMobileCodeIncorrect(ctx, typ, sequence, mobile, countryCode)
		return ErrMobileVerifyLimitExceeded
	}
	// Non-destructive read
	stored, err := s.cache.PeekMobileCode(ctx, typ, sequence, mobile, countryCode)
	if err != nil {
		return err
	}

	if stored.Code.Code != input {
		_, _ = s.limiterCache.IncrementMobileCodeIncorrect(ctx, typ, sequence, mobile, countryCode,
			s.maxVerifyIncorrect, s.verifyWindowDuration)
		return ErrCodeIncorrect
	}
	// Delete after successful verification (one-time code)
	if err = s.cache.DeleteMobileCode(ctx, typ, sequence, mobile, countryCode); err != nil {
		return err
	}
	// Clear verify incorrect count on success
	_ = s.limiterCache.DeleteMobileCodeIncorrect(ctx, typ, sequence, mobile, countryCode)
	return nil
}
