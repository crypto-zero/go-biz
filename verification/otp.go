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
	sendAttempts         int64         // max send attempts within sendWindowDuration
	sendWindowDuration   time.Duration // e.g., 1 hour
	verifyAttempts       int64         // max verify attempts within verifyWindowDuration
	verifyWindowDuration time.Duration // e.g., 1 hour
}

// NewOTPService returns a configured OTPServiceImpl.
// It keeps internal fields unexported while providing a simple constructor
// for external packages to initialize the service.
func NewOTPService(
	cache CodeCache, limiterCache CodeLimiterCache, sender MobileCodeSender,
	gen CodeGenerator, sendWindowDuration, verifyWindowDuration, ttl time.Duration,
	sendAttempts, verifyAttempts int64,
) *OTPServiceImpl {
	return &OTPServiceImpl{
		cache:                cache,
		smsSender:            sender,
		generator:            gen,
		limiterCache:         limiterCache,
		ttl:                  ttl,
		sendAttempts:         sendAttempts,         // max send attempts within sendWindowDuration
		sendWindowDuration:   sendWindowDuration,   // e.g., 1 hour
		verifyAttempts:       verifyAttempts,       // max verify attempts within verifyWindowDuration
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
	mc, err := s.generator.NewMobileCode(ctx, typ, userID, mobile, countryCode)
	if err != nil {
		return "", err
	}
	allowMobile, err := s.limiterCache.AllowSendMobile(ctx, typ, mobile, countryCode,
		s.sendAttempts, s.sendWindowDuration)
	if err != nil {
		return "", err
	}
	if !allowMobile.Allowed {
		if allowMobile.Count > allowMobile.Limit {
			return "", ErrMobileLimitExceeded
		}
		return "", ErrMobileNotAllowed
	}
	if err = s.cache.SetMobileCode(ctx, mc, s.ttl); err != nil {
		return "", err
	}
	if err = s.smsSender.Send(ctx, mc); err != nil {
		return "", err
	}
	return mc.Sequence, nil
}

func (s *OTPServiceImpl) VerifyMobileOTP(
	ctx context.Context, typ CodeType, sequence, mobile, countryCode, input string,
) error {
	cnt, err := s.limiterCache.GetVerifyMobileCount(ctx, typ, sequence, mobile, countryCode)
	if err != nil {
		return err
	}
	if cnt >= s.verifyAttempts {
		return ErrMobileVerifyLimitExceeded
	}
	// Non-destructive read
	stored, err := s.cache.PeekMobileCode(ctx, typ, sequence, mobile, countryCode)
	if err != nil {
		return err
	}

	if stored.Code.Code != input {
		_, err = s.limiterCache.RecordMobileVerifyFailure(ctx, typ, sequence, mobile, countryCode,
			s.verifyAttempts, s.verifyWindowDuration)
		if err != nil {
			return err
		}
		return ErrCodeIncorrect
	}
	// Delete after successful verification (one-time code)
	if err = s.cache.DeleteMobileCode(ctx, typ, sequence, mobile, countryCode); err != nil {
		return err
	}
	// Clear verify failure count on success
	if err = s.limiterCache.ClearMobileVerifyFailures(ctx, typ, sequence, mobile, countryCode); err != nil {
		return err
	}
	return nil
}
