package verification

import (
	"context"
	"time"
)

// OTPService provides methods to send and verify OTP codes.
type OTPService interface {
	// SendMobileOTP sends a mobile OTP code and returns the sequence.
	SendMobileOTP(ctx context.Context, typ string, userID int64, mobile, countryCode string) (string, error)
	// VerifyMobileOTP verifies the mobile OTP code.
	VerifyMobileOTP(ctx context.Context, typ, sequence, mobile, countryCode, input string) error
}

// OTPServiceImpl encapsulates sending and verifying OTP codes.
type OTPServiceImpl struct {
	cache     CodeCache
	smsSender MobileCodeSender
	generator CodeGenerator
	// Policy
	ttl time.Duration // e.g., 5 * time.Minute
}

// NewOTPService returns a configured OTPServiceImpl.
// It keeps internal fields unexported while providing a simple constructor
// for external packages to initialize the service.
func NewOTPService(
	cache CodeCache, sender MobileCodeSender, gen CodeGenerator, ttl time.Duration,
) *OTPServiceImpl {
	return &OTPServiceImpl{
		cache:     cache,
		smsSender: sender,
		generator: gen,
		ttl:       ttl,
	}
}

// NewStaticOTPService returns a service that generates the fixed test code ("666666").
func NewStaticOTPService(cache CodeCache, sender MobileCodeSender, ttl time.Duration) *OTPServiceImpl {
	return NewOTPService(cache, sender, DefaultCodeGenerator, ttl)
}

// NewFourDigitOPTService returns a service that generates a random code, defaulting to 4 digits.
// It uses the FourDigitCodeGenerator.
func NewFourDigitOPTService(cache CodeCache, sender MobileCodeSender, ttl time.Duration) *OTPServiceImpl {
	return NewOTPService(cache, sender, FourDigitCodeGenerator, ttl)
}

// SendMobileOTP generates a code, stores it, sends SMS, and returns the sequence.
func (s *OTPServiceImpl) SendMobileOTP(
	ctx context.Context, typ string, userID int64, mobile, countryCode string,
) (string, error) {
	mc, err := s.generator.NewMobileCode(ctx, typ, userID, mobile, countryCode)
	if err != nil {
		return "", err
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
	ctx context.Context, typ, sequence, mobile, countryCode, input string,
) error {
	// Non-destructive read
	stored, err := s.cache.PeekMobileCode(ctx, typ, sequence, mobile, countryCode)
	if err != nil {
		return err
	}
	if stored.Code.Code != input {
		return ErrCodeIncorrect
	}
	// Delete after successful verification (one-time code)
	if err = s.cache.DeleteMobileCode(ctx, typ, sequence, mobile, countryCode); err != nil {
		return err
	}
	return nil
}
