package verification

import (
	"errors"
	"time"
)

// RateLimitError wraps a rate limit error with a retry duration.
type RateLimitError struct {
	Err     error
	RetryIn time.Duration // Time until the rate limit resets
}

// Error implements the error interface.
func (e *RateLimitError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return "rate limit exceeded"
}

// Unwrap returns the underlying error.
func (e *RateLimitError) Unwrap() error {
	return e.Err
}

var (
	// ErrSendFailed represents a generic send failure.
	ErrSendFailed = errors.New("send failed")

	// ErrCodeNotFound represents a verification code not found error.
	ErrCodeNotFound = errors.New("verification code not found")
	// ErrCodeTypeIsEmpty represents a verification code type is empty error.
	ErrCodeTypeIsEmpty = errors.New("verification code type is empty")
	// ErrCodeIncorrect represents a verification code incorrect error.
	ErrCodeIncorrect = errors.New("verification code is incorrect")
	// ErrCodeIsEmpty represents an empty verification code error.
	ErrCodeIsEmpty = errors.New("verification code is empty")
	// ErrMobileSendLimitExceeded indicates that the mobile number has exceeded the limit for sending OTPs.
	ErrMobileSendLimitExceeded = errors.New("mobile send OTP limit exceeded")
	// ErrMobileVerifyLimitExceeded indicates that the mobile number has exceeded the limit for verifying OTPs.
	ErrMobileVerifyLimitExceeded = errors.New("mobile verify OTP limit exceeded")
	// ErrEmailSendLimitExceeded indicates that the email address has exceeded the limit for sending OTPs.
	ErrEmailSendLimitExceeded = errors.New("email send OTP limit exceeded")
	// ErrEmailVerifyLimitExceeded indicates that the email address has exceeded the limit for verifying OTPs.
	ErrEmailVerifyLimitExceeded = errors.New("email verify OTP limit exceeded")
	// ErrEcdsaSendLimitExceeded indicates that the ecdsa address has exceeded the limit for sending OTPs.
	ErrEcdsaSendLimitExceeded = errors.New("ecdsa send OTP limit exceeded")
	// ErrEcdsaVerifyLimitExceeded indicates that the ecdsa address has exceeded the limit for verifying OTPs.
	ErrEcdsaVerifyLimitExceeded = errors.New("ecdsa verify OTP limit exceeded")

	// ErrNilMobileCode represents a nil mobile code error.
	ErrNilMobileCode = errors.New("mobile code is nil")
	// ErrMobileCodeMobileIsEmpty represents an empty mobile error.
	ErrMobileCodeMobileIsEmpty = errors.New("mobile code mobile is empty")
	// ErrMobileCodeCountryCodeIsEmpty represents an empty country code error.
	ErrMobileCodeCountryCodeIsEmpty = errors.New("mobile code country code is empty")
	// ErrUnsupportedCountryCode represents an unsupported country code error.
	ErrUnsupportedCountryCode = errors.New("unsupported country code")

	// ErrNilEmailCode represents a nil email code error.
	ErrNilEmailCode = errors.New("email code is nil")
	// ErrEmailCodeEmailIsEmpty represents an empty email error.
	ErrEmailCodeEmailIsEmpty = errors.New("email code email is empty")
	// ErrEmailTemplateNotFound represents an email template not found error.
	ErrEmailTemplateNotFound = errors.New("email template not found")

	// ErrNilEcdsaCode represents a nil ecdsa code error.
	ErrNilEcdsaCode = errors.New("ecdsa code is nil")
	// ErrEcdsaCodeChainIsEmpty represents an empty chain error.
	ErrEcdsaCodeChainIsEmpty = errors.New("ecdsa code chain is empty")
	// ErrEcdsaCodeAddressIsEmpty represents an empty address error.
	ErrEcdsaCodeAddressIsEmpty = errors.New("ecdsa code address is empty")
)
