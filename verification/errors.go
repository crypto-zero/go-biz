package verification

import "errors"

var (
	// ErrCodeNotFound represents a verification code not found error.
	ErrCodeNotFound = errors.New("verification code not found")
	// ErrCodeTypeIsEmpty represents a verification code type is empty error.
	ErrCodeTypeIsEmpty = errors.New("verification code type is empty")
	// ErrCodeIncorrect represents a verification code incorrect error.
	ErrCodeIncorrect = errors.New("verification code is incorrect")
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
	// ErrMobileCodeCodeIsEmpty represents an empty code error.
	ErrMobileCodeCodeIsEmpty = errors.New("mobile code code is empty")
	// ErrMobileCodeTypeIsEmpty represents an empty code type error.
	ErrMobileCodeTypeIsEmpty = errors.New("mobile code type is empty")
	// ErrUnsupportedCountryCode represents an unsupported country code error.
	ErrUnsupportedCountryCode = errors.New("unsupported country code")

	// ErrNilEmailCode represents a nil email code error.
	ErrNilEmailCode = errors.New("email code is nil")
	// ErrEmailCodeEmailIsEmpty represents an empty email error.
	ErrEmailCodeEmailIsEmpty = errors.New("email code email is empty")
	// ErrEmailCodeCodeIsEmpty represents an empty code error.
	ErrEmailCodeCodeIsEmpty = errors.New("email code code is empty")
	// ErrEmailCodeTypeIsEmpty represents an empty code type error.
	ErrEmailCodeTypeIsEmpty = errors.New("email code type is empty")
	// ErrEmailTemplateNotFound represents an email template not found error.
	ErrEmailTemplateNotFound = errors.New("email template not found")
)
