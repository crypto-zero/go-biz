package verification

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	mr "github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isNDigits returns true if s is exactly n ASCII digits.
func isNDigits(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// wrongCodeFor returns a code that is guaranteed to differ from sent.
func wrongCodeFor(sent string) string {
	if len(sent) == 0 {
		return "0000"
	}
	b := []byte(sent)
	last := b[len(b)-1]
	if last != '0' {
		b[len(b)-1] = '0'
	} else {
		b[len(b)-1] = '1'
	}
	return string(b)
}

// getRedisClient returns a redis client. If REDIS_ADDR is empty, it spins up a miniredis.
func getRedisClient(t *testing.T) (redis.UniversalClient, func(), func(time.Duration)) {
	t.Helper()
	if addr := os.Getenv("REDIS_ADDR"); addr != "" {
		c := redis.NewUniversalClient(&redis.UniversalOptions{Addrs: []string{addr}})
		return c, func() { _ = c.Close() }, func(d time.Duration) { time.Sleep(d) }
	}
	m, err := mr.Run()
	if err != nil {
		t.Fatalf("miniredis start: %v", err)
	}
	c := redis.NewClient(&redis.Options{Addr: m.Addr()})
	return c, func() { _ = c.Close(); m.Close() }, m.FastForward
}

// mobileProbe creates a MobileCode probe for Verify calls.
func mobileProbe(seq, mobile, cc string) *MobileCode {
	return &MobileCode{Code: Code{Type: "LOGIN", Sequence: seq}, Mobile: mobile, CountryCode: cc}
}

// emailProbe creates an EmailCode probe for Verify calls.
func emailProbe(seq, email string) *EmailCode {
	return &EmailCode{Code: Code{Type: "LOGIN", Sequence: seq}, Email: email}
}

// fake sender captures the last MobileCode sent.
type fakeSMSSender struct{ last *MobileCode }

func (f *fakeSMSSender) Send(_ context.Context, mc *MobileCode) error {
	f.last = mc
	return nil
}

// fake email sender captures the last EmailCode sent.
type fakeEmailSender struct{ last *EmailCode }

func (f *fakeEmailSender) Send(_ context.Context, ec *EmailCode) error {
	f.last = ec
	return nil
}

// mobileTestConfig returns an OTPConfig for the mobile channel.
func mobileTestConfig(maxSend, maxVerify int64) OTPConfig {
	return OTPConfig{
		Prefix: "TEST", TTL: 5 * time.Minute,
		Send:   RateLimiterConfig{Limit: maxSend, Window: 5 * time.Minute, LimitErr: ErrMobileSendLimitExceeded},
		Verify: RateLimiterConfig{Limit: maxVerify, Window: 5 * time.Minute, LimitErr: ErrMobileVerifyLimitExceeded},
	}
}

// emailTestConfig returns an OTPConfig for the email channel.
func emailTestConfig(maxSend, maxVerify int64) OTPConfig {
	return OTPConfig{
		Prefix: "TEST", TTL: 5 * time.Minute,
		Send:   RateLimiterConfig{Limit: maxSend, Window: 5 * time.Minute, LimitErr: ErrEmailSendLimitExceeded},
		Verify: RateLimiterConfig{Limit: maxVerify, Window: 5 * time.Minute, LimitErr: ErrEmailVerifyLimitExceeded},
	}
}

func TestVerification_CodeStore_Basics(t *testing.T) {
	ctx := context.Background()
	client, cleanup, ff := getRedisClient(t)
	defer cleanup()

	gen := NewTestCodeGenerator("666666")
	keys := NewCacheKeyBuilder("TEST")
	mobileStore := NewCodeStore[MobileCode](client)
	emailStore := NewCodeStore[EmailCode](client)
	ecdsaStore := NewCodeStore[EcdsaCode](client)

	t.Run("email set/get", func(t *testing.T) {
		code, err := gen.NewEmailCode("TEST_TYPE", 1, "abc@def.com")
		assert.NoError(t, err)
		key := keys.CodeKey("EMAIL", code.Type, code.Sequence, code.Email)
		assert.NoError(t, emailStore.Set(ctx, key, code, time.Minute))
		emailCode, err := emailStore.Peek(ctx, key)
		assert.NoError(t, err)
		assert.NotNil(t, emailCode)
		assert.Equal(t, hashCode("666666"), emailCode.Code.Digest)
		assert.Empty(t, emailCode.Code.Value) // Plaintext is not serialized
	})

	t.Run("email expired", func(t *testing.T) {
		code, _ := gen.NewEmailCode("TEST_TYPE", 1, "abc@def.com")
		key := keys.CodeKey("EMAIL", code.Type, code.Sequence, code.Email)
		_ = emailStore.Set(ctx, key, code, time.Second)
		ff(2 * time.Second)
		_, err := emailStore.Peek(ctx, key)
		assert.Equal(t, ErrCodeNotFound, err)
	})

	t.Run("mobile set/get", func(t *testing.T) {
		code, _ := gen.NewMobileCode("TEST_TYPE", 1, "13566667777", "86")
		key := keys.CodeKey("MOBILE", code.Type, code.Sequence, code.Mobile, code.CountryCode)
		_ = mobileStore.Set(ctx, key, code, time.Minute)
		mobileCode, err := mobileStore.Peek(ctx, key)
		assert.NoError(t, err)
		assert.NotNil(t, mobileCode)
		assert.Equal(t, hashCode("666666"), mobileCode.Code.Digest)
		assert.Empty(t, mobileCode.Code.Value) // Plaintext is not serialized
	})

	t.Run("ecdsa set/get", func(t *testing.T) {
		code, _ := gen.NewEcdsaCode("TEST_TYPE", 1, "ETHEREUM", "0xabc")
		key := keys.CodeKey("ECDSA", code.Type, code.Sequence, code.Chain, code.Address)
		_ = ecdsaStore.Set(ctx, key, code, time.Minute)
		ecdsaCode, err := ecdsaStore.Peek(ctx, key)
		assert.NoError(t, err)
		assert.NotNil(t, ecdsaCode)
	})
}

func TestVerification_Service_SendAndVerify_Fixed6(t *testing.T) {
	ctx := context.Background()
	client, cleanup, _ := getRedisClient(t)
	defer cleanup()

	fake := &fakeSMSSender{}
	gen := NewTestCodeGenerator("666666")
	keys := NewCacheKeyBuilder("TEST")
	svc := NewOTPService[MobileCode](mobileTestConfig(10, 10), client, fake)

	mc, err := gen.NewMobileCode("login", 123, "13800138000", "86")
	assert.NoError(t, err)
	seq, err := svc.Send(ctx, mc)
	assert.NoError(t, err)
	assert.NotEmpty(t, seq)
	if assert.NotNil(t, fake.last) {
		assert.Equal(t, "13800138000", fake.last.Mobile)
		assert.Equal(t, "86", fake.last.CountryCode)
		assert.True(t, isNDigits(fake.last.Code.Value, 6))
		assert.Equal(t, "666666", fake.last.Code.Value)

		// Verify OK should delete
		err := svc.Verify(ctx, "666666", mobileProbe(seq, "13800138000", "86"))
		assert.NoError(t, err)
		mobileStore := NewCodeStore[MobileCode](client)
		_, err = mobileStore.Peek(ctx, keys.CodeKey("MOBILE", "LOGIN", seq, "13800138000", "86"))
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrCodeNotFound))
	}
}

func TestVerification_Service_SendAndVerify_Random4(t *testing.T) {
	ctx := context.Background()
	client, cleanup, _ := getRedisClient(t)
	defer cleanup()

	fake := &fakeSMSSender{}
	gen := NewCodeGenerator(4)
	keys := NewCacheKeyBuilder("TEST")
	svc := NewOTPService[MobileCode](mobileTestConfig(10, 10), client, fake)

	mc, err := gen.NewMobileCode("login", 123, "13800138000", "86")
	assert.NoError(t, err)
	seq, err := svc.Send(ctx, mc)
	assert.NoError(t, err)
	assert.NotEmpty(t, seq)

	if assert.NotNil(t, fake.last) {
		code := fake.last.Code.Value
		assert.True(t, isNDigits(code, 4), "code should be 4 digits, got: %q", code)

		err := svc.Verify(ctx, code, mobileProbe(seq, "13800138000", "86"))
		assert.NoError(t, err)
		mobileStore := NewCodeStore[MobileCode](client)
		_, err = mobileStore.Peek(ctx, keys.CodeKey("MOBILE", "LOGIN", seq, "13800138000", "86"))
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrCodeNotFound))
	}
}

func TestVerification_Service_VerifyFailKeepsCode(t *testing.T) {
	ctx := context.Background()
	client, cleanup, _ := getRedisClient(t)
	defer cleanup()

	fake := &fakeSMSSender{}
	gen := NewCodeGenerator(4)
	keys := NewCacheKeyBuilder("TEST")
	svc := NewOTPService[MobileCode](mobileTestConfig(10, 10), client, fake)

	mc, err := gen.NewMobileCode("login", 123, "13800138000", "86")
	assert.NoError(t, err)
	seq, err := svc.Send(ctx, mc)
	assert.NoError(t, err)
	assert.NotEmpty(t, seq)

	sent := fake.last.Code.Value
	assert.True(t, isNDigits(sent, 4), "code should be 4 digits, got: %q", sent)

	bad := wrongCodeFor(sent)
	err = svc.Verify(ctx, bad, mobileProbe(seq, "13800138000", "86"))
	assert.ErrorIs(t, err, ErrCodeIncorrect)
	// should still exist
	mobileStore := NewCodeStore[MobileCode](client)
	_, err = mobileStore.Peek(ctx, keys.CodeKey("MOBILE", "LOGIN", seq, "13800138000", "86"))
	assert.NoError(t, err)
}

func TestOTPServiceImpl_Integration_SendAndVerifyLimit(t *testing.T) {
	ctx := context.Background()
	client, cleanup, _ := getRedisClient(t)
	defer cleanup()

	sender := &fakeSMSSender{}
	gen := NewTestCodeGenerator("666666")
	svc := NewOTPService[MobileCode](OTPConfig{
		Prefix: "TEST", TTL: time.Minute,
		Send:   RateLimiterConfig{Limit: 5, Window: time.Minute, LimitErr: ErrMobileSendLimitExceeded},
		Verify: RateLimiterConfig{Limit: 2, Window: time.Minute, LimitErr: ErrMobileVerifyLimitExceeded},
	}, client, sender)

	mc, err := gen.NewMobileCode("login", 1, "13800138000", "86")
	assert.NoError(t, err)
	seq, err := svc.Send(ctx, mc)
	assert.NoError(t, err)
	assert.NotEmpty(t, seq)
	assert.NotNil(t, sender.last)
	code := sender.last.Code.Value

	// First wrong attempt
	err = svc.Verify(ctx, wrongCodeFor(code), mobileProbe(seq, "13800138000", "86"))
	assert.ErrorIs(t, err, ErrCodeIncorrect)

	// Second wrong attempt
	err = svc.Verify(ctx, wrongCodeFor(code), mobileProbe(seq, "13800138000", "86"))
	assert.ErrorIs(t, err, ErrCodeIncorrect)

	// Third wrong attempt triggers limit
	err = svc.Verify(ctx, wrongCodeFor(code), mobileProbe(seq, "13800138000", "86"))
	assert.ErrorIs(t, err, ErrMobileVerifyLimitExceeded)

	// Fourth attempt — code is already deleted
	err = svc.Verify(ctx, wrongCodeFor(code), mobileProbe(seq, "13800138000", "86"))
	assert.ErrorIs(t, err, ErrCodeNotFound)

	// Correct code after limit should still fail
	err = svc.Verify(ctx, code, mobileProbe(seq, "13800138000", "86"))
	assert.ErrorIs(t, err, ErrCodeNotFound)
}

func TestOTPServiceImpl_Integration_AdvancedCases(t *testing.T) {
	ctx := context.Background()
	client, cleanup, ff := getRedisClient(t)
	defer cleanup()

	sender := &fakeSMSSender{}
	gen := NewTestCodeGenerator("666666")
	svc := NewOTPService[MobileCode](OTPConfig{
		Prefix: "TEST", TTL: time.Second,
		Send:   RateLimiterConfig{Limit: 5, Window: time.Second, LimitErr: ErrMobileSendLimitExceeded},
		Verify: RateLimiterConfig{Limit: 2, Window: time.Second, LimitErr: ErrMobileVerifyLimitExceeded},
	}, client, sender)

	mc, err := gen.NewMobileCode("login", 1, "13800138000", "86")
	assert.NoError(t, err)
	seq, err := svc.Send(ctx, mc)
	assert.NoError(t, err)
	code := sender.last.Code.Value

	// Verify with correct code
	err = svc.Verify(ctx, code, mobileProbe(seq, "13800138000", "86"))
	assert.NoError(t, err)

	// Send another OTP
	mc2, err := gen.NewMobileCode("login", 1, "13800138000", "86")
	assert.NoError(t, err)
	seq2, err := svc.Send(ctx, mc2)
	assert.NoError(t, err)
	code2 := sender.last.Code.Value

	// Expire the code
	ff(2 * time.Second)
	err = svc.Verify(ctx, code2, mobileProbe(seq2, "13800138000", "86"))
	assert.ErrorIs(t, err, ErrCodeNotFound)

	// Send again and test limit
	mc3, err := gen.NewMobileCode("login", 1, "13800138000", "86")
	assert.NoError(t, err)
	seq3, err := svc.Send(ctx, mc3)
	assert.NoError(t, err)
	code3 := sender.last.Code.Value
	for i := 0; i < 2; i++ {
		err = svc.Verify(ctx, wrongCodeFor(code3), mobileProbe(seq3, "13800138000", "86"))
		assert.ErrorIs(t, err, ErrCodeIncorrect)
	}
	err = svc.Verify(ctx, wrongCodeFor(code3), mobileProbe(seq3, "13800138000", "86"))
	assert.ErrorIs(t, err, ErrMobileVerifyLimitExceeded)
}

func TestOTPServiceImpl_Integration_SendLimitExceeded(t *testing.T) {
	ctx := context.Background()
	client, cleanup, _ := getRedisClient(t)
	defer cleanup()

	sender := &fakeSMSSender{}
	gen := NewTestCodeGenerator("666666")
	svc := NewOTPService[MobileCode](OTPConfig{
		Prefix: "TEST", TTL: time.Minute,
		Send:   RateLimiterConfig{Limit: 2, Window: time.Minute, LimitErr: ErrMobileSendLimitExceeded},
		Verify: RateLimiterConfig{Limit: 5, Window: time.Minute, LimitErr: ErrMobileVerifyLimitExceeded},
	}, client, sender)

	mc1, err := gen.NewMobileCode("login", 1, "13800138000", "86")
	assert.NoError(t, err)
	seq1, err := svc.Send(ctx, mc1)
	assert.NoError(t, err)
	assert.NotEmpty(t, seq1)

	mc2, err := gen.NewMobileCode("login", 1, "13800138000", "86")
	assert.NoError(t, err)
	seq2, err := svc.Send(ctx, mc2)
	assert.NoError(t, err)
	assert.NotEmpty(t, seq2)

	// Third send should hit limit
	mc3, err := gen.NewMobileCode("login", 1, "13800138000", "86")
	assert.NoError(t, err)
	_, err = svc.Send(ctx, mc3)
	assert.ErrorIs(t, err, ErrMobileSendLimitExceeded)
}

// ============================================================================
// Email OTP Integration Tests
// ============================================================================

func TestOTPServiceImpl_EmailOTP_SendAndVerify(t *testing.T) {
	ctx := context.Background()
	client, cleanup, _ := getRedisClient(t)
	defer cleanup()

	emailSender := &fakeEmailSender{}
	gen := NewTestCodeGenerator("666666")
	svc := NewOTPService[EmailCode](OTPConfig{
		Prefix: "TEST", TTL: time.Minute,
		Send:   RateLimiterConfig{Limit: 5, Window: time.Minute, LimitErr: ErrEmailSendLimitExceeded},
		Verify: RateLimiterConfig{Limit: 2, Window: time.Minute, LimitErr: ErrEmailVerifyLimitExceeded},
	}, client, emailSender)

	ec, err := gen.NewEmailCode("login", 1, "user@example.com")
	assert.NoError(t, err)
	seq, err := svc.Send(ctx, ec)
	assert.NoError(t, err)
	assert.NotEmpty(t, seq)
	require.NotNil(t, emailSender.last)
	assert.Equal(t, "user@example.com", emailSender.last.Email)
	code := emailSender.last.Code.Value
	assert.Equal(t, "666666", code)

	err = svc.Verify(ctx, code, emailProbe(seq, "user@example.com"))
	assert.NoError(t, err)

	// Code should be deleted
	keys := NewCacheKeyBuilder("TEST")
	emailStore := NewCodeStore[EmailCode](client)
	_, err = emailStore.Peek(ctx, keys.CodeKey("EMAIL", "LOGIN", seq, "user@example.com"))
	assert.ErrorIs(t, err, ErrCodeNotFound)
}

func TestOTPServiceImpl_EmailOTP_VerifyFailKeepsCode(t *testing.T) {
	ctx := context.Background()
	client, cleanup, _ := getRedisClient(t)
	defer cleanup()

	emailSender := &fakeEmailSender{}
	gen := NewTestCodeGenerator("666666")
	svc := NewOTPService[EmailCode](emailTestConfig(5, 5), client, emailSender)

	ec, err := gen.NewEmailCode("login", 1, "user@example.com")
	assert.NoError(t, err)
	seq, err := svc.Send(ctx, ec)
	assert.NoError(t, err)
	code := emailSender.last.Code.Value

	// Wrong code
	err = svc.Verify(ctx, wrongCodeFor(code), emailProbe(seq, "user@example.com"))
	assert.ErrorIs(t, err, ErrCodeIncorrect)

	// Code should still exist
	keys := NewCacheKeyBuilder("TEST")
	emailStore := NewCodeStore[EmailCode](client)
	_, err = emailStore.Peek(ctx, keys.CodeKey("EMAIL", "LOGIN", seq, "user@example.com"))
	assert.NoError(t, err)

	// Correct code should still work
	err = svc.Verify(ctx, code, emailProbe(seq, "user@example.com"))
	assert.NoError(t, err)
}

func TestOTPServiceImpl_EmailOTP_VerifyLimitExceeded(t *testing.T) {
	ctx := context.Background()
	client, cleanup, _ := getRedisClient(t)
	defer cleanup()

	emailSender := &fakeEmailSender{}
	gen := NewTestCodeGenerator("666666")
	svc := NewOTPService[EmailCode](emailTestConfig(5, 2), client, emailSender)

	ec, err := gen.NewEmailCode("login", 1, "user@example.com")
	assert.NoError(t, err)
	seq, err := svc.Send(ctx, ec)
	assert.NoError(t, err)
	code := emailSender.last.Code.Value

	err = svc.Verify(ctx, wrongCodeFor(code), emailProbe(seq, "user@example.com"))
	assert.ErrorIs(t, err, ErrCodeIncorrect)

	err = svc.Verify(ctx, wrongCodeFor(code), emailProbe(seq, "user@example.com"))
	assert.ErrorIs(t, err, ErrCodeIncorrect)

	// Third attempt triggers limit
	err = svc.Verify(ctx, wrongCodeFor(code), emailProbe(seq, "user@example.com"))
	assert.ErrorIs(t, err, ErrEmailVerifyLimitExceeded)

	// Correct code after limit should fail
	err = svc.Verify(ctx, code, emailProbe(seq, "user@example.com"))
	assert.ErrorIs(t, err, ErrCodeNotFound)
}

func TestOTPServiceImpl_EmailOTP_SendLimitExceeded(t *testing.T) {
	ctx := context.Background()
	client, cleanup, _ := getRedisClient(t)
	defer cleanup()

	emailSender := &fakeEmailSender{}
	gen := NewTestCodeGenerator("666666")
	svc := NewOTPService[EmailCode](emailTestConfig(2, 5), client, emailSender)

	ec1, err := gen.NewEmailCode("login", 1, "user@example.com")
	assert.NoError(t, err)
	seq1, err := svc.Send(ctx, ec1)
	assert.NoError(t, err)
	assert.NotEmpty(t, seq1)

	ec2, err := gen.NewEmailCode("login", 1, "user@example.com")
	assert.NoError(t, err)
	seq2, err := svc.Send(ctx, ec2)
	assert.NoError(t, err)
	assert.NotEmpty(t, seq2)

	// Third send should hit limit
	ec3, err := gen.NewEmailCode("login", 1, "user@example.com")
	assert.NoError(t, err)
	_, err = svc.Send(ctx, ec3)
	assert.ErrorIs(t, err, ErrEmailSendLimitExceeded)
}

func TestVerification_RateLimitError_Unwrap(t *testing.T) {
	client, cleanup, _ := getRedisClient(t)
	defer cleanup()

	ctx := context.Background()
	gen := NewCodeGenerator(6)

	cfg := DefaultOTPConfig("RL_TEST")
	cfg.Send.Limit = 1
	cfg.Send.Window = 10 * time.Second
	cfg.Send.LimitErr = ErrMobileSendLimitExceeded

	svc := NewOTPService[MobileCode](cfg, client, nil)

	code, err := gen.NewMobileCode("LOGIN", 1, "13800000000", "86")
	assert.NoError(t, err)

	// First send should succeed
	_, err = svc.Send(ctx, code)
	assert.NoError(t, err)

	// Second send should fail with RateLimitError
	_, err = svc.Send(ctx, code)
	assert.Error(t, err)

	var rlErr *RateLimitError
	assert.True(t, errors.As(err, &rlErr), "error should be of type *RateLimitError")
	assert.Equal(t, ErrMobileSendLimitExceeded, rlErr.Unwrap(), "underlying error should be exact sentinel")
	assert.True(t, rlErr.RetryIn > 0 && rlErr.RetryIn <= 10*time.Second, "retry duration should be valid > 0 and <= window")
}

func TestVerification_ConstructorValidation(t *testing.T) {
	gen := NewCodeGenerator(6)

	t.Run("MobileCode empty mobile", func(t *testing.T) {
		_, err := gen.NewMobileCode("LOGIN", 1, "", "86")
		assert.Equal(t, ErrMobileCodeMobileIsEmpty, err)
	})

	t.Run("MobileCode empty countrycode", func(t *testing.T) {
		_, err := gen.NewMobileCode("LOGIN", 1, "13800000000", "")
		assert.Equal(t, ErrMobileCodeCountryCodeIsEmpty, err)
	})

	t.Run("EmailCode empty email", func(t *testing.T) {
		_, err := gen.NewEmailCode("LOGIN", 1, "")
		assert.Equal(t, ErrEmailCodeEmailIsEmpty, err)
	})

	t.Run("EcdsaCode empty chain", func(t *testing.T) {
		_, err := gen.NewEcdsaCode("LOGIN", 1, "", "0xabc")
		assert.Equal(t, ErrEcdsaCodeChainIsEmpty, err)
	})

	t.Run("EcdsaCode empty address", func(t *testing.T) {
		_, err := gen.NewEcdsaCode("LOGIN", 1, "ETH", "")
		assert.Equal(t, ErrEcdsaCodeAddressIsEmpty, err)
	})
}
