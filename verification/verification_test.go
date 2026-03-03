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
		MaxSendAttempts: maxSend, SendWindow: 5 * time.Minute,
		MaxVerifyIncorrect: maxVerify, VerifyWindow: 5 * time.Minute,
		SendLimitErr:   ErrMobileSendLimitExceeded,
		VerifyLimitErr: ErrMobileVerifyLimitExceeded,
	}
}

// emailTestConfig returns an OTPConfig for the email channel.
func emailTestConfig(maxSend, maxVerify int64) OTPConfig {
	return OTPConfig{
		Prefix: "TEST", TTL: 5 * time.Minute,
		MaxSendAttempts: maxSend, SendWindow: 5 * time.Minute,
		MaxVerifyIncorrect: maxVerify, VerifyWindow: 5 * time.Minute,
		SendLimitErr:   ErrEmailSendLimitExceeded,
		VerifyLimitErr: ErrEmailVerifyLimitExceeded,
	}
}

func TestVerification_CodeStore_Basics(t *testing.T) {
	ctx := context.Background()
	client, cleanup, ff := getRedisClient(t)
	defer cleanup()

	gen := NewTestCodeGenerator("666666")
	keys := NewCacheKeyBuilder("TEST")
	mobileStore := NewRedisCodeStore[MobileCode](client)
	emailStore := NewRedisCodeStore[EmailCode](client)
	ecdsaStore := NewRedisCodeStore[EcdsaCode](client)

	t.Run("email set/get", func(t *testing.T) {
		code, err := gen.NewEmailCode("TEST_TYPE", 1, "abc@def.com")
		assert.NoError(t, err)
		key := keys.CodeKey("EMAIL", code.Type, code.Sequence, code.Email)
		assert.NoError(t, emailStore.Set(ctx, key, code, time.Minute))
		emailCode, err := emailStore.Peek(ctx, key)
		assert.NoError(t, err)
		assert.NotNil(t, emailCode)
		assert.Equal(t, code.Content, emailCode.Content)
		assert.Equal(t, "666666", emailCode.Code.Code)
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
		assert.Equal(t, code.Content, mobileCode.Content)
		assert.Equal(t, "666666", mobileCode.Code.Code)
	})

	t.Run("ecdsa set/get", func(t *testing.T) {
		code, _ := gen.NewEcdsaCode("TEST_TYPE", 1, "ETHEREUM", "0xabc")
		key := keys.CodeKey("ECDSA", code.Type, code.Sequence, code.Chain, code.Address)
		_ = ecdsaStore.Set(ctx, key, code, time.Minute)
		ecdsaCode, err := ecdsaStore.Peek(ctx, key)
		assert.NoError(t, err)
		assert.NotNil(t, ecdsaCode)
		assert.Equal(t, code.Content, ecdsaCode.Content)
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
		assert.True(t, isNDigits(fake.last.Code.Code, 6))
		assert.Equal(t, "666666", fake.last.Code.Code)

		// Verify OK should delete
		err := svc.Verify(ctx, "login", "666666", seq, "13800138000", "86")
		assert.NoError(t, err)
		mobileStore := NewRedisCodeStore[MobileCode](client)
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
		code := fake.last.Code.Code
		assert.True(t, isNDigits(code, 4), "code should be 4 digits, got: %q", code)

		err := svc.Verify(ctx, "login", code, seq, "13800138000", "86")
		assert.NoError(t, err)
		mobileStore := NewRedisCodeStore[MobileCode](client)
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

	sent := fake.last.Code.Code
	assert.True(t, isNDigits(sent, 4), "code should be 4 digits, got: %q", sent)

	bad := wrongCodeFor(sent)
	err = svc.Verify(ctx, "login", bad, seq, "13800138000", "86")
	assert.ErrorIs(t, err, ErrCodeIncorrect)
	// should still exist
	mobileStore := NewRedisCodeStore[MobileCode](client)
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
		MaxSendAttempts: 5, SendWindow: time.Minute,
		MaxVerifyIncorrect: 2, VerifyWindow: time.Minute,
		SendLimitErr:   ErrMobileSendLimitExceeded,
		VerifyLimitErr: ErrMobileVerifyLimitExceeded,
	}, client, sender)

	mc, err := gen.NewMobileCode("login", 1, "13800138000", "86")
	assert.NoError(t, err)
	seq, err := svc.Send(ctx, mc)
	assert.NoError(t, err)
	assert.NotEmpty(t, seq)
	assert.NotNil(t, sender.last)
	code := sender.last.Code.Code

	// First wrong attempt
	err = svc.Verify(ctx, "login", wrongCodeFor(code), seq, "13800138000", "86")
	assert.ErrorIs(t, err, ErrCodeIncorrect)

	// Second wrong attempt
	err = svc.Verify(ctx, "login", wrongCodeFor(code), seq, "13800138000", "86")
	assert.ErrorIs(t, err, ErrCodeIncorrect)

	// Third wrong attempt triggers limit
	err = svc.Verify(ctx, "login", wrongCodeFor(code), seq, "13800138000", "86")
	assert.ErrorIs(t, err, ErrMobileVerifyLimitExceeded)

	// Fourth attempt — code is already deleted
	err = svc.Verify(ctx, "login", wrongCodeFor(code), seq, "13800138000", "86")
	assert.ErrorIs(t, err, ErrCodeNotFound)

	// Correct code after limit should still fail
	err = svc.Verify(ctx, "login", code, seq, "13800138000", "86")
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
		MaxSendAttempts: 5, SendWindow: time.Second,
		MaxVerifyIncorrect: 2, VerifyWindow: time.Second,
		SendLimitErr:   ErrMobileSendLimitExceeded,
		VerifyLimitErr: ErrMobileVerifyLimitExceeded,
	}, client, sender)

	mc, err := gen.NewMobileCode("login", 1, "13800138000", "86")
	assert.NoError(t, err)
	seq, err := svc.Send(ctx, mc)
	assert.NoError(t, err)
	code := sender.last.Code.Code

	// Verify with correct code
	err = svc.Verify(ctx, "login", code, seq, "13800138000", "86")
	assert.NoError(t, err)

	// Send another OTP
	mc2, err := gen.NewMobileCode("login", 1, "13800138000", "86")
	assert.NoError(t, err)
	seq2, err := svc.Send(ctx, mc2)
	assert.NoError(t, err)
	code2 := sender.last.Code.Code

	// Expire the code
	ff(2 * time.Second)
	err = svc.Verify(ctx, "login", code2, seq2, "13800138000", "86")
	assert.ErrorIs(t, err, ErrCodeNotFound)

	// Send again and test limit
	mc3, err := gen.NewMobileCode("login", 1, "13800138000", "86")
	assert.NoError(t, err)
	seq3, err := svc.Send(ctx, mc3)
	assert.NoError(t, err)
	code3 := sender.last.Code.Code
	for i := 0; i < 2; i++ {
		err = svc.Verify(ctx, "login", wrongCodeFor(code3), seq3, "13800138000", "86")
		assert.ErrorIs(t, err, ErrCodeIncorrect)
	}
	err = svc.Verify(ctx, "login", wrongCodeFor(code3), seq3, "13800138000", "86")
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
		MaxSendAttempts: 2, SendWindow: time.Minute,
		MaxVerifyIncorrect: 5, VerifyWindow: time.Minute,
		SendLimitErr:   ErrMobileSendLimitExceeded,
		VerifyLimitErr: ErrMobileVerifyLimitExceeded,
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
		MaxSendAttempts: 5, SendWindow: time.Minute,
		MaxVerifyIncorrect: 2, VerifyWindow: time.Minute,
		SendLimitErr:   ErrEmailSendLimitExceeded,
		VerifyLimitErr: ErrEmailVerifyLimitExceeded,
	}, client, emailSender)

	ec, err := gen.NewEmailCode("login", 1, "user@example.com")
	assert.NoError(t, err)
	seq, err := svc.Send(ctx, ec)
	assert.NoError(t, err)
	assert.NotEmpty(t, seq)
	require.NotNil(t, emailSender.last)
	assert.Equal(t, "user@example.com", emailSender.last.Email)
	code := emailSender.last.Code.Code
	assert.Equal(t, "666666", code)

	err = svc.Verify(ctx, "login", code, seq, "user@example.com")
	assert.NoError(t, err)

	// Code should be deleted
	keys := NewCacheKeyBuilder("TEST")
	emailStore := NewRedisCodeStore[EmailCode](client)
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
	code := emailSender.last.Code.Code

	// Wrong code
	err = svc.Verify(ctx, "login", wrongCodeFor(code), seq, "user@example.com")
	assert.ErrorIs(t, err, ErrCodeIncorrect)

	// Code should still exist
	keys := NewCacheKeyBuilder("TEST")
	emailStore := NewRedisCodeStore[EmailCode](client)
	_, err = emailStore.Peek(ctx, keys.CodeKey("EMAIL", "LOGIN", seq, "user@example.com"))
	assert.NoError(t, err)

	// Correct code should still work
	err = svc.Verify(ctx, "login", code, seq, "user@example.com")
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
	code := emailSender.last.Code.Code

	err = svc.Verify(ctx, "login", wrongCodeFor(code), seq, "user@example.com")
	assert.ErrorIs(t, err, ErrCodeIncorrect)

	err = svc.Verify(ctx, "login", wrongCodeFor(code), seq, "user@example.com")
	assert.ErrorIs(t, err, ErrCodeIncorrect)

	// Third attempt triggers limit
	err = svc.Verify(ctx, "login", wrongCodeFor(code), seq, "user@example.com")
	assert.ErrorIs(t, err, ErrEmailVerifyLimitExceeded)

	// Correct code after limit should fail
	err = svc.Verify(ctx, "login", code, seq, "user@example.com")
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
