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

// wrongCodeFor returns a 4-digit code that differs from sent.
func wrongCodeFor(sent string) string {
	if sent != "0000" {
		return "0000"
	}
	return "0001"
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

// fake sender captures the last MobileCode sent
type fakeSMSSender struct{ last *MobileCode }

func (f *fakeSMSSender) Send(ctx context.Context, mc *MobileCode) error {
	f.last = mc
	return nil
}

func TestVerification_CodeCache_Basics(t *testing.T) {
	ctx := context.Background()
	client, cleanup, ff := getRedisClient(t)
	defer cleanup()

	generator := NewStaticCodeGenerator()
	cache := NewCodeCacheImpl("TEST", client)

	t.Run("email set/get", func(t *testing.T) {
		typ := "TEST_TYPE"
		code, err := generator.NewEmailCode(ctx, typ, 1, "abc@def.com")
		assert.NoError(t, err)
		assert.NoError(t, cache.SetEmailCode(ctx, code, time.Minute))
		emailCode, err := cache.GetEmailCode(ctx, typ, code.Sequence, code.Email)
		assert.NoError(t, err)
		assert.NotNil(t, emailCode)
		assert.Equal(t, code.Content, emailCode.Content)
	})

	t.Run("email expired", func(t *testing.T) {
		code, _ := generator.NewEmailCode(ctx, "TEST_TYPE", 1, "abc@def.com")
		_ = cache.SetEmailCode(ctx, code, time.Second)
		ff(2 * time.Second)
		_, err := cache.GetEmailCode(ctx, "TEST_TYPE", code.Sequence, code.Email)
		assert.Equal(t, ErrCodeNotFound, err)
	})

	t.Run("mobile set/get", func(t *testing.T) {
		code, _ := generator.NewMobileCode(ctx, "TEST_TYPE", 1, "13566667777", "CN")
		_ = cache.SetMobileCode(ctx, code, time.Minute)
		mobileCode, err := cache.GetMobileCode(ctx, "TEST_TYPE", code.Sequence, code.Mobile, code.CountryCode)
		assert.NoError(t, err)
		assert.NotNil(t, mobileCode)
		assert.Equal(t, code.Content, mobileCode.Content)
	})

	t.Run("ecdsa set/get", func(t *testing.T) {
		code, _ := generator.NewEcdsaCode(ctx, "TEST_TYPE", 1, "ETHEREUM", "12345")
		_ = cache.SetEcdsaCode(ctx, code, time.Minute)
		ecdsaCode, err := cache.GetEcdsaCode(ctx, "TEST_TYPE", code.Sequence, code.Chain, code.Address)
		assert.NoError(t, err)
		assert.NotNil(t, ecdsaCode)
		assert.Equal(t, code.Content, ecdsaCode.Content)
	})
}

func TestVerification_Service_SendAndVerify(t *testing.T) {
	ctx := context.Background()
	client, cleanup, _ := getRedisClient(t)
	defer cleanup()

	cache := NewCodeCacheImpl("TEST", client)
	fake := &fakeSMSSender{}
	svc := &VerificationService{
		Cache:     cache,
		SMSSender: fake,
		Generator: NewStaticCodeGenerator(), // returns random 4-digit code
		TTL:       5 * time.Minute,
		Secret:    []byte("test-secret-32-bytes-minimum-abcdefgh"),
	}

	// Send
	seq, err := svc.SendMobileOTP(ctx, "login", 123, "13800138000", "86")
	assert.NoError(t, err)
	assert.NotEmpty(t, seq)
	if assert.NotNil(t, fake.last) {
		// plaintext sent out must be 4 numeric digits
		assert.True(t, isNDigits(fake.last.Code.Code, 4), "code should be 4 digits, got: %q", fake.last.Code.Code)
		code := fake.last.Code.Code

		assert.Equal(t, "13800138000", fake.last.Mobile)
		assert.Equal(t, "86", fake.last.CountryCode)

		// Ensure stored code is HMAC, not plaintext
		stored, err := cache.PeekMobileCode(ctx, "LOGIN", seq, "13800138000", "86")
		assert.NoError(t, err)
		if assert.NotNil(t, stored) {
			assert.NotEqual(t, code, stored.Code.Code)
			assert.Greater(t, len(stored.Code.Code), 4) // hex string
		}

		// Verify OK should delete
		ok, err := svc.VerifyMobileOTP(ctx, "login", seq, "13800138000", "86", code)
		assert.NoError(t, err)
		assert.True(t, ok)
		_, err = cache.PeekMobileCode(ctx, "login", seq, "13800138000", "86")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrCodeNotFound))
	}
}

func TestVerification_Service_VerifyFailKeepsCode(t *testing.T) {
	ctx := context.Background()
	client, cleanup, _ := getRedisClient(t)
	defer cleanup()

	cache := NewCodeCacheImpl("TEST", client)
	fake := &fakeSMSSender{}
	svc := &VerificationService{
		Cache:     cache,
		SMSSender: fake,
		Generator: NewStaticCodeGenerator(),
		TTL:       5 * time.Minute,
		Secret:    []byte("test-secret-32-bytes-minimum-abcdefgh"),
	}

	seq, err := svc.SendMobileOTP(ctx, "login", 123, "13800138000", "86")
	assert.NoError(t, err)
	assert.NotEmpty(t, seq)

	sent := fake.last.Code.Code
	bad := wrongCodeFor(sent)

	ok, err := svc.VerifyMobileOTP(ctx, "login", seq, "13800138000", "86", bad)
	assert.NoError(t, err)
	assert.False(t, ok)
	// should still exist
	_, err = cache.PeekMobileCode(ctx, "login", seq, "13800138000", "86")
	assert.NoError(t, err)
}
