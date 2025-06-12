package verification

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

func TestVerification(t *testing.T) {
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		t.Skip()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	redisClient := redis.NewUniversalClient(&redis.UniversalOptions{Addrs: []string{redisAddr}})
	generator := NewStaticCodeGenerator()
	cache := NewCodeCacheImpl("TEST", redisClient)

	t.Run("test email code", func(t *testing.T) {
		typ := "TEST_TYPE"
		code, err := generator.NewEmailCode(ctx, typ, 1, "abc@def.com")
		if err != nil {
			t.Error(err)
			return
		}
		if err = cache.SetEmailCode(ctx, code, time.Minute); err != nil {
			t.Error(err)
			return
		}
		assert.NotEmpty(t, code.Sequence)
		assert.Equal(t, typ, code.Type)
		assert.Equal(t, code.Email, "abc@def.com")
		emailCode, err := cache.GetEmailCode(ctx, typ, code.Sequence, code.Email)
		if err != nil {
			t.Error(err)
			return
		}
		assert.NotNil(t, emailCode)
		assert.Equal(t, code.Content, emailCode.Content)
	})

	t.Run("test email code expired", func(t *testing.T) {
		typ := "TEST_TYPE"
		code, err := generator.NewEmailCode(ctx, typ, 1, "abc@def.com")
		if err != nil {
			t.Error(err)
			return
		}
		if err = cache.SetEmailCode(ctx, code, time.Second); err != nil {
			t.Error(err)
			return
		}
		time.Sleep(2 * time.Second)
		assert.NotEmpty(t, code.Sequence)
		assert.Equal(t, typ, code.Type)
		assert.Equal(t, code.Email, "abc@def.com")
		_, err = cache.GetEmailCode(ctx, typ, code.Sequence, code.Email)
		assert.Equal(t, ErrCodeNotFound, err)
	})

	t.Run("test mobile code", func(t *testing.T) {
		typ := "TEST_TYPE"
		code, err := generator.NewMobileCode(ctx, typ, 1, "13566667777", "CN")
		if err != nil {
			t.Error(err)
			return
		}
		if err = cache.SetMobileCode(ctx, code, time.Minute); err != nil {
			t.Error(err)
			return
		}

		assert.NotEmpty(t, code.Sequence)
		assert.Equal(t, typ, code.Type)
		assert.Equal(t, "13566667777", code.Mobile)
		assert.Equal(t, "CN", code.CountryCode)

		mobileCode, err := cache.GetMobileCode(ctx, typ, code.Sequence, code.Mobile, code.CountryCode)
		if err != nil {
			t.Error(err)
			return
		}
		assert.NotNil(t, mobileCode)
		assert.Equal(t, code.Content, mobileCode.Content)
	})

	t.Run("test ecdsa code", func(t *testing.T) {
		typ := "TEST_TYPE"
		code, err := generator.NewEcdsaCode(ctx, typ, 1, "ETHEREUM", "12345")
		if err != nil {
			t.Error(err)
			return
		}
		if err = cache.SetEcdsaCode(ctx, code, time.Minute); err != nil {
			t.Error(err)
			return
		}

		assert.NotEmpty(t, code.Sequence)
		assert.Equal(t, typ, code.Type)
		assert.Equal(t, "ETHEREUM", code.Chain)
		assert.Equal(t, "12345", code.Address)

		ecdsaCode, err := cache.GetEcdsaCode(ctx, typ, code.Sequence, code.Chain, code.Address)
		if err != nil {
			t.Error(err)
			return
		}
		assert.NotNil(t, ecdsaCode)
		assert.Equal(t, code.Content, ecdsaCode.Content)
	})
}
