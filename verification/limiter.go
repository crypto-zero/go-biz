package verification

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const expectedResultLen = 4

// fixedWindowScript is a Lua script for fixed-window rate limiting.
var fixedWindowScript = redis.NewScript(`
local key        = KEYS[1]
local limit      = tonumber(ARGV[1])
local window_ms  = tonumber(ARGV[2])

redis.call('SET', key, 0, 'PX', window_ms, 'NX')
local current = redis.call('INCR', key)

local ttl = redis.call('PTTL', key)
if ttl == -1 then
  redis.call('PEXPIRE', key, window_ms)
  ttl = window_ms
end

local allowed = 0
if current <= limit then
  allowed = 1
end

return {allowed, current, limit, ttl}
`)

// LimitDecision captures a single limiter evaluation result.
type LimitDecision struct {
	Allowed bool          // whether the action is allowed
	Count   int64         // current count in the window
	Limit   int64         // configured limit
	ResetIn time.Duration // time until the window resets
}

// CodeLimiter provides key-based rate limiting and incorrect-count tracking.
type CodeLimiter interface {
	AllowSend(ctx context.Context, key string, limit int64, window time.Duration) (*LimitDecision, error)
	RollbackSend(ctx context.Context, key string) error
	GetIncorrectCount(ctx context.Context, key string) (int64, error)
	IncrementIncorrect(ctx context.Context, key string, maxAttempts int64, window time.Duration) (*LimitDecision, error)
	DeleteIncorrect(ctx context.Context, key string) error
}

// RedisCodeLimiter implements CodeLimiter backed by Redis + Lua.
type RedisCodeLimiter struct {
	client redis.UniversalClient
}

// NewRedisCodeLimiter creates a CodeLimiter backed by the given Redis client.
func NewRedisCodeLimiter(client redis.UniversalClient) CodeLimiter {
	return &RedisCodeLimiter{client: client}
}

func (l *RedisCodeLimiter) evalFixedWindow(ctx context.Context, key string, limit int64, window time.Duration) (*LimitDecision, error) {
	if window <= 0 {
		return nil, fmt.Errorf("invalid window duration: %d", window)
	}
	if limit <= 0 {
		return nil, fmt.Errorf("invalid limit: %d", limit)
	}
	res, err := fixedWindowScript.Run(ctx, l.client, []string{key}, limit, window.Milliseconds()).Int64Slice()
	if err != nil {
		return nil, fmt.Errorf("limiter eval failed: %w", err)
	}
	if len(res) != expectedResultLen {
		return nil, fmt.Errorf("limiter eval unexpected result length: got %d, want %d", len(res), expectedResultLen)
	}
	return &LimitDecision{
		Allowed: res[0] == 1,
		Count:   res[1],
		Limit:   res[2],
		ResetIn: time.Duration(res[3]) * time.Millisecond,
	}, nil
}

func (l *RedisCodeLimiter) AllowSend(ctx context.Context, key string, limit int64, window time.Duration) (*LimitDecision, error) {
	return l.evalFixedWindow(ctx, key, limit, window)
}

func (l *RedisCodeLimiter) RollbackSend(ctx context.Context, key string) error {
	val, err := l.client.Decr(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("verification: rollback send failed: %w", err)
	}
	// If the counter dropped below zero (shouldn't happen, but be safe), reset to 0.
	if val < 0 {
		_ = l.client.Set(ctx, key, 0, redis.KeepTTL).Err()
	}
	return nil
}

func (l *RedisCodeLimiter) GetIncorrectCount(ctx context.Context, key string) (int64, error) {
	cnt, err := l.client.Get(ctx, key).Int64()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("verification: get incorrect count failed: %w", err)
	}
	return cnt, nil
}

func (l *RedisCodeLimiter) IncrementIncorrect(ctx context.Context, key string, maxAttempts int64, window time.Duration) (*LimitDecision, error) {
	return l.evalFixedWindow(ctx, key, maxAttempts, window)
}

func (l *RedisCodeLimiter) DeleteIncorrect(ctx context.Context, key string) error {
	return deleteCode(ctx, l.client, key)
}
