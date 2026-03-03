package verification

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// allowScript atomically increments a fixed-window counter and checks the limit.
var allowScript = redis.NewScript(`
local key       = KEYS[1]
local limit     = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])

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

// undoScript atomically decrements a counter, flooring at zero.
var undoScript = redis.NewScript(`
local val = redis.call('DECR', KEYS[1])
if val < 0 then
  redis.call('SET', KEYS[1], 0, 'KEEPTTL')
end
return val
`)

// RateLimiterConfig holds the fixed-window rate limiter policy.
type RateLimiterConfig struct {
	Limit    int64         // max actions per window
	Window   time.Duration // window duration
	LimitErr error         // sentinel wrapped in *RateLimitError when exceeded
}

// RateLimiter provides fixed-window rate limiting backed by Redis.
// Configuration is bound at construction time.
type RateLimiter struct {
	client redis.UniversalClient
	cfg    RateLimiterConfig
}

// NewRateLimiter creates a RateLimiter with the given policy.
func NewRateLimiter(client redis.UniversalClient, cfg RateLimiterConfig) *RateLimiter {
	return &RateLimiter{client: client, cfg: cfg}
}

// Allow increments the counter for key.
// Returns nil if allowed, *RateLimitError if exceeded, or an error on failure.
func (l *RateLimiter) Allow(ctx context.Context, key string) error {
	res, err := allowScript.Run(ctx, l.client, []string{key}, l.cfg.Limit, l.cfg.Window.Milliseconds()).Int64Slice()
	if err != nil {
		return fmt.Errorf("limiter: %w", err)
	}
	if res[0] != 1 {
		return &RateLimitError{Err: l.cfg.LimitErr, RetryIn: time.Duration(res[3]) * time.Millisecond}
	}
	return nil
}

// Undo decrements the counter (e.g. to reverse a failed send attempt).
func (l *RateLimiter) Undo(ctx context.Context, key string) error {
	return undoScript.Run(ctx, l.client, []string{key}).Err()
}

// Reset removes the counter key entirely.
func (l *RateLimiter) Reset(ctx context.Context, key string) error {
	return l.client.Del(ctx, key).Err()
}
