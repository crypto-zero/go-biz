package verification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// setCode encodes v as JSON and stores it in Redis under key with the given TTL.
func setCode[T VerificationCode](ctx context.Context, client redis.UniversalClient, key string, v *T, ttl time.Duration) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("verification: encode failed: %w", err)
	}
	if err = client.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("verification: redis set failed: %w", err)
	}
	return nil
}

// getCode fetches and JSON-decodes a value from Redis.
// If deleteAfter is true it uses GETDEL (atomic get+delete), otherwise plain GET.
func getCode[T VerificationCode](ctx context.Context, client redis.UniversalClient, key string, deleteAfter bool) (*T, error) {
	var cmd *redis.StringCmd
	if deleteAfter {
		cmd = client.GetDel(ctx, key)
	} else {
		cmd = client.Get(ctx, key)
	}
	data, err := cmd.Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("verification: redis get failed: %w", err)
	}
	var v T
	if err = json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("verification: decode failed: %w", err)
	}
	return &v, nil
}

// deleteCode removes a key from Redis.
func deleteCode(ctx context.Context, client redis.UniversalClient, key string) error {
	if err := client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("verification: redis del failed: %w", err)
	}
	return nil
}

// CodeStore[T] provides typed CRUD for verification codes.
type CodeStore[T VerificationCode] interface {
	Set(ctx context.Context, key string, code *T, expire time.Duration) error
	Get(ctx context.Context, key string) (*T, error)
	Peek(ctx context.Context, key string) (*T, error)
	Delete(ctx context.Context, key string) error
}

// RedisCodeStore[T] implements CodeStore[T] backed by Redis + JSON.
type RedisCodeStore[T VerificationCode] struct {
	client redis.UniversalClient
}

// NewRedisCodeStore creates a CodeStore[T] backed by the given Redis client.
func NewRedisCodeStore[T VerificationCode](client redis.UniversalClient) CodeStore[T] {
	return &RedisCodeStore[T]{client: client}
}

func (s *RedisCodeStore[T]) Set(ctx context.Context, key string, code *T, expire time.Duration) error {
	return setCode(ctx, s.client, key, code, expire)
}

func (s *RedisCodeStore[T]) Get(ctx context.Context, key string) (*T, error) {
	return getCode[T](ctx, s.client, key, true)
}

func (s *RedisCodeStore[T]) Peek(ctx context.Context, key string) (*T, error) {
	return getCode[T](ctx, s.client, key, false)
}

func (s *RedisCodeStore[T]) Delete(ctx context.Context, key string) error {
	return deleteCode(ctx, s.client, key)
}
