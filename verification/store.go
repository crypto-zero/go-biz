package verification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// CodeStore[T] provides typed CRUD for verification codes.
type CodeStore[T VerificationCode] interface {
	Set(ctx context.Context, key string, code *T, expire time.Duration) error
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
	data, err := json.Marshal(code)
	if err != nil {
		return fmt.Errorf("verification: encode failed: %w", err)
	}
	if err = s.client.Set(ctx, key, data, expire).Err(); err != nil {
		return fmt.Errorf("verification: redis set failed: %w", err)
	}
	return nil
}

func (s *RedisCodeStore[T]) Peek(ctx context.Context, key string) (*T, error) {
	data, err := s.client.Get(ctx, key).Bytes()
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

func (s *RedisCodeStore[T]) Delete(ctx context.Context, key string) error {
	if err := s.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("verification: redis del failed: %w", err)
	}
	return nil
}
