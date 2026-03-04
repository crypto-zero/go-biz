package verification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// CodeStore[T] provides typed CRUD for verification codes backed by Redis + JSON.
// The verification code is stored as a SHA-256 hash to prevent plaintext
// exposure in the event of unauthorized Redis access.
type CodeStore[T VerificationCode] struct {
	client redis.UniversalClient
}

// NewCodeStore creates a CodeStore[T] backed by the given Redis client.
func NewCodeStore[T VerificationCode](client redis.UniversalClient) *CodeStore[T] {
	return &CodeStore[T]{client: client}
}

func (s *CodeStore[T]) Set(ctx context.Context, key string, code *T, expire time.Duration) error {
	data, err := json.Marshal(code)
	if err != nil {
		return fmt.Errorf("verification: encode failed: %w", err)
	}
	if err = s.client.Set(ctx, key, data, expire).Err(); err != nil {
		return fmt.Errorf("verification: redis set failed: %w", err)
	}
	return nil
}

func (s *CodeStore[T]) Peek(ctx context.Context, key string) (*T, error) {
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

func (s *CodeStore[T]) Delete(ctx context.Context, key string) (bool, error) {
	n, err := s.client.Del(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("verification: redis del failed: %w", err)
	}
	return n > 0, nil
}
