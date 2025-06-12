package authorization

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// userSetSessionIDScript is a redis lua script to set user session id,
// it set user session id, set a user session map, and remove expired session id from a session map.
//
// KEYS[1] = user session key
// KEYS[2] = user session map key
// ARGV[1] = user id
// ARGV[2] = session id
// ARGV[3] = expire timestamp
// ARGV[4] = current timestamp
var userSetSessionIDScript = redis.NewScript(
	`
redis.call("SET", KEYS[1], ARGV[1])
redis.call("EXPIREAT", KEYS[1], ARGV[3])
redis.call("HSET", KEYS[2], ARGV[2], ARGV[3])
local expire_timestamp = tonumber(ARGV[3])
local current_timestamp = tonumber(ARGV[4])
local hash_table = redis.call('HGETALL', KEYS[2])
for idx = 1, #hash_table, 2 do
    local field = hash_table[idx]
    local value = tonumber(hash_table[idx + 1])
    if value < current_timestamp then
        redis.call('HDEL', KEYS[2], field)
    elseif value > expire_timestamp then
        expire_timestamp = value
    end
end
return redis.call("EXPIREAT", KEYS[2], expire_timestamp)`,
)

// SessionCacheImpl is a SessionCache implementation.
type SessionCacheImpl struct {
	prefix SessionCachePrefix
	client redis.UniversalClient
}

func (s SessionCacheImpl) userSessionKey(sessionID string) string {
	return fmt.Sprintf("%s:USER:SESSION:%s", s.prefix, sessionID)
}

func (s SessionCacheImpl) userSessionMapKey(userID int64) string {
	return fmt.Sprintf("%s:USER:SESSION:MAP:%d", s.prefix, userID)
}

func (s SessionCacheImpl) SetUserSessionID(ctx context.Context, sessionID string,
	userID int64, expire time.Duration,
) error {
	n := time.Now()
	expireAt := n.Add(expire)
	currentTimestamp, expireTimestamp := n.Unix(), expireAt.Unix()
	key, mapKey := s.userSessionKey(sessionID), s.userSessionMapKey(userID)
	err := userSetSessionIDScript.Run(
		ctx, s.client,
		[]string{key, mapKey},
		userID, sessionID, expireTimestamp, currentTimestamp,
	).Err()
	if err != nil {
		return fmt.Errorf("set user session id failed: %w", err)
	}
	return nil
}

func (s SessionCacheImpl) GetUserIDBySessionID(ctx context.Context, sessionID string,
	expire time.Duration,
) (userID int64, err error) {
	key := s.userSessionKey(sessionID)
	if userID, err = s.client.Get(ctx, key).Int64(); errors.Is(err, redis.Nil) {
		return 0, ErrSessionNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("get user id by session id failed: %w", err)
	}
	mapKey := s.userSessionMapKey(userID)
	expireAt := time.Now().Add(expire)
	_, err = s.client.Pipelined(
		ctx, func(pipe redis.Pipeliner) error {
			pipe.Expire(ctx, key, expire)
			pipe.Expire(ctx, mapKey, expire)
			pipe.HSet(ctx, mapKey, sessionID, expireAt.Unix())
			return nil
		},
	)
	if err != nil {
		return 0, fmt.Errorf("failed to refresh user session: %w", err)
	}
	return userID, nil
}

// NewSessionCacheImpl returns a new SessionCacheImpl.
func NewSessionCacheImpl(
	prefix SessionCachePrefix, client redis.UniversalClient,
) SessionCache {
	return &SessionCacheImpl{prefix: prefix, client: client}
}
